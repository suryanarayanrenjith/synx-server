//! WebSocket upgrade, message handling, and connection lifecycle.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, info, warn};

use crate::control::{ClientMsg, ServerMsg};
use crate::hub::{Hub, HubError, RoomHandle};
use crate::identity::Session;
use crate::limits::Bucket;
use crate::maps::Ruleset;
use crate::room::{self, JoinRequest, Outbound, PlayerLink, RoomMsg};

#[derive(Debug, Deserialize)]
pub struct WsQuery {
    /// The session token from `/api/session`. Carried in the query string
    /// rather than a header because the browser WebSocket API cannot set
    /// headers on the upgrade - there is nowhere else to put it.
    #[serde(default)]
    pub token: String,
}

/// The address a request actually came from.
///
/// # Why the last entry of `X-Forwarded-For`
///
/// The server sits behind the host's proxy, so the socket address is the
/// proxy's and useless for rate limiting. `X-Forwarded-For` carries the chain,
/// and the conventional advice is to take the first entry - which is exactly
/// wrong when the value is attacker-controlled: a client that sends its own
/// `X-Forwarded-For: 1.2.3.4` has the proxy APPEND to it, so the first entry
/// is whatever the client made up and the last is the one the proxy vouched
/// for. Taking the last is correct whether the proxy appends or replaces, and
/// it is the only choice a client cannot influence.
pub fn client_ip(headers: &HeaderMap, socket: SocketAddr) -> IpAddr {
    for name in ["cf-connecting-ip", "true-client-ip"] {
        if let Some(v) = headers.get(name).and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = v.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(last) = v.rsplit(',').map(str::trim).find(|s| !s.is_empty()) {
            if let Ok(ip) = last.parse::<IpAddr>() {
                return ip;
            }
        }
    }
    socket.ip()
}

/// Everything the reader and the writer both need. Atomics, so neither ever
/// waits on the other.
struct Shared {
    /// Milliseconds since the connection opened, when the client last spoke.
    last_seen_ms: AtomicU64,
    /// The nonce of the outstanding liveness probe, and when it went out.
    ping_nonce: AtomicU32,
    ping_at_ms: AtomicU64,
    opened: Instant,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

impl Shared {
    fn ms(&self) -> u64 {
        self.opened.elapsed().as_millis() as u64
    }
}

pub async fn upgrade(
    State(hub): State<Arc<Hub>>,
    Query(q): Query<WsQuery>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let ip = client_ip(&headers, peer);

    // ORIGIN, BEFORE THE TOKEN.
    //
    // CORS does not apply to WebSockets: a browser will happily open one to
    // any host and hand the page the frames, with no preflight to refuse it.
    // The `Origin` header is still sent and still unforgeable by a script, so
    // for a browser client this is the only place the same check can be made -
    // and without it the socket would be the unguarded way in to a server whose
    // front door is locked.
    if hub.config.strict_client {
        if let crate::client::OriginVerdict::Refused =
            crate::client::check_origin(&hub.config, &headers)
        {
            hub.stats.clients_refused.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            warn!(
                %ip,
                origin = ?headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()),
                "websocket refused: origin"
            );
            return (StatusCode::FORBIDDEN, crate::client::Refusal::Origin.as_str()).into_response();
        }
    }

    // The token next: an unauthenticated socket never gets upgraded, so an
    // attacker cannot make the server hold open connections for free.
    let session = {
        let mut reg = hub.sessions.lock().unwrap();
        match reg.claim(&hub.config.token_secret, &q.token) {
            Ok(s) => s,
            Err(e) => {
                warn!(%ip, error = e.as_str(), "websocket refused");
                return (StatusCode::UNAUTHORIZED, e.as_str()).into_response();
            }
        }
    };

    if let Err(refusal) = hub.admit(ip) {
        hub.sessions.lock().unwrap().release(session.id);
        return (StatusCode::SERVICE_UNAVAILABLE, refusal.as_str()).into_response();
    }

    info!(
        %ip,
        session = session.id,
        name = %session.name,
        device = %session.device.short(),
        "websocket open"
    );

    // A frame this server has any use for is under two hundred bytes. Four
    // kilobytes is generous for a lobby message and small enough that a
    // malformed length cannot make the process allocate anything worth having.
    ws.max_message_size(8 * 1024)
        .max_frame_size(8 * 1024)
        .on_upgrade(move |socket| async move {
            // A GUARD, not a matching release at the end.
            //
            // The connection slot and the session claim have to be given back
            // on every path out of here, and there are four: a clean close, a
            // socket error, the task being cancelled at shutdown, and a panic
            // somewhere inside the reader. Only a `Drop` covers all four, and
            // a leaked slot is permanent - the address is capped at four
            // connections and never gets one of them back.
            let _guard = ConnGuard { hub: hub.clone(), ip, session: session.id };
            let id = session.id;
            let started = Instant::now();
            run(socket, hub.clone(), session, ip).await;
            info!(%ip, session = id, seconds = started.elapsed().as_secs(), "websocket closed");
        })
}

/// Gives back the connection slot and the session claim however the connection
/// ends. See the note at the call site.
struct ConnGuard {
    hub: Arc<Hub>,
    ip: IpAddr,
    session: u64,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.hub.release(self.ip);
        if let Ok(mut reg) = self.hub.sessions.lock() {
            reg.release(self.session);
        }
    }
}

async fn run(socket: WebSocket, hub: Arc<Hub>, session: Session, ip: IpAddr) {
    let (mut sink, mut stream) = socket.split();
    let config = hub.config.clone();

    let shared = Arc::new(Shared {
        last_seen_ms: AtomicU64::new(0),
        ping_nonce: AtomicU32::new(0),
        ping_at_ms: AtomicU64::new(0),
        opened: Instant::now(),
        bytes_in: AtomicU64::new(0),
        bytes_out: AtomicU64::new(0),
    });

    // Reliable, bounded: the lobby, results, corrections. Thirty-two deep is
    // far more than a well-behaved session ever queues, so a full channel is
    // a client that has stopped reading.
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<Outbound>(32);
    // Latest-wins: snapshots. See the note at the top of room.rs.
    let (snap_tx, mut snap_rx) = watch::channel::<Arc<Vec<u8>>>(Arc::new(Vec::new()));

    let link = PlayerLink { ctrl: ctrl_tx.clone(), snap: snap_tx };

    // ---- the writer -------------------------------------------------------
    let writer = {
        let shared = shared.clone();
        let hub = hub.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let mut ping = tokio::time::interval(config.ping_every);
            ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut nonce: u32 = 1;
            loop {
                let out: Option<Message> = tokio::select! {
                    biased;
                    msg = ctrl_rx.recv() => match msg {
                        None => None,
                        Some(Outbound::Text(s)) => Some(Message::Text(Utf8Bytes::from(s))),
                        Some(Outbound::Binary(b)) => Some(Message::Binary(b.as_slice().to_vec().into())),
                        Some(Outbound::Bye(s)) => {
                            let _ = sink.send(Message::Text(Utf8Bytes::from(s))).await;
                            let _ = sink.send(Message::Close(None)).await;
                            return;
                        }
                    },
                    changed = snap_rx.changed() => {
                        if changed.is_err() { None } else {
                            let frame = snap_rx.borrow_and_update().clone();
                            if frame.is_empty() { continue }
                            Some(Message::Binary(frame.as_slice().to_vec().into()))
                        }
                    },
                    _ = ping.tick() => {
                        // A client that has not answered the previous probe by
                        // the time the timeout has elapsed is gone. Checked
                        // here rather than on a third timer, because this
                        // timer is already the right cadence.
                        let now = shared.ms();
                        let seen = shared.last_seen_ms.load(Ordering::Relaxed);
                        if now.saturating_sub(seen) > config.client_timeout.as_millis() as u64 {
                            warn!(%ip, session = session.id, quiet_ms = now - seen, "client went quiet");
                            let _ = sink.send(Message::Close(None)).await;
                            return;
                        }
                        nonce = nonce.wrapping_add(1).max(1);
                        shared.ping_nonce.store(nonce, Ordering::Relaxed);
                        shared.ping_at_ms.store(now, Ordering::Relaxed);
                        let mut buf = [0u8; 8];
                        match synx_net::msg::write_ping(&mut buf, nonce) {
                            Ok(n) => Some(Message::Binary(buf[..n].to_vec().into())),
                            Err(_) => continue,
                        }
                    }
                };
                let Some(msg) = out else { return };
                let n = match &msg {
                    Message::Text(t) => t.len(),
                    Message::Binary(b) => b.len(),
                    _ => 0,
                };
                // A write that has not completed in the timeout is a peer that
                // is not reading. Without this bound the task waits forever and
                // the connection is never reclaimed.
                match tokio::time::timeout(config.write_timeout, sink.send(msg)).await {
                    Ok(Ok(())) => {
                        shared.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                        hub.stats.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Ok(Err(_)) => return,
                    Err(_) => {
                        warn!(%ip, session = session.id, "socket write stalled; dropping");
                        return;
                    }
                }
            }
        })
    };

    // ---- the reader -------------------------------------------------------
    let mut state = Conn {
        hub: hub.clone(),
        session: session.clone(),
        ip,
        link,
        room: None,
        slot: 0,
        state_bucket: Bucket::per_second(config.state_rate),
        control_bucket: Bucket::per_second(config.control_rate),
        room_bucket: Bucket::new(0.2, 3.0),
        bad_frames: 0,
        shared: shared.clone(),
    };

    // The welcome goes out before anything is read, so a client always knows
    // what it is talking to even if it never says anything.
    let now_ms = hub.started.elapsed().as_millis() as u32;
    state.say(room::welcome(&config, &session.name, &format!("{}", session.id), now_ms));

    let deadline = tokio::time::sleep(config.max_socket);
    tokio::pin!(deadline);

    loop {
        let frame = tokio::select! {
            f = stream.next() => f,
            _ = &mut deadline => {
                info!(%ip, session = session.id, "socket reached its lifetime cap; asking it to reconnect");
                let _ = ctrl_tx
                    .try_send(Outbound::Bye(
                        serde_json::to_string(&ServerMsg::Bye {
                            code: "reconnect",
                            message: "this connection has been open a long time; reconnecting".into(),
                        })
                        .unwrap_or_default(),
                    ));
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                None
            }
        };
        let Some(frame) = frame else { break };
        let Ok(msg) = frame else { break };
        shared.last_seen_ms.store(shared.ms(), Ordering::Relaxed);
        let n = match &msg {
            Message::Text(t) => t.len(),
            Message::Binary(b) => b.len(),
            _ => 0,
        };
        shared.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
        hub.stats.bytes_in.fetch_add(n as u64, Ordering::Relaxed);

        let keep = match msg {
            Message::Binary(b) => state.on_binary(&b).await,
            Message::Text(t) => state.on_text(&t).await,
            Message::Ping(_) | Message::Pong(_) => true,
            Message::Close(_) => false,
        };
        if !keep {
            break;
        }
        hub.sessions.lock().unwrap().touch(session.id);
    }

    // Tell the room the seat is empty before anything else is torn down.
    if let Some(handle) = state.room.take() {
        let _ = handle.tx.send(RoomMsg::Dropped { slot: state.slot, session: session.id }).await;
    }
    writer.abort();
    debug!(
        %ip,
        session = session.id,
        seconds = shared.opened.elapsed().as_secs(),
        kb_in = shared.bytes_in.load(Ordering::Relaxed) / 1024,
        kb_out = shared.bytes_out.load(Ordering::Relaxed) / 1024,
        "connection statistics"
    );
}

/// The reader's own state.
struct Conn {
    hub: Arc<Hub>,
    session: crate::identity::Session,
    ip: IpAddr,
    link: PlayerLink,
    room: Option<RoomHandle>,
    slot: u8,
    state_bucket: Bucket,
    control_bucket: Bucket,
    /// Opening and joining rooms.
    ///
    /// Metered apart from the rest of the lobby because it is the only action
    /// whose cost outlives the request: a room is a task, a tick and an entry
    /// in a table with a finite number of codes in it. A client that creates,
    /// leaves, and creates again in a loop would otherwise hold most of the
    /// server's rooms in their empty-room grace period without ever tripping
    /// the ordinary control limit. One every five seconds, three in hand.
    room_bucket: Bucket,
    /// Malformed frames seen. A handful is a bug somewhere; a stream of them
    /// is somebody probing, and the connection is not worth keeping.
    bad_frames: u32,
    shared: Arc<Shared>,
}

impl Conn {
    fn say(&self, msg: ServerMsg) {
        if let Ok(text) = serde_json::to_string(&msg) {
            let _ = self.link.ctrl.try_send(Outbound::Text(text));
        }
    }

    fn err(&self, code: &'static str, message: &str) {
        self.say(ServerMsg::Error { code, message: message.to_string() });
    }

    /// The binary channel: state, clock sync, and the answer to a probe.
    /// Returns false to close the connection.
    async fn on_binary(&mut self, buf: &[u8]) -> bool {
        if buf.len() > synx_net::MAX_CLIENT_BINARY {
            warn!(ip = %self.ip, len = buf.len(), "oversized binary frame");
            return false;
        }
        let Some((&id, body)) = buf.split_first() else { return true };
        match id {
            synx_net::c2s::STATE => {
                if !self.state_bucket.take() {
                    // Dropped rather than answered: telling a flooding client
                    // that it is flooding is another packet it did not need.
                    self.hub.stats.states_refused.fetch_add(1, Ordering::Relaxed);
                    return true;
                }
                let Ok(m) = synx_net::msg::read_state(body) else {
                    return self.malformed("state");
                };
                let Some(room) = &self.room else { return true };
                self.hub.stats.states_accepted.fetch_add(1, Ordering::Relaxed);
                // try_send, never send: a room whose inbox is full is a room
                // that is behind, and the correct thing to do with a state
                // packet in that situation is throw it away.
                let _ = room.tx.try_send(RoomMsg::State {
                    slot: self.slot,
                    session: self.session.id,
                    car: m.car,
                });
                true
            }
            synx_net::c2s::TIME_REQ => {
                let mut r = synx_net::Reader::new(body);
                let Ok(echo) = r.u32() else { return self.malformed("time") };
                let mut out = [0u8; 16];
                let server_ms = self.hub.started.elapsed().as_millis() as u32;
                if let Ok(n) = synx_net::msg::write_time(&mut out, echo, server_ms) {
                    let _ = self.link.ctrl.try_send(Outbound::Binary(Arc::new(out[..n].to_vec())));
                }
                true
            }
            synx_net::c2s::PONG => {
                let mut r = synx_net::Reader::new(body);
                let Ok(nonce) = r.u32() else { return self.malformed("pong") };
                if nonce == self.shared.ping_nonce.load(Ordering::Relaxed) {
                    let sent = self.shared.ping_at_ms.load(Ordering::Relaxed);
                    let rtt = self.shared.ms().saturating_sub(sent).min(u16::MAX as u64) as u16;
                    if let Some(room) = &self.room {
                        let _ = room.tx.try_send(RoomMsg::Rtt { slot: self.slot, rtt_ms: rtt });
                    }
                }
                true
            }
            _ => self.malformed("unknown"),
        }
    }

    fn malformed(&mut self, what: &str) -> bool {
        self.bad_frames += 1;
        if self.bad_frames <= 3 {
            debug!(ip = %self.ip, what, count = self.bad_frames, "malformed frame");
        }
        if self.bad_frames > 24 {
            warn!(ip = %self.ip, "too many malformed frames; closing");
            return false;
        }
        true
    }

    /// The text channel: everything about lobbies.
    async fn on_text(&mut self, raw: &str) -> bool {
        if raw.len() > synx_net::MAX_CLIENT_TEXT {
            warn!(ip = %self.ip, len = raw.len(), "oversized text frame");
            return false;
        }
        if !self.control_bucket.take() {
            self.err("slow-down", "too many requests");
            return true;
        }
        let msg: ClientMsg = match serde_json::from_str(raw) {
            Ok(m) => m,
            Err(e) => {
                debug!(ip = %self.ip, error = %e, "unparseable lobby message");
                self.err("bad-message", "that is not a message this server knows");
                return self.malformed("json");
            }
        };

        match msg {
            ClientMsg::Create { map, ruleset, private, max } => {
                if self.room.is_some() {
                    self.err("in-room", "leave the room you are in first");
                    return true;
                }
                if !self.room_bucket.take() {
                    self.err("slow-down", "wait a moment before opening another room");
                    return true;
                }
                if crate::maps::map(map).is_none() {
                    self.err(HubError::BadMap.code(), HubError::BadMap.message());
                    return true;
                }
                if !ruleset.is_empty() && Ruleset::from_str(&ruleset).is_none() {
                    self.err("bad-ruleset", "there is no such car");
                    return true;
                }
                let rules = Ruleset::from_str(&ruleset).unwrap_or(Ruleset::Stock);
                let max = if max == 0 { synx_net::MAX_PLAYERS as u8 } else { max };
                match self.hub.open(map, rules, !private, max) {
                    Ok(h) => self.enter(h).await,
                    Err(e) => self.err(e.code(), e.message()),
                }
            }
            ClientMsg::Join { code } => {
                if self.room.is_some() {
                    self.err("in-room", "leave the room you are in first");
                    return true;
                }
                if !self.room_bucket.take() {
                    self.err("slow-down", "wait a moment before joining another room");
                    return true;
                }
                match self.hub.find(&code) {
                    Ok(h) => self.enter(h).await,
                    Err(e) => self.err(e.code(), e.message()),
                }
            }
            ClientMsg::Quick { map } => {
                if self.room.is_some() {
                    self.err("in-room", "leave the room you are in first");
                    return true;
                }
                if !self.room_bucket.take() {
                    self.err("slow-down", "wait a moment before looking for another race");
                    return true;
                }
                match self.hub.quick(map, Ruleset::Stock) {
                    Ok(h) => self.enter(h).await,
                    Err(e) => self.err(e.code(), e.message()),
                }
            }
            ClientMsg::Rooms {} => {
                self.say(ServerMsg::Rooms { rooms: self.hub.list() });
            }
            ClientMsg::Leave {} => {
                if let Some(h) = self.room.take() {
                    let _ =
                        h.tx.send(RoomMsg::Dropped { slot: self.slot, session: self.session.id }).await;
                    self.slot = 0;
                }
            }
            other => {
                let Some(room) = &self.room else {
                    self.err("no-room", "you are not in a room");
                    return true;
                };
                let _ = room.tx.try_send(RoomMsg::Control {
                    slot: self.slot,
                    session: self.session.id,
                    msg: Box::new(other),
                });
            }
        }
        true
    }

    /// Ask a room for a seat and remember the answer.
    async fn enter(&mut self, handle: RoomHandle) {
        // Asked of the summary first. The room is authoritative and re-checks
        // when the join lands, but answering here means a player who picked a
        // room that filled up in the meantime is told which of the two things
        // happened rather than a flat "refused".
        if !handle.summary.joinable() {
            let e = if handle.summary.players.load(Ordering::Relaxed) >= handle.summary.max_players {
                HubError::RoomFull
            } else {
                HubError::RoomRacing
            };
            self.err(e.code(), e.message());
            return;
        }
        let (tx, rx) = oneshot::channel();
        let req = JoinRequest {
            session: self.session.id,
            name: self.session.name.clone(),
            device: self.session.device.short(),
            link: self.link.clone(),
            reply: tx,
        };
        if handle.tx.send(RoomMsg::Join(Box::new(req))).await.is_err() {
            // The room closed between being found and being asked, which is
            // an ordinary race and not an error worth logging loudly.
            self.err(HubError::NoSuchRoom.code(), HubError::NoSuchRoom.message());
            return;
        }
        // Bounded: a room that never answers must not strand a connection.
        match tokio::time::timeout(std::time::Duration::from_secs(5), rx).await {
            Ok(Ok(Ok(slot))) => {
                self.slot = slot;
                self.room = Some(handle);
            }
            Ok(Ok(Err(why))) => self.err("refused", why),
            _ => self.err("timeout", "the room did not answer"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        use axum::http::HeaderName;
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn sock() -> SocketAddr {
        "10.0.0.1:1234".parse().unwrap()
    }

    #[test]
    fn the_client_address_cannot_be_spoofed_by_the_client() {
        // the proxy appends, so the client's own entry is on the left and the
        // one that can be trusted is on the right
        let h = headers(&[("x-forwarded-for", "1.2.3.4, 203.0.113.9")]);
        assert_eq!(client_ip(&h, sock()).to_string(), "203.0.113.9");

        // a proxy that replaces gives one entry, which is still correct
        let h = headers(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(client_ip(&h, sock()).to_string(), "203.0.113.9");

        // rubbish in the header falls through to the socket
        let h = headers(&[("x-forwarded-for", "not-an-ip")]);
        assert_eq!(client_ip(&h, sock()).to_string(), "10.0.0.1");
        assert_eq!(client_ip(&HeaderMap::new(), sock()).to_string(), "10.0.0.1");

        // a CDN header wins outright when it is present
        let h = headers(&[("cf-connecting-ip", "198.51.100.7"), ("x-forwarded-for", "1.1.1.1")]);
        assert_eq!(client_ip(&h, sock()).to_string(), "198.51.100.7");
    }
}
