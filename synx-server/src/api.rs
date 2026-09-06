//! HTTP endpoints for health, sessions, rooms, and diagnostics.

use crate::sync::LockExt;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::client;
use crate::hub::Hub;
use crate::identity::{
    self, ChallengeResponse, DevicePrint, RegisterError, RegisterRequest, RegisterResponse,
};
use crate::ws::client_ip;

/// The gate every request passes through.
///
/// Load shedding, the jail and the per-address bucket, in that order - cheapest
/// test first, so a flood is refused by an atomic and a hash lookup rather than
/// by a handler. The health probe is exempt: the platform must always be able
/// to ask whether the process is alive, and a probe that is rate limited
/// eventually gets the instance restarted for no reason.
pub async fn gate(
    State(hub): State<Arc<Hub>>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| client_ip(req.headers(), c.0))
        .unwrap_or_else(|| std::net::Ipv4Addr::UNSPECIFIED.into());

    // The guard is held for the whole handler and released on every path out
    // of it, including a cancelled request and a panicking one.
    let _guard = match hub.gate(ip) {
        Ok(g) => g,
        Err(e) => {
            return (
                StatusCode::from_u16(e.status()).unwrap_or(StatusCode::TOO_MANY_REQUESTS),
                Json(json!({ "error": "rate-limited", "message": e.as_str() })),
            )
                .into_response();
        }
    };
    next.run(req).await
}

/// `GET /healthz` - the host's own probe, and the cheapest possible answer.
pub async fn healthz(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    if hub.is_ready() {
        (StatusCode::OK, "ok")
    } else {
        // 503 rather than 200 while loading, so a health check does not route
        // players at an instance that cannot take them yet.
        (StatusCode::SERVICE_UNAVAILABLE, "starting")
    }
}

#[derive(Serialize)]
pub struct WakeResponse {
    pub ready: bool,
    /// How long this instance has been up. A small number means the client
    /// just woke it, which is exactly what the interface wants to say.
    pub uptime_s: u64,
    pub server_time_ms: u64,
    pub protocol: u16,
    pub build: &'static str,
    pub players: usize,
    pub rooms: usize,
    /// True when the instance is at capacity, so the client can say so before
    /// the player picks a route.
    pub full: bool,
}

/// `GET /wake` - what the game calls the moment multiplayer is in view.
pub async fn wake(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    let n = hub.stats.wakes.fetch_add(1, Ordering::Relaxed);
    // Only the first few are logged. A client that is polling while it waits
    // would otherwise be the entire log for the minute it takes to come up.
    if n < 3 {
        info!(uptime_s = hub.uptime_s(), "woken");
    }
    Json(WakeResponse {
        ready: hub.is_ready(),
        uptime_s: hub.uptime_s(),
        server_time_ms: identity::now_ms(),
        protocol: synx_net::PROTOCOL_VERSION,
        build: crate::BUILD,
        players: hub.player_count(),
        rooms: hub.room_count(),
        full: hub.room_count() >= hub.config.max_rooms,
    })
}

/// `GET /api/handshake` - a proof-of-work challenge and the server's clock.
pub async fn handshake(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    Json(ChallengeResponse {
        challenge: identity::issue_challenge(&hub.config.token_secret),
        bits: hub.config.pow_bits,
        ttl_ms: 120_000,
        server_time_ms: identity::now_ms(),
        protocol: synx_net::PROTOCOL_VERSION,
        fingerprint: synx_net::WIRE_FINGERPRINT,
        build: crate::BUILD,
        ready: hub.is_ready(),
    })
}

/// `POST /api/session` - register, and get a token for this session.
///
/// The whole identity story lives in `identity.rs`, including an honest
/// account of what a device print can and cannot prove. This is the plumbing.
pub async fn session(
    State(hub): State<Arc<Hub>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let ip = client_ip(&headers, peer);

    // The body cap is enforced by a layer, but the parse is still the first
    // untrusted thing that happens, so it is fenced here too.
    if body.len() > 8 * 1024 {
        return refuse(RegisterError::BadChallenge, "that request is too large");
    }
    let req: RegisterRequest = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            warn!(%ip, error = %e, "unparseable registration");
            return refuse(RegisterError::BadChallenge, "that is not a registration");
        }
    };

    if req.protocol != 0 && req.protocol != synx_net::PROTOCOL_VERSION {
        warn!(%ip, theirs = req.protocol, ours = synx_net::PROTOCOL_VERSION, "protocol mismatch");
        return refuse(RegisterError::ProtocolMismatch, RegisterError::ProtocolMismatch.as_str());
    }

    // Does this client speak our wire format, and is it allowed here?
    // Answered before the proof of work is verified and before anything is
    // allocated for this caller, because a client that will not be admitted
    // should cost an integer compare.
    if let Err(r) = client::admit(&hub.config, &headers, req.fingerprint) {
        hub.stats.clients_refused.fetch_add(1, Ordering::Relaxed);
        warn!(
            %ip,
            refusal = r.code(),
            theirs = req.fingerprint,
            ours = synx_net::WIRE_FINGERPRINT,
            build = %req.build,
            origin = ?headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()),
            "client refused at the door"
        );
        return (
            StatusCode::from_u16(r.status()).unwrap_or(StatusCode::FORBIDDEN),
            Json(json!({ "error": r.code(), "message": r.as_str() })),
        )
            .into_response();
    }

    // Metered before the proof is checked, so a flood of bad proofs is a flood
    // of one hash each rather than of one hash plus a table entry each.
    if !hub.ips.lock_safe().may_register(ip, hub.config.register_per_minute) {
        warn!(%ip, "registration rate limited");
        return refuse(RegisterError::RateLimited, RegisterError::RateLimited.as_str());
    }

    if let Err(e) =
        identity::verify_challenge(&hub.config.token_secret, &req.challenge, &req.nonce, hub.config.pow_bits)
    {
        warn!(%ip, error = e.as_str(), "registration refused");
        return refuse(e, e.as_str());
    }

    // Capacity is checked here as well as at the socket, so a player is told
    // "the grid is full" on the screen where they can do something about it
    // rather than after they have picked a route.
    if hub.sessions.lock_safe().len() >= hub.config.max_connections * 4 {
        return refuse(RegisterError::ServerFull, RegisterError::ServerFull.as_str());
    }

    let name = identity::clean_name(&req.name);
    let print: DevicePrint = req.device;
    let device = print.hash(&hub.config.token_secret);

    let (token, sess) = {
        let mut reg = hub.sessions.lock_safe();
        reg.open(&hub.config.token_secret, name.clone(), device, Some(ip), hub.config.session_ttl)
    };
    identity::log_registration(&sess, &print, Some(ip));

    (
        StatusCode::OK,
        Json(json!(RegisterResponse {
            token,
            name,
            fingerprint: synx_net::WIRE_FINGERPRINT,
            session: sess.id.to_string(),
            device: device.short(),
            expires_ms: sess.expires_ms,
            server_time_ms: identity::now_ms(),
            protocol: synx_net::PROTOCOL_VERSION,
            ws: "/ws".into(),
        })),
    )
        .into_response()
}

fn refuse(e: RegisterError, message: &str) -> axum::response::Response {
    (
        StatusCode::from_u16(e.status()).unwrap_or(StatusCode::BAD_REQUEST),
        Json(json!({ "error": e.code(), "message": message })),
    )
        .into_response()
}

/// `GET /api/rooms` - the public lobby list, without needing a socket.
pub async fn rooms(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    Json(json!({ "rooms": hub.list(), "ready": hub.is_ready() }))
}

/// `GET /api/stats` - everything the process knows about itself.
///
/// There is no shell on this host and no persistent log, so this endpoint is
/// how the server is actually observed. It is read-only, it names nobody, and
/// it is the same data the heartbeat line carries.
pub async fn stats(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    let s = &hub.stats;
    let (sessions, connected, bans) = {
        let r = hub.sessions.lock_safe();
        (r.len(), r.connected(), r.bans())
    };
    let (addresses, connections, jailed) = {
        let t = hub.ips.lock_safe();
        (t.addresses(), t.total(), t.jailed_count())
    };
    Json(json!({
        "build": crate::BUILD,
        "protocol": synx_net::PROTOCOL_VERSION,
        "fingerprint": synx_net::WIRE_FINGERPRINT,
        "ready": hub.is_ready(),
        "uptime_s": hub.uptime_s(),
        "course": {
            "samples": hub.course.count,
            "length_units": hub.course.length,
            "checksum": format!("{:08x}", hub.course.checksum),
        },
        "now": {
            "rooms": hub.room_count(),
            "players": hub.player_count(),
            "connections": connections,
            "addresses": addresses,
            "sessions": sessions,
            "sessions_connected": connected,
            "bans": bans,
        },
        "totals": {
            "connections": s.connections_total.load(Ordering::Relaxed),
            "connections_refused": s.connections_refused.load(Ordering::Relaxed),
            "rooms_opened": s.rooms_opened.load(Ordering::Relaxed),
            "races_started": s.races_started.load(Ordering::Relaxed),
            "states_accepted": s.states_accepted.load(Ordering::Relaxed),
            "states_refused": s.states_refused.load(Ordering::Relaxed),
            "bytes_in": s.bytes_in.load(Ordering::Relaxed),
            "bytes_out": s.bytes_out.load(Ordering::Relaxed),
            "wakes": s.wakes.load(Ordering::Relaxed),
        },
        "requests": {
            "total": s.requests.load(Ordering::Relaxed),
            "refused": s.requests_refused.load(Ordering::Relaxed),
            "shed": s.shed.load(Ordering::Relaxed),
            "inflight": hub.inflight(),
            "jailed_addresses": jailed,
        },
        "limits": {
            "max_rooms": hub.config.max_rooms,
            "max_connections": hub.config.max_connections,
            "max_per_ip": hub.config.max_per_ip,
            "max_inflight": hub.config.max_inflight,
            "snapshot_hz": hub.config.snapshot_hz,
            "state_rate": hub.config.state_rate,
            "http_rate": hub.config.http_rate,
            "accept_rate": hub.config.accept_rate,
        },
        "client_gate": {
            "origins": hub.config.allowed_origins,
            "refused": s.clients_refused.load(Ordering::Relaxed),
        },
        "faults": {
            "rooms_panicked": s.rooms_panicked.load(Ordering::Relaxed),
        },
    }))
}

/// `GET /` - a plain page, so a human who opens the URL sees something.
pub async fn index(State(hub): State<Arc<Hub>>) -> impl IntoResponse {
    let body = format!(
        "SYNX multiplayer server\n\
         =======================\n\
         build      {}\n\
         protocol   {}\n\
         wire       {:08x}\n\
         status     {}\n\
         uptime     {} s\n\
         rooms      {}\n\
         players    {}\n\
         \n\
         GET  /healthz          liveness\n\
         GET  /wake             wake the instance, and how awake it is\n\
         GET  /api/handshake    a registration challenge and this wire fingerprint\n\
         POST /api/session      register, and receive a session token\n\
         GET  /api/rooms        public lobbies\n\
         GET  /api/stats        everything this process knows about itself\n\
         WS   /ws?token=...     the game\n",
        crate::BUILD,
        synx_net::PROTOCOL_VERSION,
        synx_net::WIRE_FINGERPRINT,
        if hub.is_ready() { "ready" } else { "starting" },
        hub.uptime_s(),
        hub.room_count(),
        hub.player_count(),
    );
    ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], body)
}

/// Anything that is not a route.
pub async fn not_found() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, Json(json!({ "error": "no-such-route" })))
}

/// The periodic housekeeping task. One timer for the whole process.
pub async fn housekeeping(hub: Arc<Hub>) {
    let mut tick = tokio::time::interval(Duration::from_secs(60));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        hub.housekeeping();
    }
}
