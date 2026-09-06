//! Shared registry for rooms, sessions, addresses, and server statistics.

use crate::sync::LockExt;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::Config;
use crate::control::{Phase, RoomBrief};
use crate::course::Course;
use crate::identity::Registry;
use crate::limits::IpTable;
use crate::maps::Ruleset;
use crate::room::{self, Room, RoomMsg, RoomSummary};

/// One room, from the outside.
#[derive(Clone, Debug)]
pub struct RoomHandle {
    pub code: String,
    pub tx: mpsc::Sender<RoomMsg>,
    pub summary: Arc<RoomSummary>,
}

/// Counters that are only ever read by the diagnostics endpoint and the
/// periodic log line. Atomics rather than a lock, so nothing on a hot path
/// ever waits on the statistics.
#[derive(Default)]
pub struct Stats {
    pub connections_total: AtomicU64,
    pub connections_refused: AtomicU64,
    pub rooms_opened: AtomicU64,
    pub races_started: AtomicU64,
    pub states_accepted: AtomicU64,
    pub states_refused: AtomicU64,
    pub bytes_out: AtomicU64,
    pub bytes_in: AtomicU64,
    pub wakes: AtomicU64,
    pub requests: AtomicU64,
    pub requests_refused: AtomicU64,
    pub shed: AtomicU64,
    pub rooms_panicked: AtomicU64,
    /// Clients turned away by the door in `client.rs` - wrong wire
    /// format, wrong origin, or unable to prove they are the game.
    pub clients_refused: AtomicU64,
}

pub struct Hub {
    pub config: Arc<Config>,
    pub course: Arc<Course>,
    pub sessions: Mutex<Registry>,
    pub ips: Mutex<IpTable>,
    pub stats: Stats,
    pub started: Instant,
    rooms: Mutex<HashMap<String, RoomHandle>>,
    /// Set once the server has finished loading and is willing to take
    /// players. The health endpoint reports it, which is what lets the game
    /// tell "waking up" from "here".
    ready: AtomicU8,
    /// Requests currently being served. The load-shedding counter: past the
    /// configured ceiling the process answers 503 immediately rather than
    /// accepting work it has no CPU to do, which is the difference between
    /// degrading and collapsing.
    inflight: AtomicUsize,
}

/// Holds one unit of in-flight capacity and gives it back on drop.
///
/// A guard rather than a matching decrement at the end of the handler, because
/// a handler can return early, be cancelled when the client hangs up, or
/// panic - and a counter that leaks on any of those paths reaches its ceiling
/// and never comes back down.
pub struct InflightGuard(Arc<Hub>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Why a room could not be opened or joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HubError {
    TooManyRooms,
    NoSuchRoom,
    RoomFull,
    RoomRacing,
    BadMap,
}

impl HubError {
    pub fn code(self) -> &'static str {
        match self {
            HubError::TooManyRooms => "server-full",
            HubError::NoSuchRoom => "no-room",
            HubError::RoomFull => "room-full",
            HubError::RoomRacing => "room-racing",
            HubError::BadMap => "bad-map",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            HubError::TooManyRooms => "the server is at capacity; try again shortly",
            HubError::NoSuchRoom => "no room with that code",
            HubError::RoomFull => "that room is full",
            HubError::RoomRacing => "that race has already started",
            HubError::BadMap => "there is no such route",
        }
    }
}

impl Hub {
    pub fn new(config: Arc<Config>, course: Arc<Course>) -> Arc<Hub> {
        Arc::new(Hub {
            config,
            course,
            sessions: Mutex::new(Registry::default()),
            ips: Mutex::new(IpTable::default()),
            stats: Stats::default(),
            started: Instant::now(),
            rooms: Mutex::new(HashMap::new()),
            ready: AtomicU8::new(0),
            inflight: AtomicUsize::new(0),
        })
    }

    pub fn mark_ready(&self) {
        self.ready.store(1, Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed) == 1
    }

    pub fn uptime_s(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    /// Open a room and start its task.
    pub fn open(
        self: &Arc<Self>,
        map: u8,
        ruleset: Ruleset,
        public: bool,
        max_players: u8,
    ) -> Result<RoomHandle, HubError> {
        if crate::maps::map(map).is_none() {
            return Err(HubError::BadMap);
        }
        let max_players = max_players.clamp(2, synx_net::MAX_PLAYERS as u8);

        let (code, handle) = {
            let mut rooms = self.rooms.lock_safe();
            if rooms.len() >= self.config.max_rooms {
                return Err(HubError::TooManyRooms);
            }
            // Retried rather than assumed unique: at 887 million codes a
            // collision is vanishingly unlikely and silently reusing one would
            // put two sets of players in the same room.
            let mut code = room::make_code();
            for _ in 0..8 {
                if !rooms.contains_key(&code) {
                    break;
                }
                code = room::make_code();
            }
            if rooms.contains_key(&code) {
                return Err(HubError::TooManyRooms);
            }

            let summary = Arc::new(RoomSummary {
                players: AtomicU8::new(0),
                phase: AtomicU8::new(0),
                map: AtomicU8::new(map),
                ruleset: AtomicU8::new(ruleset as u8),
                public,
                max_players,
            });
            // Bounded. A room that is not draining its inbox is a room that
            // has stopped, and queueing another thousand packets at it does
            // not help anybody; the sender treats a full channel as a dropped
            // packet, which for state is exactly right.
            let (tx, rx) = mpsc::channel::<RoomMsg>(256);
            let handle = RoomHandle { code: code.clone(), tx, summary: summary.clone() };
            rooms.insert(code.clone(), handle.clone());

            let room = Room::new(
                code.clone(),
                self.clone(),
                self.config.clone(),
                self.course.clone(),
                summary,
                map,
                ruleset,
                public,
                max_players,
            );
            // SUPERVISED, not merely spawned.
            //
            // `Room::run` removes itself from the table on the way out, which
            // covers every ordinary exit and none of the extraordinary ones. A
            // panic inside a room would leave its entry in the map for the
            // life of the process: the code stays claimed, matchmaking keeps
            // offering it, and every player who joins is talking to a channel
            // whose receiver is gone. The supervisor reclaims it either way.
            let supervisor = self.clone();
            let watched = code.clone();
            tokio::spawn(async move {
                let joined = tokio::spawn(room.run(rx)).await;
                if let Err(e) = joined {
                    if e.is_panic() {
                        supervisor.stats.rooms_panicked.fetch_add(1, Ordering::Relaxed);
                        error!(room = %watched, "room task panicked; the room has been reclaimed");
                    }
                }
                supervisor.forget(&watched);
            });
            (code, handle)
        };

        self.stats.rooms_opened.fetch_add(1, Ordering::Relaxed);
        info!(room = %code, public, max_players, rooms = self.room_count(), "room registered");
        Ok(handle)
    }

    pub fn find(&self, code: &str) -> Result<RoomHandle, HubError> {
        // Codes are shown in upper case and typed in whatever the player felt
        // like, so they are matched case-insensitively rather than being a
        // support request. The shape is checked before the map is touched: a
        // client sending rubbish should cost six comparisons, not a hash and a
        // lock.
        let trimmed = code.trim();
        if trimmed.len() != 6 || !trimmed.is_ascii() {
            return Err(HubError::NoSuchRoom);
        }
        let key = trimmed.to_ascii_uppercase();
        if !key.bytes().all(|b| crate::room::CODE_ALPHABET.contains(&b)) {
            return Err(HubError::NoSuchRoom);
        }
        let rooms = self.rooms.lock_safe();
        rooms.get(&key).cloned().ok_or(HubError::NoSuchRoom)
    }

    /// Find a room worth joining, or open one.
    ///
    /// Fullest-that-still-has-room first: filling a room with three people is
    /// a better race than starting a fourth room with one person in it, and it
    /// is also what keeps the room count - and therefore the tick budget -
    /// down on a small instance.
    pub fn quick(self: &Arc<Self>, map: u8, ruleset: Ruleset) -> Result<RoomHandle, HubError> {
        let want_map = crate::maps::map(map).map(|m| m.id);
        {
            let rooms = self.rooms.lock_safe();
            let mut best: Option<(u8, &RoomHandle)> = None;
            for h in rooms.values() {
                if !h.summary.public || !h.summary.joinable() {
                    continue;
                }
                if let Some(id) = want_map {
                    if h.summary.map.load(Ordering::Relaxed) != id {
                        continue;
                    }
                }
                let n = h.summary.players.load(Ordering::Relaxed);
                if n == 0 {
                    continue;
                }
                if best.is_none_or(|(bn, _)| n > bn) {
                    best = Some((n, h));
                }
            }
            if let Some((_, h)) = best {
                return Ok(h.clone());
            }
        }
        self.open(want_map.unwrap_or(0), ruleset, true, synx_net::MAX_PLAYERS as u8)
    }

    /// Every room anybody may walk into.
    pub fn list(&self) -> Vec<RoomBrief> {
        let rooms = self.rooms.lock_safe();
        let mut out: Vec<RoomBrief> = rooms
            .values()
            .filter(|h| h.summary.public && h.summary.players.load(Ordering::Relaxed) > 0)
            .map(|h| {
                let map = crate::maps::map(h.summary.map.load(Ordering::Relaxed))
                    .unwrap_or(&crate::maps::MAPS[0]);
                RoomBrief {
                    code: h.code.clone(),
                    map: map.id,
                    map_name: map.name,
                    players: h.summary.players.load(Ordering::Relaxed),
                    max_players: h.summary.max_players,
                    phase: h.summary.phase(),
                    ruleset: h.summary.ruleset().label(),
                }
            })
            .collect();
        // Joinable first, then fullest: the list is a thing to pick from, so
        // the top of it should be the best answer.
        out.sort_by(|a, b| {
            let ja = matches!(a.phase, Phase::Lobby | Phase::Results);
            let jb = matches!(b.phase, Phase::Lobby | Phase::Results);
            jb.cmp(&ja).then(b.players.cmp(&a.players))
        });
        out.truncate(24);
        out
    }

    /// Called by a room task as it exits.
    pub fn forget(&self, code: &str) {
        self.rooms.lock_safe().remove(code);
    }

    pub fn room_count(&self) -> usize {
        self.rooms.lock_safe().len()
    }

    pub fn player_count(&self) -> usize {
        self.rooms
            .lock()
            .unwrap()
            .values()
            .map(|h| h.summary.players.load(Ordering::Relaxed) as usize)
            .sum()
    }

    /// The gate every HTTP request passes through.
    ///
    /// Three tests, cheapest first: the load-shed counter (one atomic), the
    /// jail (one hash lookup) and the per-address bucket (a clock read). Under
    /// a flood almost everything is refused by one of the first two.
    pub fn gate(self: &Arc<Self>, ip: IpAddr) -> Result<InflightGuard, crate::limits::Refusal> {
        self.stats.requests.fetch_add(1, Ordering::Relaxed);
        let n = self.inflight.fetch_add(1, Ordering::Relaxed);
        let guard = InflightGuard(self.clone());
        if n >= self.config.max_inflight {
            self.stats.shed.fetch_add(1, Ordering::Relaxed);
            return Err(crate::limits::Refusal::ServerFull);
        }
        if let Err(e) = self.ips.lock_safe().may_request(ip, self.config.http_rate) {
            self.stats.requests_refused.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        Ok(guard)
    }

    /// Take a connection slot for `ip`, or say why not.
    pub fn admit(&self, ip: IpAddr) -> Result<(), crate::limits::Refusal> {
        let r = {
            let mut t = self.ips.lock_safe();
            if !t.may_connect(ip, self.config.connect_rate) {
                // Either jailed, or opening sockets faster than any client
                // needs to. Both answer the same way.
                Err(crate::limits::Refusal::TooFast)
            } else if !t.may_accept(self.config.accept_rate) {
                Err(crate::limits::Refusal::TooFast)
            } else {
                t.admit(ip, self.config.max_connections, self.config.max_per_ip)
            }
        };
        match r {
            Ok(()) => {
                self.stats.connections_total.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                self.stats.connections_refused.fetch_add(1, Ordering::Relaxed);
                // At debug for the ordinary case - a household at its cap is
                // not news, and logging it at warning turns a busy evening
                // into a wall of text - and at warning for the rest.
                if e == crate::limits::Refusal::TooManyFromAddress {
                    tracing::debug!(%ip, refusal = e.as_str(), "connection refused");
                } else {
                    warn!(%ip, refusal = e.as_str(), "connection refused");
                }
                Err(e)
            }
        }
    }

    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    pub fn release(&self, ip: IpAddr) {
        self.ips.lock_safe().release(ip);
    }

    /// Periodic housekeeping and the heartbeat log line.
    ///
    /// The log line is not decoration. On a host with no shell and no
    /// persistent storage, the log IS the observability, and one line a minute
    /// that says how many people are here and what they are doing is the
    /// difference between diagnosing a report and guessing at it.
    pub fn housekeeping(&self) {
        {
            let mut s = self.sessions.lock_safe();
            s.sweep(self.config.session_idle);
        }
        self.ips.lock_safe().sweep();

        let (sessions, connected, bans) = {
            let s = self.sessions.lock_safe();
            (s.len(), s.connected(), s.bans())
        };
        let (addrs, live) = {
            let t = self.ips.lock_safe();
            (t.addresses(), t.total())
        };
        let jailed = self.ips.lock_safe().jailed_count();
        info!(
            uptime_s = self.uptime_s(),
            rooms = self.room_count(),
            players = self.player_count(),
            connections = live,
            addresses = addrs,
            sessions,
            connected,
            bans,
            rooms_opened = self.stats.rooms_opened.load(Ordering::Relaxed),
            races = self.stats.races_started.load(Ordering::Relaxed),
            states_ok = self.stats.states_accepted.load(Ordering::Relaxed),
            states_bad = self.stats.states_refused.load(Ordering::Relaxed),
            kb_in = self.stats.bytes_in.load(Ordering::Relaxed) / 1024,
            kb_out = self.stats.bytes_out.load(Ordering::Relaxed) / 1024,
            wakes = self.stats.wakes.load(Ordering::Relaxed),
            requests = self.stats.requests.load(Ordering::Relaxed),
            refused = self.stats.requests_refused.load(Ordering::Relaxed),
            shed = self.stats.shed.load(Ordering::Relaxed),
            jailed,
            inflight = self.inflight(),
            "heartbeat"
        );
    }

    /// Tell every room to stand down, for a clean shutdown.
    pub async fn close_all(&self) {
        let handles: Vec<RoomHandle> = self.rooms.lock_safe().values().cloned().collect();
        for h in handles {
            let _ = h.tx.send(RoomMsg::Close).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hub() -> Arc<Hub> {
        let mut c = Config::from_env();
        c.max_rooms = 3;
        Hub::new(Arc::new(c), Arc::new(Course::embedded()))
    }

    #[tokio::test]
    async fn rooms_open_are_found_and_are_capped() {
        let h = hub();
        let a = h.open(0, Ruleset::Stock, true, 4).unwrap();
        assert_eq!(h.find(&a.code).unwrap().code, a.code);
        // codes are matched however the player typed them
        assert_eq!(h.find(&a.code.to_lowercase()).unwrap().code, a.code);
        assert_eq!(h.find("ZZZZZZ").unwrap_err(), HubError::NoSuchRoom);
        assert_eq!(h.find("short").unwrap_err(), HubError::NoSuchRoom);

        h.open(1, Ruleset::Stock, true, 4).unwrap();
        h.open(2, Ruleset::Stock, true, 4).unwrap();
        assert_eq!(h.open(3, Ruleset::Stock, true, 4).unwrap_err(), HubError::TooManyRooms);

        assert_eq!(h.open(200, Ruleset::Stock, true, 4).unwrap_err(), HubError::BadMap);
    }

    #[tokio::test]
    async fn quick_play_fills_a_room_before_opening_another() {
        let h = hub();
        let a = h.open(2, Ruleset::Stock, true, 4).unwrap();
        // an empty room is not offered - it would be a room of one
        let opened = h.quick(2, Ruleset::Stock).unwrap();
        assert_ne!(opened.code, a.code);

        a.summary.players.store(2, Ordering::Relaxed);
        assert_eq!(h.quick(2, Ruleset::Stock).unwrap().code, a.code);

        // ...but not once it is racing
        a.summary.phase.store(2, Ordering::Relaxed);
        assert_ne!(h.quick(2, Ruleset::Stock).unwrap().code, a.code);
    }

    #[tokio::test]
    async fn a_private_room_is_never_listed_or_matched() {
        let h = hub();
        let p = h.open(0, Ruleset::Stock, false, 4).unwrap();
        p.summary.players.store(2, Ordering::Relaxed);
        assert!(h.list().is_empty(), "a private room was listed");
        assert_ne!(h.quick(0, Ruleset::Stock).unwrap().code, p.code);
        // but it can still be found by its code, which is the point of it
        assert_eq!(h.find(&p.code).unwrap().code, p.code);
    }

    /// Being at the cap is refused; being at the cap is not abuse. A house
    /// with four players in it must not be jailed for the fifth click, so the
    /// slot has to come straight back when one is released.
    #[tokio::test]
    async fn connections_are_capped_but_a_full_house_is_not_punished() {
        let mut c = Config::from_env();
        c.max_rooms = 3;
        // the attempt limiter is not what is under test here
        c.connect_rate = 1_000.0;
        let h = Hub::new(Arc::new(c), Arc::new(Course::embedded()));
        let ip: IpAddr = std::net::Ipv4Addr::new(203, 0, 113, 5).into();
        for i in 0..h.config.max_per_ip {
            h.admit(ip).unwrap_or_else(|e| panic!("connection {i} refused: {:?}", e.as_str()));
        }
        assert!(h.admit(ip).is_err(), "the cap was not enforced");
        assert!(!h.ips.lock_safe().jailed(ip), "a full house was jailed");
        h.release(ip);
        assert!(h.admit(ip).is_ok(), "the released slot did not come back");
    }

    /// Opening sockets in a loop, on the other hand, does earn a jail term.
    #[tokio::test]
    async fn hammering_the_door_is_jailed() {
        let mut c = Config::from_env();
        c.connect_rate = 1.0;
        let h = Hub::new(Arc::new(c), Arc::new(Course::embedded()));
        let ip: IpAddr = std::net::Ipv4Addr::new(198, 51, 100, 9).into();
        let mut refused = 0;
        for _ in 0..40 {
            if h.admit(ip).is_err() {
                refused += 1;
            }
        }
        assert!(refused > 20, "a connection flood was not throttled");
        assert!(h.ips.lock_safe().jailed(ip), "a flooding address was not jailed");
    }
}
