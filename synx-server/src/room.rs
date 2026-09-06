//! One room: up to four cars, one route, and the race director that owns them.
//!
//! # Why a room is a task and not a lock
//!
//! The obvious shape is a `Mutex<Room>` that every connection reaches into.
//! It is also the shape that produces the two bugs that are hardest to find in
//! a game server: a lock held across an `await` (which stalls every player in
//! the room behind the slowest socket), and two connections observing the room
//! in an order neither of them can reason about.
//!
//! So a room is an actor. It owns its state outright, it is reached only
//! through a channel, and everything that happens to it happens in the order
//! it arrived - which means the race director is ordinary single-threaded code
//! with no locking in it at all, and the only concurrency in the whole file is
//! the channel at the front door.
//!
//! # Why snapshots go out through a `watch`
//!
//! This is the single most important decision in the server, so it is worth
//! being explicit. The transport is TCP. If a player's connection stalls -
//! a phone changing cell, a congested link - and the server keeps queueing
//! snapshots for them, then when the stall clears they receive a burst of
//! states that are all out of date, in order, slowly. They see the last two
//! seconds of the race played back at them before catching up. That is the
//! classic failure of a game on a reliable transport and it is entirely
//! self-inflicted.
//!
//! A [`tokio::sync::watch`] holds exactly one value and overwrites it. A
//! writer that is keeping up sends every snapshot; a writer that is behind
//! silently skips to the newest one, which is the only one worth having. The
//! protocol is designed for that - every snapshot is complete and depends on
//! no other - and the two decisions only work together.
//!
//! Control messages (the lobby, the results, a correction) go on a separate
//! bounded channel, because those are not state and losing one is not
//! recoverable.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use synx_net::msg::{CarState, SnapshotEntry};
use synx_net::{flag, Correction, MAX_PLAYERS};
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::control::{
    clean_chat, map_views, ClientMsg, GridSlot, Phase, PlayerView, ResultRow, ServerMsg,
};
use crate::course::Course;
use crate::hub::Hub;
use crate::limits::Bucket;
use crate::maps::{self, Ruleset};
use crate::validate::{self, Rules};

/// How long a seat is held for a player whose socket dropped.
///
/// Long enough to survive a lift change or a Wi-Fi handover, short enough that
/// a room is not held up by somebody who has closed the game. Their car is
/// frozen where it was and their place is kept.
const RECONNECT_GRACE: Duration = Duration::from_secs(25);

/// What a connection sends to a room.
pub enum RoomMsg {
    Join(Box<JoinRequest>),
    /// The socket for `slot` has gone. The seat may be held; see the grace.
    Dropped { slot: u8, session: u64 },
    /// A validated-on-arrival binary state packet.
    State { slot: u8, session: u64, car: CarState },
    /// A lobby message.
    Control { slot: u8, session: u64, msg: Box<ClientMsg> },
    /// The client answered a liveness probe; this is the round trip.
    Rtt { slot: u8, rtt_ms: u16 },
    /// The hub is shutting down.
    Close,
}

/// Everything one connection needs to be handed a seat.
pub struct JoinRequest {
    pub session: u64,
    pub name: String,
    pub device: String,
    pub link: PlayerLink,
    pub reply: tokio::sync::oneshot::Sender<Result<u8, &'static str>>,
}

/// The two ways the room can reach a connection.
#[derive(Clone, Debug)]
pub struct PlayerLink {
    /// Reliable, ordered, bounded. Losing one of these loses meaning, so a
    /// full channel closes the connection rather than dropping the message.
    pub ctrl: mpsc::Sender<Outbound>,
    /// Latest-wins. See the note at the top of the file.
    pub snap: watch::Sender<Arc<Vec<u8>>>,
}

#[derive(Debug, Clone)]
pub enum Outbound {
    Text(String),
    Binary(Arc<Vec<u8>>),
    /// Say this and then hang up.
    Bye(String),
}

/// What the hub can see about a room without asking it.
///
/// Matchmaking reads this on every `quick` request, and asking each room over
/// its channel would mean the hub awaiting four replies to answer one join.
/// Three atomics cost nothing and are always at most one tick stale, which for
/// "does this room have space" is exact enough - the room re-checks when the
/// join actually arrives.
#[derive(Debug)]
pub struct RoomSummary {
    pub players: AtomicU8,
    pub phase: AtomicU8,
    pub map: AtomicU8,
    pub ruleset: AtomicU8,
    pub public: bool,
    pub max_players: u8,
}

impl RoomSummary {
    pub fn ruleset(&self) -> Ruleset {
        match self.ruleset.load(Ordering::Relaxed) {
            1 => Ruleset::Rebuilt,
            _ => Ruleset::Stock,
        }
    }

    pub fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Relaxed) {
            1 => Phase::Countdown,
            2 => Phase::Racing,
            3 => Phase::Results,
            _ => Phase::Lobby,
        }
    }

    /// Can somebody walk into this room right now?
    ///
    /// Only from the lobby. Dropping a fifth-of-a-second-late car onto a grid
    /// that has already left is worse for everybody than a short wait.
    pub fn joinable(&self) -> bool {
        self.players.load(Ordering::Relaxed) < self.max_players
            && matches!(self.phase(), Phase::Lobby | Phase::Results)
    }
}

fn phase_code(p: Phase) -> u8 {
    match p {
        Phase::Lobby => 0,
        Phase::Countdown => 1,
        Phase::Racing => 2,
        Phase::Results => 3,
    }
}

/// One seat.
struct Player {
    session: u64,
    name: String,
    device: String,
    /// `None` while the player is reconnecting.
    link: Option<PlayerLink>,
    dropped_at: Option<Instant>,
    ready: bool,
    rtt_ms: u16,
    /// Everything the validator knows about this car.
    track: validate::Track,
    /// Metered separately from the connection's own buckets, because the room
    /// is where the cost actually lands.
    chat: Bucket,
    place: u8,
    /// Set once they are out: kicked, or too many strikes.
    removed: bool,
}

impl Player {
    fn view(&self, host: u8, map: &maps::Map) -> PlayerView {
        PlayerView {
            slot: 0, // filled by the caller, which knows the index
            name: self.name.clone(),
            ready: self.ready,
            ping: self.rtt_ms,
            place: self.place,
            progress: self.track.progress(map),
            finish_ms: self.track.finished_ms,
            connected: self.link.is_some(),
            host: false,
        }
        .with_host(host)
    }
}

impl PlayerView {
    fn with_host(mut self, _host: u8) -> PlayerView {
        self.host = false;
        self
    }
}

/// The room itself. Owned by one task; nothing else ever sees it.
pub struct Room {
    pub code: String,
    hub: Arc<Hub>,
    config: Arc<Config>,
    course: Arc<Course>,
    summary: Arc<RoomSummary>,

    players: [Option<Player>; MAX_PLAYERS],
    host: u8,
    map: u8,
    ruleset: Ruleset,
    public: bool,
    max_players: u8,

    phase: Phase,
    /// THE clock. Not the room's own: every timestamp that crosses the wire -
    /// a snapshot, a countdown, a finish - is milliseconds since the process
    /// started, and so is the answer to the clock handshake in `ws.rs`.
    ///
    /// They used to be two different epochs with the same name, which is a
    /// mistake that cannot be seen by reading either side: the client syncs
    /// against one and interpolates against the other, so every remote car is
    /// placed however long ago the room happened to open. A `u32` of
    /// milliseconds since boot wraps after forty-nine days, and a process that
    /// has been up that long has larger problems than a wrapped counter.
    epoch: Instant,
    /// When the countdown ends and the lights go out.
    start_at: Option<Instant>,
    /// When the race actually started, for the finish times.
    started_at: Option<Instant>,
    /// When the first car crossed the line, for the grace period.
    first_finish: Option<Instant>,
    /// When the results board goes away.
    results_until: Option<Instant>,
    /// When the room became empty, for the teardown grace.
    empty_since: Option<Instant>,

    /// Rotated between races so the inside of the grid is not always the same
    /// player's.
    grid_offset: u8,

    /// One encode per tick for the whole room, not one per player.
    snap_buf: Vec<u8>,
    races_run: u32,
}

impl Room {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        code: String,
        hub: Arc<Hub>,
        config: Arc<Config>,
        course: Arc<Course>,
        summary: Arc<RoomSummary>,
        map: u8,
        ruleset: Ruleset,
        public: bool,
        max_players: u8,
    ) -> Room {
        let hub_epoch = hub.started;
        Room {
            code,
            hub,
            config,
            course,
            summary,
            players: [const { None }; MAX_PLAYERS],
            host: 0,
            map,
            ruleset,
            public,
            max_players,
            phase: Phase::Lobby,
            epoch: hub_epoch,
            start_at: None,
            started_at: None,
            first_finish: None,
            results_until: None,
            empty_since: Some(Instant::now()),
            grid_offset: 0,
            snap_buf: vec![0u8; synx_net::MAX_SERVER_FRAME],
            races_run: 0,
        }
    }

    /// Milliseconds since the room opened.
    fn now_ms(&self) -> u32 {
        self.epoch.elapsed().as_millis() as u32
    }

    fn map(&self) -> &'static maps::Map {
        maps::map(self.map).unwrap_or(&maps::MAPS[0])
    }

    fn occupied(&self) -> u8 {
        self.players.iter().filter(|p| p.is_some()).count() as u8
    }

    fn connected(&self) -> u8 {
        self.players.iter().filter(|p| p.as_ref().is_some_and(|q| q.link.is_some())).count() as u8
    }

    // ------------------------------------------------------------ the loop --

    /// Run until the room is empty and its grace has run out.
    ///
    /// # The deadline is checked at the top, not raced against
    ///
    /// The obvious loop is `select!` between the inbox and a sleep. It is also
    /// wrong in a way that only shows up under load, and it cost a race that
    /// never started to find: four cars at thirty hertz is a hundred and
    /// twenty messages a second arriving at a channel that is therefore almost
    /// never empty, so a biased select takes the inbox every time and the
    /// timer branch is polled only in the gaps. Worse, advancing the deadline
    /// once per LOOP rather than once per TICK pushes it further into the
    /// future with every message handled - after a second of traffic the next
    /// tick is scheduled three seconds out, and the countdown never ends.
    ///
    /// So the deadline is not something the loop races against, it is
    /// something the loop checks. However much traffic arrives, a tick happens
    /// the moment one is due, and the sleep exists only to stop a quiet room
    /// spinning.
    pub async fn run(mut self, mut rx: mpsc::Receiver<RoomMsg>) {
        info!(room = %self.code, map = self.map().name, ruleset = self.ruleset.label(), "room opened");
        let mut next = Instant::now() + self.tick_period();
        loop {
            let now = Instant::now();
            if now >= next {
                let period = self.tick_period();
                // Rebased from now rather than accumulated from the last
                // deadline: a task descheduled for half a second on a tenth of
                // a CPU should resume at the current rate, not burst through
                // ten ticks catching up.
                next = now + period;
                if self.tick() {
                    break;
                }
                continue;
            }
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(next.into()) => {}
                msg = rx.recv() => match msg {
                    Some(RoomMsg::Close) | None => break,
                    Some(m) => self.handle(m),
                },
            }
        }
        // Whatever is left gets told, so a client is never staring at a lobby
        // that no longer exists.
        for i in 0..MAX_PLAYERS {
            self.say_to(i as u8, ServerMsg::Bye {
                code: "room-closed",
                message: "the room closed".into(),
            });
        }
        info!(room = %self.code, races = self.races_run, "room closed");
    }

    /// How often this room needs to think.
    ///
    /// A racing room is the snapshot rate. A lobby is four hertz, because
    /// nothing in a lobby happens on a frame boundary and two dozen idle rooms
    /// ticking twenty times a second is real work for no reason.
    fn tick_period(&self) -> Duration {
        let hz = match self.phase {
            Phase::Racing | Phase::Countdown => self.config.snapshot_hz,
            _ => self.config.lobby_hz,
        };
        Duration::from_secs_f64(1.0 / hz as f64)
    }

    fn handle(&mut self, msg: RoomMsg) {
        match msg {
            RoomMsg::Join(req) => self.on_join(*req),
            RoomMsg::Dropped { slot, session } => self.on_dropped(slot, session),
            RoomMsg::State { slot, session, car } => self.on_state(slot, session, car),
            RoomMsg::Control { slot, session, msg } => self.on_control(slot, session, *msg),
            RoomMsg::Rtt { slot, rtt_ms } => {
                if let Some(p) = self.player_mut(slot) {
                    p.rtt_ms = rtt_ms;
                }
            }
            RoomMsg::Close => {}
        }
    }

    fn player(&self, slot: u8) -> Option<&Player> {
        self.players.get(slot as usize).and_then(|p| p.as_ref())
    }

    fn player_mut(&mut self, slot: u8) -> Option<&mut Player> {
        self.players.get_mut(slot as usize).and_then(|p| p.as_mut())
    }

    /// The seat a session already holds, if any. This is what makes a
    /// reconnection a reconnection rather than a second player.
    fn seat_of(&self, session: u64) -> Option<u8> {
        self.players
            .iter()
            .position(|p| p.as_ref().is_some_and(|q| q.session == session))
            .map(|i| i as u8)
    }

    // ------------------------------------------------------------- joining --

    fn on_join(&mut self, req: JoinRequest) {
        // A session that already has a seat is coming back to it, whatever the
        // phase - that is the whole point of holding the seat.
        if let Some(slot) = self.seat_of(req.session) {
            let name = req.name.clone();
            if let Some(p) = self.player_mut(slot) {
                p.link = Some(req.link);
                p.dropped_at = None;
                p.name = name;
            }
            let _ = req.reply.send(Ok(slot));
            info!(room = %self.code, slot, session = req.session, "player reconnected");
            self.notice("rejoined", format!("{} is back", self.player(slot).unwrap().name));
            self.broadcast_room();
            return;
        }

        if !matches!(self.phase, Phase::Lobby | Phase::Results) {
            let _ = req.reply.send(Err("that race has already started"));
            return;
        }
        let Some(slot) = self.free_slot() else {
            let _ = req.reply.send(Err("that room is full"));
            return;
        };

        let was_empty = self.occupied() == 0;
        self.players[slot as usize] = Some(Player {
            session: req.session,
            name: req.name.clone(),
            device: req.device.clone(),
            link: Some(req.link),
            dropped_at: None,
            ready: false,
            rtt_ms: 0,
            track: validate::Track::new(),
            chat: Bucket::new(self.config.chat_rate, 3.0),
            place: 0,
            removed: false,
        });
        if was_empty {
            self.host = slot;
        }
        self.empty_since = None;
        let _ = req.reply.send(Ok(slot));
        info!(
            room = %self.code,
            slot,
            name = %req.name,
            device = %req.device,
            players = self.occupied(),
            "player joined"
        );
        self.notice("joined", format!("{} joined", req.name));
        self.broadcast_room();
    }

    fn free_slot(&self) -> Option<u8> {
        (0..self.max_players).find(|i| self.players[*i as usize].is_none())
    }

    fn on_dropped(&mut self, slot: u8, session: u64) {
        let Some(p) = self.player_mut(slot) else { return };
        if p.session != session {
            // A stale message from a socket whose seat has already been reused.
            return;
        }
        p.link = None;
        p.dropped_at = Some(Instant::now());
        p.ready = false;
        let name = p.name.clone();
        // In a lobby there is nothing to hold a seat for, so the player simply
        // leaves. Mid-race the seat is kept: their car freezes where it is and
        // their place is defended until the grace runs out.
        if matches!(self.phase, Phase::Lobby | Phase::Results) {
            self.release(slot, "left");
        } else {
            info!(room = %self.code, slot, %name, "connection lost; holding the seat");
            self.notice("dropped", format!("{name} lost connection"));
            self.broadcast_room();
        }
    }

    /// Empty a seat for good.
    fn release(&mut self, slot: u8, why: &'static str) {
        let Some(p) = self.players[slot as usize].take() else { return };
        info!(room = %self.code, slot, name = %p.name, why, players = self.occupied(), "seat released");
        self.notice("left", format!("{} left", p.name));
        if self.occupied() == 0 {
            self.empty_since = Some(Instant::now());
            // Nobody left to race. Whatever was happening, is not.
            if self.phase != Phase::Lobby {
                self.to_lobby();
            }
        } else if self.host == slot {
            // The host seat moves to whoever has been here longest, which with
            // a fixed slot table is simply the lowest occupied index.
            if let Some(next) = (0..self.max_players).find(|i| self.players[*i as usize].is_some()) {
                self.host = next;
                let name = self.player(next).map(|p| p.name.clone()).unwrap_or_default();
                info!(room = %self.code, slot = next, %name, "host moved");
                self.notice("host", format!("{name} is now the host"));
            }
        }
        self.broadcast_room();
    }

    // ------------------------------------------------------------- the hot --

    fn on_state(&mut self, slot: u8, session: u64, car: CarState) {
        let (map, course, ruleset, now_ms, live) =
            (self.map(), self.course.clone(), self.ruleset, self.now_ms(), self.phase == Phase::Racing);
        let strikes_budget = self.config.correction_strikes;

        let Some(p) = self.player_mut(slot) else { return };
        if p.session != session || p.removed {
            return;
        }
        if !p.track.started {
            // A state before the grid has been set: the race has not been
            // built yet, so there is nothing to validate against.
            return;
        }
        let rules = Rules { map, course: &course, ruleset, now_ms, live };
        let verdict = validate::check(&mut p.track, &rules, &car);
        match verdict.rejected() {
            None => {
                self.hub.stats.states_accepted.fetch_add(1, Ordering::Relaxed);
            }
            Some(why) => {
                let state = p.track.last;
                let strikes = p.track.strikes;
                let name = p.name.clone();
                self.send_correction(slot, why, &state);
                // Loud, and rate-limited by being every eighth: an honest
                // player on a bad link produces a trickle, and a modified one
                // produces a flood that would otherwise be the log.
                if strikes % 8 == 1 {
                    warn!(
                        room = %self.code,
                        slot,
                        %name,
                        ?why,
                        strikes,
                        "state refused"
                    );
                }
                self.hub.stats.states_refused.fetch_add(1, Ordering::Relaxed);
                if strikes >= strikes_budget {
                    // The session carries this across rooms, so leaving and
                    // rejoining does not launder a strike count; a session that
                    // does it three races running loses its device with it.
                    let (session, device) = self
                        .player(slot)
                        .map(|p| (p.session, p.device.clone()))
                        .unwrap_or_default();
                    let out = {
                        let mut reg = self.hub.sessions.lock().unwrap();
                        reg.strike(session, strikes, strikes_budget * 3)
                    };
                    warn!(
                        room = %self.code,
                        slot,
                        %name,
                        %device,
                        strikes,
                        session_removed = out,
                        "removed for repeated refusals"
                    );
                    self.remove(slot, "too many impossible positions");
                }
            }
        }
    }

    fn send_correction(&mut self, slot: u8, why: Correction, state: &CarState) {
        let mut buf = [0u8; 64];
        let Ok(n) = synx_net::msg::write_correction(&mut buf, why as u8, state) else { return };
        let frame = Arc::new(buf[..n].to_vec());
        if let Some(p) = self.player(slot) {
            if let Some(link) = &p.link {
                // A correction is not state: it must not be dropped, so it
                // goes on the reliable channel. A client whose control channel
                // is full is not keeping up with anything and is closed by the
                // sender below.
                let _ = link.ctrl.try_send(Outbound::Binary(frame));
            }
        }
    }

    fn remove(&mut self, slot: u8, why: &'static str) {
        if let Some(p) = self.player_mut(slot) {
            p.removed = true;
        }
        self.say_to(slot, ServerMsg::Bye { code: "removed", message: why.into() });
        let name = self.player(slot).map(|p| p.name.clone()).unwrap_or_default();
        self.notice("removed", format!("{name} was removed: {why}"));
        self.release(slot, "removed");
    }

    // ------------------------------------------------------------- control --

    fn on_control(&mut self, slot: u8, session: u64, msg: ClientMsg) {
        if self.player(slot).map(|p| p.session) != Some(session) {
            return;
        }
        let is_host = slot == self.host;
        match msg {
            ClientMsg::Ready { on } => {
                if self.phase != Phase::Lobby {
                    return;
                }
                if let Some(p) = self.player_mut(slot) {
                    if p.ready == on {
                        return;
                    }
                    p.ready = on;
                }
                self.broadcast_room();
            }
            ClientMsg::Map { map } => {
                if !is_host {
                    return self.err(slot, "not-host", "only the host can change the route");
                }
                if self.phase != Phase::Lobby {
                    return self.err(slot, "racing", "the route cannot change mid-race");
                }
                if maps::map(map).is_none() {
                    return self.err(slot, "bad-map", "there is no such route");
                }
                if self.map == map {
                    return;
                }
                self.map = map;
                self.summary.map.store(map, Ordering::Relaxed);
                // A change of route invalidates everybody's decision to race it.
                self.clear_ready();
                info!(room = %self.code, map = self.map().name, "route changed");
                self.notice("map", format!("route: {}", self.map().name));
                self.broadcast_room();
            }
            ClientMsg::Ruleset { ruleset } => {
                if !is_host {
                    return self.err(slot, "not-host", "only the host can change the car");
                }
                if self.phase != Phase::Lobby {
                    return self.err(slot, "racing", "the car cannot change mid-race");
                }
                let Some(r) = Ruleset::from_str(&ruleset) else {
                    return self.err(slot, "bad-ruleset", "there is no such car");
                };
                if self.ruleset == r {
                    return;
                }
                self.ruleset = r;
                self.summary.ruleset.store(r as u8, Ordering::Relaxed);
                self.clear_ready();
                info!(room = %self.code, ruleset = r.label(), "car changed");
                self.notice("ruleset", format!("car: {}", r.label()));
                self.broadcast_room();
            }
            ClientMsg::Start {} => {
                if !is_host {
                    return self.err(slot, "not-host", "only the host can start the race");
                }
                self.try_start(slot);
            }
            ClientMsg::Kick { slot: target } => {
                if !is_host {
                    return self.err(slot, "not-host", "only the host can remove a player");
                }
                if target == slot || self.player(target).is_none() {
                    return;
                }
                let name = self.player(target).map(|p| p.name.clone()).unwrap_or_default();
                info!(room = %self.code, target, %name, "kicked by the host");
                self.say_to(target, ServerMsg::Bye {
                    code: "kicked",
                    message: "the host removed you from the room".into(),
                });
                self.release(target, "kicked");
            }
            ClientMsg::Chat { text } => {
                let Some(text) = clean_chat(&text) else { return };
                let allowed = self.player_mut(slot).map(|p| p.chat.take()).unwrap_or(false);
                if !allowed {
                    return self.err(slot, "slow-down", "one line at a time");
                }
                let name = self.player(slot).map(|p| p.name.clone()).unwrap_or_default();
                debug!(room = %self.code, slot, %name, %text, "chat");
                self.broadcast(ServerMsg::Chat { slot, name, text });
            }
            // Everything else is the hub's business, not the room's, and the
            // connection handles it before it reaches here.
            _ => {}
        }
    }

    fn clear_ready(&mut self) {
        for p in self.players.iter_mut().flatten() {
            p.ready = false;
        }
    }

    fn try_start(&mut self, by: u8) {
        if self.phase != Phase::Lobby {
            return self.err(by, "already", "a race is already under way");
        }
        let live = self.connected();
        if live < 2 {
            return self.err(by, "alone", "a race needs at least two cars");
        }
        let unready: Vec<String> = self
            .players
            .iter()
            .flatten()
            .filter(|p| p.link.is_some() && !p.ready)
            .map(|p| p.name.clone())
            .collect();
        // The host is allowed not to have pressed READY - pressing START is
        // the same statement - so they are excused here rather than being made
        // to say it twice.
        let host_name = self.player(self.host).map(|p| p.name.clone()).unwrap_or_default();
        let waiting: Vec<String> = unready.into_iter().filter(|n| *n != host_name).collect();
        if !waiting.is_empty() {
            return self.err(by, "not-ready", &format!("waiting for {}", waiting.join(", ")));
        }
        self.begin_countdown();
    }

    // --------------------------------------------------------- the director --

    fn begin_countdown(&mut self) {
        let map = self.map();
        let now = self.now_ms();
        let of = self.connected();
        // Put every car on the grid, through the validator, so the position it
        // will be checked against tomorrow is the position it was given today.
        let mut grid = Vec::with_capacity(MAX_PLAYERS);
        let offset = self.grid_offset;
        let mut n = 0u8;
        for i in 0..MAX_PLAYERS {
            let Some(p) = self.players[i].as_mut() else { continue };
            p.place = 0;
            if p.link.is_none() {
                // A player who is mid-reconnect still gets a seat on the grid;
                // if they come back before the lights they are simply racing.
            }
            let seat = (n + offset) % self.max_players.max(1);
            p.track.place(map, &self.course, seat, of, now);
            grid.push(GridSlot { slot: i as u8, s: p.track.last.s, lateral: p.track.last.lateral });
            n += 1;
        }
        self.grid_offset = (self.grid_offset + 1) % self.max_players.max(1);

        self.phase = Phase::Countdown;
        self.hub.stats.races_started.fetch_add(1, Ordering::Relaxed);
        self.start_at = Some(Instant::now() + self.config.countdown);
        self.started_at = None;
        self.first_finish = None;
        self.results_until = None;
        self.summary.phase.store(phase_code(self.phase), Ordering::Relaxed);

        let start_at_ms = now + self.config.countdown.as_millis() as u32;
        info!(
            room = %self.code,
            map = map.name,
            km = map.km(),
            ruleset = self.ruleset.label(),
            cars = of,
            countdown_ms = self.config.countdown.as_millis(),
            "race starting"
        );
        self.broadcast(ServerMsg::Countdown {
            start_at_ms,
            map: self.map,
            ruleset: self.ruleset.label(),
            grid,
        });
        self.broadcast_room();
    }

    fn go(&mut self) {
        self.phase = Phase::Racing;
        self.started_at = Some(Instant::now());
        self.summary.phase.store(phase_code(self.phase), Ordering::Relaxed);
        info!(room = %self.code, map = self.map().name, "lights out");
        self.broadcast_room();
    }

    fn to_lobby(&mut self) {
        self.phase = Phase::Lobby;
        self.start_at = None;
        self.started_at = None;
        self.first_finish = None;
        self.results_until = None;
        self.clear_ready();
        for p in self.players.iter_mut().flatten() {
            p.place = 0;
            p.track = validate::Track::new();
        }
        self.summary.phase.store(phase_code(self.phase), Ordering::Relaxed);
        self.broadcast_room();
    }

    fn finish_race(&mut self, why: &'static str) {
        let map = self.map();
        let mut rows: Vec<ResultRow> = Vec::with_capacity(MAX_PLAYERS);
        for i in 0..MAX_PLAYERS {
            let Some(p) = self.players[i].as_ref() else { continue };
            rows.push(ResultRow {
                slot: i as u8,
                name: p.name.clone(),
                place: 0,
                time_ms: p.track.finished_ms,
                progress: p.track.progress(map),
                dnf: p.track.finished_ms.is_none(),
                corrections: p.track.strikes,
            });
        }
        // Finishers first, by time; then everybody else by how far they got.
        rows.sort_by(|a, b| match (a.time_ms, b.time_ms) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => b.progress.total_cmp(&a.progress),
        });
        for (i, r) in rows.iter_mut().enumerate() {
            r.place = i as u8 + 1;
        }
        for r in &rows {
            if let Some(p) = self.player_mut(r.slot) {
                p.place = r.place;
            }
        }

        let start_ms = self.started_at.map(|t| (t - self.epoch).as_millis() as u32).unwrap_or(0);
        info!(
            room = %self.code,
            map = map.name,
            why,
            results = ?rows.iter().map(|r| (r.place, r.name.as_str(), r.time_ms.map(|t| t.saturating_sub(start_ms)))).collect::<Vec<_>>(),
            "race over"
        );

        // Times reported relative to the lights, not to the room clock.
        let rows: Vec<ResultRow> = rows
            .into_iter()
            .map(|mut r| {
                r.time_ms = r.time_ms.map(|t| t.saturating_sub(start_ms));
                r
            })
            .collect();

        self.races_run += 1;
        self.phase = Phase::Results;
        self.results_until = Some(Instant::now() + self.config.results_hold);
        self.summary.phase.store(phase_code(self.phase), Ordering::Relaxed);
        self.broadcast(ServerMsg::Results {
            rows,
            hold_ms: self.config.results_hold.as_millis() as u32,
            map: self.map,
        });
        self.broadcast_room();
    }

    /// One tick. Returns true when the room should close.
    fn tick(&mut self) -> bool {
        let now = Instant::now();

        // ---- seats held for players who have not come back ----------------
        let mut expired: Vec<u8> = Vec::new();
        for i in 0..MAX_PLAYERS {
            if let Some(p) = self.players[i].as_ref() {
                if let Some(at) = p.dropped_at {
                    if now.duration_since(at) > RECONNECT_GRACE {
                        expired.push(i as u8);
                    }
                }
            }
        }
        for slot in expired {
            self.release(slot, "did not reconnect");
        }

        // ---- an empty room is a room that should not exist -----------------
        if self.occupied() == 0 {
            if let Some(since) = self.empty_since {
                if now.duration_since(since) > self.config.empty_room_grace {
                    return true;
                }
            } else {
                self.empty_since = Some(now);
            }
            self.summary.players.store(0, Ordering::Relaxed);
            return false;
        }
        self.summary.players.store(self.occupied(), Ordering::Relaxed);

        match self.phase {
            Phase::Countdown => {
                if self.start_at.is_some_and(|t| now >= t) {
                    self.go();
                }
            }
            Phase::Racing => {
                self.update_places();
                let all_in = self
                    .players
                    .iter()
                    .flatten()
                    .all(|p| p.track.finished_ms.is_some() || p.link.is_none());
                if all_in {
                    self.finish_race("everybody is in");
                } else if self
                    .first_finish
                    .is_some_and(|t| now.duration_since(t) > self.config.finish_grace)
                {
                    self.finish_race("the grace period after the winner expired");
                } else if self
                    .started_at
                    .is_some_and(|t| now.duration_since(t) > self.config.race_timeout)
                {
                    self.finish_race("the race ran out of time");
                }
            }
            Phase::Results => {
                if self.results_until.is_some_and(|t| now >= t) {
                    self.to_lobby();
                }
            }
            Phase::Lobby => {}
        }

        if matches!(self.phase, Phase::Racing | Phase::Countdown) {
            self.broadcast_snapshot();
        }
        false
    }

    /// Standings: whoever has finished, in the order they finished; then
    /// everybody else by how far along the route they actually are.
    fn update_places(&mut self) {
        let map = self.map();
        let mut order: Vec<(u8, Option<u32>, f32)> = self
            .players
            .iter()
            .enumerate()
            .filter_map(|(i, p)| p.as_ref().map(|q| (i as u8, q.track.finished_ms, q.track.max_s)))
            .collect();
        order.sort_by(|a, b| match (a.1, b.1) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => b.2.total_cmp(&a.2),
        });
        for (place, (slot, finished, _)) in order.into_iter().enumerate() {
            if finished.is_some() && self.first_finish.is_none() {
                self.first_finish = Some(Instant::now());
                let name = self.player(slot).map(|p| p.name.clone()).unwrap_or_default();
                info!(
                    room = %self.code,
                    %name,
                    grace_s = self.config.finish_grace.as_secs(),
                    "first car across the line"
                );
            }
            if let Some(p) = self.player_mut(slot) {
                p.place = place as u8 + 1;
            }
        }
        let _ = map;
    }

    // ------------------------------------------------------------- sending --

    /// Assemble and publish one snapshot for the whole room.
    ///
    /// Encoded once. Four players would otherwise mean four encodes of the
    /// same bytes for nothing: the only per-player field is `place`, and that
    /// sits inside each entry rather than being addressed at a viewer. A
    /// client skips its own car by slot.
    fn broadcast_snapshot(&mut self) {
        let mut entries: [SnapshotEntry; MAX_PLAYERS] = Default::default();
        let mut n = 0usize;
        let live = self.phase == Phase::Racing;
        for i in 0..MAX_PLAYERS {
            let Some(p) = self.players[i].as_ref() else { continue };
            if !p.track.started {
                continue;
            }
            let mut car = p.track.last;
            // A car whose driver is not connected is explicitly idle, so the
            // receiving clients hold it still instead of dead-reckoning it off
            // into the scenery.
            if p.link.is_none() {
                car.flags |= flag::IDLE;
            }
            car.t_ms = self.now_ms();
            entries[n] = SnapshotEntry {
                slot: i as u8,
                place: p.place,
                rtt_ms: p.rtt_ms,
                car,
            };
            n += 1;
        }
        if n == 0 {
            return;
        }
        let mut flags = 0u8;
        if live {
            flags |= synx_net::msg::SNAP_LIVE;
        }
        if self.phase == Phase::Countdown {
            flags |= synx_net::msg::SNAP_COUNTDOWN;
        }
        let stamp = self.now_ms();
        let Ok(len) =
            synx_net::msg::write_snapshot(&mut self.snap_buf, stamp, flags, &entries[..n])
        else {
            return;
        };
        let frame = Arc::new(self.snap_buf[..len].to_vec());
        for p in self.players.iter().flatten() {
            if let Some(link) = &p.link {
                // Overwrite rather than queue. See the note at the top.
                let _ = link.snap.send(frame.clone());
            }
        }
    }

    fn room_message(&self, you: u8) -> ServerMsg {
        let map = self.map();
        let mut players = Vec::with_capacity(MAX_PLAYERS);
        for i in 0..MAX_PLAYERS {
            if let Some(p) = self.players[i].as_ref() {
                let mut v = p.view(self.host, map);
                v.slot = i as u8;
                v.host = i as u8 == self.host;
                players.push(v);
            }
        }
        ServerMsg::Room {
            code: self.code.clone(),
            map: self.map,
            ruleset: self.ruleset.label(),
            phase: self.phase,
            you,
            host: self.host,
            max_players: self.max_players,
            private: !self.public,
            players,
        }
    }

    /// The room, to everybody, with each copy addressed to its reader.
    pub fn broadcast_room(&mut self) {
        for i in 0..MAX_PLAYERS {
            if self.players[i].is_some() {
                let msg = self.room_message(i as u8);
                self.say_to(i as u8, msg);
            }
        }
    }

    fn broadcast(&mut self, msg: ServerMsg) {
        let Ok(text) = serde_json::to_string(&msg) else { return };
        for i in 0..MAX_PLAYERS {
            self.send_text(i as u8, text.clone());
        }
    }

    fn notice(&mut self, kind: &'static str, text: String) {
        self.broadcast(ServerMsg::Notice { kind, text });
    }

    fn err(&mut self, slot: u8, code: &'static str, message: &str) {
        self.say_to(slot, ServerMsg::Error { code, message: message.to_string() });
    }

    fn say_to(&mut self, slot: u8, msg: ServerMsg) {
        let Ok(text) = serde_json::to_string(&msg) else { return };
        // A farewell is the last thing this connection will ever be told, so it
        // goes out as one message that also closes the socket. Sending the text
        // and letting the teardown race the write is how a client ends up
        // disconnected with no reason on screen.
        if matches!(msg, ServerMsg::Bye { .. }) {
            if let Some(link) = self.player(slot).and_then(|p| p.link.as_ref()) {
                let _ = link.ctrl.try_send(Outbound::Bye(text));
            }
            return;
        }
        self.send_text(slot, text);
    }

    fn send_text(&mut self, slot: u8, text: String) {
        let Some(p) = self.player(slot) else { return };
        let Some(link) = &p.link else { return };
        if link.ctrl.try_send(Outbound::Text(text)).is_err() {
            // The reliable channel is full or closed. Full means the client is
            // not reading even the lobby, which is thirty-two messages behind:
            // there is nothing to be gained by waiting for it.
            let name = p.name.clone();
            warn!(room = %self.code, slot, %name, "control channel backed up; dropping the connection");
            if let Some(p) = self.player_mut(slot) {
                p.link = None;
                p.dropped_at = Some(Instant::now());
            }
        }
    }

}

/// Everything the welcome carries. Built here so the room and the connection
/// cannot disagree about what a client was told.
pub fn welcome(config: &Config, name: &str, session: &str, now_ms: u32) -> ServerMsg {
    ServerMsg::Welcome {
        protocol: synx_net::PROTOCOL_VERSION,
        name: name.to_string(),
        session: session.to_string(),
        snapshot_hz: config.snapshot_hz,
        send_hz: synx_net::CLIENT_SEND_HZ,
        server_time_ms: now_ms,
        max_players: MAX_PLAYERS as u8,
        maps: map_views(),
        build: crate::BUILD,
    }
}

/// The alphabet room codes are drawn from.
///
/// No `0`/`O`, no `1`/`I`/`L`: a code exists to be read off one screen and
/// typed into another, usually over a voice call, and every one of those pairs
/// is a support request waiting to happen.
pub const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

/// A six-character room code. Thirty-one to the sixth is about 887 million, so
/// a collision inside the two dozen rooms this server holds is not something
/// that needs handling beyond the retry the hub already does.
pub fn make_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..6).map(|_| CODE_ALPHABET[rng.gen_range(0..CODE_ALPHABET.len())] as char).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_codes_are_readable_and_unlikely_to_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..4_000 {
            let c = make_code();
            assert_eq!(c.len(), 6);
            for ch in c.chars() {
                assert!(CODE_ALPHABET.contains(&(ch as u8)), "{ch} is not in the alphabet");
                assert!(!"01OIL".contains(ch), "{ch} is ambiguous");
            }
            seen.insert(c);
        }
        // 4,000 draws from 887 million: a handful of collisions would be
        // extraordinary, and zero is the expected result
        assert!(seen.len() > 3_990, "only {} unique codes in 4000", seen.len());
    }

    #[test]
    fn a_summary_only_admits_people_between_races() {
        let s = RoomSummary {
            players: AtomicU8::new(2),
            phase: AtomicU8::new(phase_code(Phase::Lobby)),
            map: AtomicU8::new(0),
            ruleset: AtomicU8::new(0),
            public: true,
            max_players: 4,
        };
        assert!(s.joinable());
        s.phase.store(phase_code(Phase::Racing), Ordering::Relaxed);
        assert!(!s.joinable());
        s.phase.store(phase_code(Phase::Results), Ordering::Relaxed);
        assert!(s.joinable());
        s.players.store(4, Ordering::Relaxed);
        assert!(!s.joinable());
    }
}
