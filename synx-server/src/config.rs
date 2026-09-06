//! Server configuration.
//!
//! WHY THERE IS ALMOST NOTHING HERE TO SET.
//!
//! This server is meant to be cloned and run by anybody who wants their own
//! grid, which puts a hard requirement on this file: `git clone`, `cargo run`,
//! and you have a working server. Every variable that has to be set before
//! that works is a step somebody can get wrong, and every tuning knob that
//! nobody will ever turn is a decision the reader has to rule out while
//! looking for the two that matter.
//!
//! So there are two, and both exist because the environment genuinely differs
//! between deployments rather than because the value is arguable:
//!
//!   PORT                  the host picks it - Render, Fly and Railway all
//!                         assign one and expect the process to obey.
//!   SYNX_ALLOWED_ORIGINS  who may connect, if you serve the game from your
//!                         own domain rather than the desktop build.
//!
//! Everything else below is a constant. They were environment variables once,
//! and the tuning that produced these numbers is written beside each one so
//! that changing a value is an informed edit to a named constant rather than
//! an undocumented variable set in a dashboard nobody else can see.

use std::time::Duration;

use tracing::{info, warn};

/// Read an environment variable, or fall back, complaining about anything set
/// to something that will not parse rather than silently using the default.
fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    match std::env::var(key) {
        Err(_) => default,
        Ok(raw) => match raw.trim().parse::<T>() {
            Ok(v) => v,
            Err(_) => {
                warn!(key, value = %raw, "not parseable; using the default");
                default
            }
        },
    }
}

/// The origins a SYNX desktop build actually presents.
///
/// Tauri serves the bundled page from a custom scheme, and which one depends on
/// the platform: `tauri://localhost` on macOS and Linux, `http://tauri.localhost`
/// on Windows, where a custom scheme cannot be used for the main document. The
/// `https://` form covers Tauri builds configured to serve over it. The two
/// loopback entries are for running the game against `python -m http.server`
/// during development, which is how the harness drives it.
///
/// A native process can send whatever `Origin` it likes, so this list is not
/// what stops a hand-written client, and nothing here pretends otherwise. What
/// it does stop is any web PAGE, anywhere, quietly using this server as free
/// infrastructure: a browser sets that header itself and will not let a script
/// change it. That is a narrow guarantee, and it is a real one.
pub const DEFAULT_CLIENT_ORIGINS: &[&str] = &[
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "http://localhost",
    "http://127.0.0.1",
];

#[derive(Debug, Clone)]
pub struct Config {
    /// The port to listen on. The host sets `PORT`; there is no negotiating.
    pub port: u16,

    /// How often each room assembles and broadcasts a snapshot.
    pub snapshot_hz: u32,
    /// How often each room re-evaluates itself when nobody is racing. Nothing
    /// in a lobby happens on a frame boundary, and the difference between an
    /// idle room ticking twenty times a second and four is the difference
    /// between a dozen idle rooms being free and being the whole CPU budget.
    pub lobby_hz: u32,

    /// The most rooms that may exist at once, and the most connections.
    ///
    /// These are the two numbers that stand between the process and its
    /// memory limit. A room is about 4 kB; a connection with its buffers is
    /// about 64 kB. The defaults are deliberately well under what the memory
    /// would allow, because the ceiling that binds first is CPU: refusing one
    /// player is much better than serving two hundred of them badly.
    pub max_rooms: usize,
    pub max_connections: usize,
    /// The most simultaneous connections from one address.
    pub max_per_ip: usize,

    /// How long a session token is good for.
    pub session_ttl: Duration,
    /// How long a registered session may sit unused before it is forgotten.
    pub session_idle: Duration,
    /// The most sessions one address may register per minute.
    pub register_per_minute: u32,
    /// Leading zero bits the registration proof of work must produce. Each bit
    /// doubles the work; 16 is about 65k hashes, which is a few milliseconds
    /// in a browser and makes bulk registration expensive.
    pub pow_bits: u32,

    /// State messages a client may send per second before it is throttled.
    /// The client aims at `CLIENT_SEND_HZ`; the allowance is above that so
    /// ordinary jitter does not trip it.
    pub state_rate: f64,
    /// Lobby (JSON) messages per second.
    pub control_rate: f64,
    /// Chat lines per second.
    pub chat_rate: f64,

    /// How long a connection may go without answering a ping.
    pub client_timeout: Duration,
    /// How often the server probes a quiet connection.
    pub ping_every: Duration,
    /// How long one socket write may take before the peer is considered gone.
    pub write_timeout: Duration,

    /// How long the countdown runs once the host starts a race.
    pub countdown: Duration,
    /// How long the race is given after the first car finishes.
    pub finish_grace: Duration,
    /// How long the results board stays up before the room returns to its lobby.
    pub results_hold: Duration,
    /// The longest a single race may run before the room gives up on it.
    pub race_timeout: Duration,
    /// How long an empty room is kept before it is torn down.
    pub empty_room_grace: Duration,

    /// Corrections a player may collect in a race before they are removed.
    /// Honest packet loss produces one or two; a modified client produces one
    /// every packet.
    pub correction_strikes: u32,

    /// HTTP requests one address may make per second before it is throttled
    /// and then jailed. The game makes about six in a session; a browser tab
    /// left refreshing makes one a second.
    pub http_rate: f64,
    /// Connection attempts one address may make per second. Being at the
    /// concurrent cap is not abuse; opening sockets in a loop is.
    pub connect_rate: f64,
    /// New connections the whole process will accept per second, whoever they
    /// come from. The per-address cap stops one machine; this stops a
    /// thousand.
    pub accept_rate: f64,
    /// Requests the process will have in flight at once. Past this it sheds
    /// load with a 503 rather than queueing work it cannot do.
    pub max_inflight: usize,
    /// How long one request may take before it is abandoned.
    pub request_timeout: Duration,
    /// The longest a single WebSocket may stay open. A connection that has
    /// been up for hours is either a very long session or something holding a
    /// slot it is not using; both are better off reconnecting.
    pub max_socket: Duration,

    /// Which origins may speak to this server, comma separated.
    ///
    /// SYNX ships as a desktop application, so the origins that matter are the
    /// ones a Tauri webview presents - `tauri://localhost` on macOS and Linux,
    /// `http://tauri.localhost` on Windows - plus a local dev server. When
    /// `SYNX_ALLOWED_ORIGINS` is unset those defaults apply rather than "any",
    /// which is the whole point: a browser will not let a page on some other
    /// site forge its `Origin`, so this single check is what stops the server
    /// being quietly adopted as free infrastructure by a web client that is
    /// not this game.
    pub allowed_origins: Vec<String>,

    /// Secret the session tokens are signed with. Generated fresh every time
    /// the process starts, which is safe rather than merely convenient: a
    /// session never outlives the process, so a token that stops verifying
    /// after a restart names a session that no longer exists anyway. There is
    /// nothing to persist and therefore nothing to configure.
    pub token_secret: [u8; 32],
}

impl Config {
    pub fn from_env() -> Config {
        // Fresh every boot. See the note on the field: there is nothing worth
        // persisting here, so there is nothing to ask anybody to set.
        let mut token_secret = [0u8; 32];
        {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut token_secret);
        }

        Config {
            // The one value the host insists on choosing.
            port: env_or("PORT", 10_000u16),

            // TICK RATES. Twenty snapshots a second is the point past which
            // the interpolator on the client stops being able to tell the
            // difference, and every one above it costs bandwidth for nothing.
            // An idle lobby needs far less: four is enough to feel live.
            snapshot_hz: synx_net::SERVER_SNAPSHOT_HZ,
            lobby_hz: 4,

            // CAPACITY. The two numbers between this process and its memory
            // limit - a room is about 4 kB, a connection with its buffers
            // about 64 kB. Both are set well under what the memory allows,
            // because the ceiling that binds first is CPU: refusing one player
            // is much better than serving two hundred of them badly. Four per
            // address is a household, not a botnet.
            max_rooms: 24,
            max_connections: 96,
            max_per_ip: 4,

            // SESSIONS. Twelve hours is longer than anybody plays in one
            // sitting; half an hour idle is long enough to survive making tea.
            session_ttl: Duration::from_secs(43_200),
            session_idle: Duration::from_secs(1_800),
            register_per_minute: 12,
            // Sixteen bits is a few milliseconds of work for one honest player
            // and hours for somebody trying to register thousands of sessions.
            // That asymmetry is the entire point of the proof.
            pow_bits: 16,

            // WHAT ONE CLIENT MAY SEND. Comfortably above what the game
            // actually produces, so a burst after a stall is absorbed rather
            // than punished, and far below what a flood would need.
            state_rate: 45.0,
            control_rate: 6.0,
            chat_rate: 1.0,

            // LIVENESS. A probe every eight seconds and a twenty-five second
            // patience: long enough that a train tunnel is survivable, short
            // enough that a dead socket does not hold a seat for a minute.
            client_timeout: Duration::from_secs(25),
            ping_every: Duration::from_secs(8),
            write_timeout: Duration::from_secs(10),

            // RACE TIMING. Five seconds of lights; seventy-five seconds after
            // the winner for everybody else to finish; twenty seconds on the
            // results board; twenty-five minutes before a race is presumed
            // abandoned.
            countdown: Duration::from_millis(5_000),
            finish_grace: Duration::from_secs(75),
            results_hold: Duration::from_secs(20),
            race_timeout: Duration::from_secs(1_500),
            empty_room_grace: Duration::from_secs(20),

            // ANTI-CHEAT. Forty corrections is a great many for a bad
            // connection and very few for a modified client.
            correction_strikes: 40,

            // OVERLOAD PROTECTION. Everything here is per address.
            http_rate: 8.0,
            connect_rate: 1.0,
            accept_rate: 20.0,
            max_inflight: 64,
            request_timeout: Duration::from_secs(15),
            max_socket: Duration::from_secs(10_800),

            // The one genuine deployment difference: if you serve the web
            // build from your own domain, that domain has to be named here.
            allowed_origins: {
                let configured: Vec<String> = std::env::var("SYNX_ALLOWED_ORIGINS")
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if configured.is_empty() {
                    DEFAULT_CLIENT_ORIGINS.iter().map(|s| s.to_string()).collect()
                } else {
                    configured
                }
            },

            token_secret,
        }
    }

    /// One line per setting, at boot, so that what the process is actually
    /// doing can be read off the log rather than inferred from this file.
    pub fn log(&self) {
        info!("---- configuration ----------------------------------------");
        info!(port = self.port, "listen");
        info!(snapshot_hz = self.snapshot_hz, lobby_hz = self.lobby_hz, "tick rates");
        info!(
            max_rooms = self.max_rooms,
            max_connections = self.max_connections,
            max_per_ip = self.max_per_ip,
            "capacity"
        );
        info!(
            ttl_s = self.session_ttl.as_secs(),
            idle_s = self.session_idle.as_secs(),
            register_per_minute = self.register_per_minute,
            pow_bits = self.pow_bits,
            "sessions"
        );
        info!(
            state_hz = self.state_rate,
            control_hz = self.control_rate,
            chat_hz = self.chat_rate,
            "client rate limits"
        );
        info!(
            client_timeout_s = self.client_timeout.as_secs(),
            ping_every_s = self.ping_every.as_secs(),
            write_timeout_s = self.write_timeout.as_secs(),
            "liveness"
        );
        info!(
            countdown_ms = self.countdown.as_millis(),
            finish_grace_s = self.finish_grace.as_secs(),
            results_hold_s = self.results_hold.as_secs(),
            race_timeout_s = self.race_timeout.as_secs(),
            "race timing"
        );
        info!(strikes = self.correction_strikes, "anti-cheat");
        info!(
            http_per_second = self.http_rate,
            connects_per_second = self.connect_rate,
            accepts_per_second = self.accept_rate,
            max_inflight = self.max_inflight,
            request_timeout_s = self.request_timeout.as_secs(),
            max_socket_s = self.max_socket.as_secs(),
            "overload protection"
        );
        if self.allowed_origins.is_empty() {
            warn!("origins: ANY - this server will answer a client on any site");
        } else {
            info!(origins = ?self.allowed_origins, "origins");
        }
        info!("-----------------------------------------------------------");
    }
}
