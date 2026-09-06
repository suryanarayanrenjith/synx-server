//! Environment-backed server configuration and defaults.

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
/// A native process can of course send whatever `Origin` it likes, so this list
/// is not what stops a hand-written client - that is what attestation is for.
/// What it does stop is any web page, anywhere, using this server: the browser
/// sets that header itself and will not let a script change it.
pub const DEFAULT_CLIENT_ORIGINS: &[&str] = &[
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
    "http://localhost",
    "http://127.0.0.1",
];

/// Parse `major.minor.patch`, ignoring anything before the first digit so that
/// both "1.2.3" and "synx 1.2.3" are read the same way.
///
/// A version that will not parse is treated as absent rather than as zero: a
/// floor nobody can satisfy would lock every client out, and a floor of zero
/// would silently admit everything. Neither is a good failure, so an
/// unparseable one simply is not a floor.
pub fn parse_version(raw: &str) -> Option<(u32, u32, u32)> {
    let digits = raw.trim_start_matches(|c: char| !c.is_ascii_digit());
    let mut it = digits.split('.');
    let major = it.next()?.trim().parse().ok()?;
    let minor = it.next().unwrap_or("0").trim().parse().unwrap_or(0);
    // The patch field is where a suffix like "1.0.0-beta" turns up, so it is
    // read up to the first character that is not a digit.
    let patch = it
        .next()
        .unwrap_or("0")
        .trim()
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    Some((major, minor, patch))
}

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

    /// The secrets a client may sign its handshake with. Comma separated in
    /// `SYNX_CLIENT_SECRET`; a client is admitted if it matches ANY of them.
    ///
    /// A LIST RATHER THAN ONE VALUE, because the client is a public download
    /// and the alternative is a trap. With a single secret, changing it here
    /// instantly breaks every copy anyone has already installed - there is no
    /// window in which both the old build and the new one work, so rotating
    /// the key and shipping the update can never be two separate decisions.
    ///
    /// With a list they are. Add the new secret beside the old one, ship the
    /// build that uses it, wait as long as you like, then drop the old entry.
    /// Dropping it is what retires the builds that carry it - deliberately,
    /// at a moment you choose, rather than the instant you edit a variable.
    ///
    /// Empty means attestation is skipped, and the fact is logged loudly at
    /// boot: a server that believes it is locked down and is not is worse than
    /// one that never claimed to be.
    pub client_secrets: Vec<Vec<u8>>,

    /// The oldest client build this server will admit, from `SYNX_MIN_CLIENT`
    /// as `major.minor.patch`.
    ///
    /// The build string travels INSIDE the attestation signature, so an
    /// attested client cannot claim to be newer than it is. That makes this
    /// the one lever that retires a compromised or broken release without
    /// waiting for anybody to update anything: raise the floor, and the old
    /// builds are told to update the next time they connect.
    pub min_client: Option<(u32, u32, u32)>,

    /// Whether a client that fails the origin or attestation check is refused
    /// or merely logged.
    ///
    /// Strict is the default and the intended posture. The permissive setting
    /// exists for the afternoon when a deployment is being moved and locking
    /// yourself out of your own server is a real risk; it is not a setting to
    /// leave on.
    pub strict_client: bool,

    /// Secret the session tokens are signed with. Generated per process when
    /// unset, which is safe: a session does not outlive the process either
    /// way, so a token that stops verifying after a restart names a session
    /// that no longer exists.
    pub token_secret: [u8; 32],
    /// Whether the secret was generated rather than supplied, for the boot log.
    pub token_secret_generated: bool,
}

impl Config {
    pub fn from_env() -> Config {
        let secret_env = std::env::var("SYNX_TOKEN_SECRET").ok().filter(|s| s.len() >= 16);
        let mut secret = [0u8; 32];
        let generated = match &secret_env {
            Some(s) => {
                // Stretched rather than truncated, so a short but high-entropy
                // secret is not silently cut down to its first 32 bytes.
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"synx-session-v1");
                h.update(s.as_bytes());
                secret.copy_from_slice(&h.finalize());
                false
            }
            None => {
                use rand::RngCore;
                rand::thread_rng().fill_bytes(&mut secret);
                true
            }
        };

        Config {
            port: env_or("PORT", 10_000u16),
            snapshot_hz: env_or::<u32>("SYNX_SNAPSHOT_HZ", synx_net::SERVER_SNAPSHOT_HZ).clamp(5, 30),
            lobby_hz: env_or::<u32>("SYNX_LOBBY_HZ", 4).clamp(1, 10),
            max_rooms: env_or::<usize>("SYNX_MAX_ROOMS", 24).clamp(1, 512),
            max_connections: env_or::<usize>("SYNX_MAX_CONNECTIONS", 96).clamp(2, 4096),
            max_per_ip: env_or::<usize>("SYNX_MAX_PER_IP", 4).clamp(1, 64),
            session_ttl: Duration::from_secs(env_or::<u64>("SYNX_SESSION_TTL", 43_200).clamp(300, 604_800)),
            session_idle: Duration::from_secs(env_or::<u64>("SYNX_SESSION_IDLE", 1_800).clamp(60, 86_400)),
            register_per_minute: env_or::<u32>("SYNX_REGISTER_PER_MINUTE", 12).clamp(1, 600),
            pow_bits: env_or::<u32>("SYNX_POW_BITS", 16).clamp(0, 26),
            state_rate: env_or::<f64>("SYNX_STATE_RATE", 45.0).clamp(5.0, 200.0),
            control_rate: env_or::<f64>("SYNX_CONTROL_RATE", 6.0).clamp(1.0, 60.0),
            chat_rate: env_or::<f64>("SYNX_CHAT_RATE", 1.0).clamp(0.1, 10.0),
            client_timeout: Duration::from_secs(env_or::<u64>("SYNX_CLIENT_TIMEOUT", 25).clamp(5, 300)),
            ping_every: Duration::from_secs(env_or::<u64>("SYNX_PING_EVERY", 8).clamp(2, 60)),
            write_timeout: Duration::from_secs(env_or::<u64>("SYNX_WRITE_TIMEOUT", 10).clamp(2, 60)),
            countdown: Duration::from_millis(env_or::<u64>("SYNX_COUNTDOWN_MS", 5_000).clamp(1_000, 30_000)),
            finish_grace: Duration::from_secs(env_or::<u64>("SYNX_FINISH_GRACE", 75).clamp(10, 600)),
            results_hold: Duration::from_secs(env_or::<u64>("SYNX_RESULTS_HOLD", 20).clamp(5, 120)),
            race_timeout: Duration::from_secs(env_or::<u64>("SYNX_RACE_TIMEOUT", 1_500).clamp(60, 7_200)),
            empty_room_grace: Duration::from_secs(env_or::<u64>("SYNX_EMPTY_ROOM_GRACE", 20).clamp(1, 600)),
            correction_strikes: env_or::<u32>("SYNX_CORRECTION_STRIKES", 40).clamp(3, 10_000),
            http_rate: env_or::<f64>("SYNX_HTTP_RATE", 8.0).clamp(0.5, 500.0),
            connect_rate: env_or::<f64>("SYNX_CONNECT_RATE", 1.0).clamp(0.1, 100.0),
            accept_rate: env_or::<f64>("SYNX_ACCEPT_RATE", 20.0).clamp(1.0, 2_000.0),
            max_inflight: env_or::<usize>("SYNX_MAX_INFLIGHT", 64).clamp(4, 4_096),
            request_timeout: Duration::from_secs(env_or::<u64>("SYNX_REQUEST_TIMEOUT", 15).clamp(1, 120)),
            max_socket: Duration::from_secs(env_or::<u64>("SYNX_MAX_SOCKET", 10_800).clamp(60, 86_400)),
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
            client_secrets: std::env::var("SYNX_CLIENT_SECRET")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim())
                // Short entries are dropped rather than accepted, so a typo
                // cannot quietly weaken the check to something guessable.
                .filter(|s| s.len() >= 16)
                .map(|s| s.as_bytes().to_vec())
                .collect(),
            min_client: std::env::var("SYNX_MIN_CLIENT").ok().and_then(|s| parse_version(&s)),
            strict_client: env_or::<bool>("SYNX_STRICT_CLIENT", true),
            token_secret: secret,
            token_secret_generated: generated,
        }
    }

    /// One line per setting, at boot. See the note at the top of the file.
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
        info!(
            generated = self.token_secret_generated,
            "token secret{}",
            if self.token_secret_generated {
                " (generated per process; sessions end with a restart)"
            } else {
                ""
            }
        );
        if self.allowed_origins.is_empty() {
            warn!("origins: ANY - this server will answer a client on any site");
        } else {
            info!(origins = ?self.allowed_origins, strict = self.strict_client, "origins");
        }
        match (self.client_secrets.len(), self.strict_client) {
            (0, _) => warn!(
                "client attestation: OFF - set SYNX_CLIENT_SECRET to the value \
                 the game was built with to accept only your own client"
            ),
            (n, true) => info!(keys = n, "client attestation: required"),
            (n, false) => warn!(keys = n, "client attestation: checked but not enforced"),
        }
        match self.min_client {
            Some((a, b, c)) => info!("minimum client build: {a}.{b}.{c}"),
            None => info!("minimum client build: any"),
        }
        info!("-----------------------------------------------------------");
    }
}
