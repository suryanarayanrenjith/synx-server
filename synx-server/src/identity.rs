//! Identity registration, proof of work, device handles, and session tokens.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

type HmacSha256 = Hmac<Sha256>;

/// Milliseconds since the Unix epoch. The one clock everything here uses.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// How long a proof-of-work challenge is good for. Long enough for a slow
/// machine to solve one, short enough that a stolen challenge is worthless.
const CHALLENGE_TTL_MS: u64 = 120_000;

/// The most a name may be, in characters. Long enough for a handle, short
/// enough to fit a scoreboard row without eliding.
pub const MAX_NAME: usize = 16;

// ------------------------------------------------------------------- names --

/// Make a submitted name safe to show to other players.
///
/// Three separate problems, all solved by the same pass:
///
///   RENDERING. The scoreboard is drawn into a fixed-width row, and the game
///   draws with one font. Anything outside printable ASCII either renders as a
///   box or, in the case of the combining and bidirectional ranges, rearranges
///   the text around it. So the alphabet is ASCII, and it is an allow list.
///
///   IMPERSONATION. Zero-width characters would let two players have names
///   that are visibly identical, which is worth nothing to an honest player
///   and quite a lot to a dishonest one. They are not in the allow list.
///
///   INJECTION. The name travels to other clients inside JSON and is drawn
///   into a canvas, never into HTML - but it also lands in the server log, and
///   a newline in a log line is how one entry becomes two.
///
/// Anything that survives none of that becomes a generated name rather than an
/// error, because a player who typed an emoji should get to race.
pub fn clean_name(raw: &str) -> String {
    let mut out = String::with_capacity(MAX_NAME);
    let mut last_space = true;
    for ch in raw.chars() {
        if out.chars().count() >= MAX_NAME {
            break;
        }
        let c = ch.to_ascii_uppercase();
        let ok = c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '\'');
        if !ok {
            continue;
        }
        // no leading space, and never two in a row
        if c == ' ' {
            if last_space {
                continue;
            }
            last_space = true;
        } else {
            last_space = false;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    if out.len() < 2 {
        // A stable-ish anonymous handle rather than a rejection.
        let n = now_ms() % 9000 + 1000;
        return format!("DRIVER {n}");
    }
    out
}

// -------------------------------------------------------------- the device --

/// What the game reports about the machine it is running on.
///
/// Every field is optional and every field is untrusted. They are combined
/// into one hash and otherwise never read individually, except in the log,
/// where they are useful for working out what a report of "it stutters" was
/// actually running on.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DevicePrint {
    /// A random identifier the game generated on first run and keeps in its
    /// save file. The strongest of a weak set, because it survives a restart
    /// and costs a player nothing.
    pub install: String,
    pub platform: String,
    pub cores: u32,
    pub memory_gb: f32,
    /// The WebGL unmasked renderer string. The most distinguishing single
    /// field in practice, because there are a lot of GPUs.
    pub gpu: String,
    pub screen: String,
    pub dpr: f32,
    pub timezone: String,
    pub locale: String,
    pub agent: String,
    /// The game build and the WebAssembly ABI it loaded, so a mismatched
    /// client is refused at the door rather than at the first snapshot.
    pub build: String,
    pub wasm_abi: u32,
    /// A digest the client computes over things that are awkward to send
    /// whole - canvas and audio rendering differences, the font list.
    pub entropy: String,
}

impl DevicePrint {
    /// Everything that goes into the hash, in a fixed order, with lengths
    /// bounded so a client cannot make the server hash a megabyte.
    fn canonical(&self) -> String {
        fn cut(s: &str, n: usize) -> &str {
            let end = s.char_indices().nth(n).map(|(i, _)| i).unwrap_or(s.len());
            &s[..end]
        }
        format!(
            "{}|{}|{}|{:.0}|{}|{}|{:.2}|{}|{}|{}|{}|{}",
            cut(&self.install, 64),
            cut(&self.platform, 48),
            self.cores.min(512),
            self.memory_gb.clamp(0.0, 4096.0),
            cut(&self.gpu, 128),
            cut(&self.screen, 32),
            self.dpr.clamp(0.0, 16.0),
            cut(&self.timezone, 48),
            cut(&self.locale, 24),
            cut(&self.agent, 160),
            cut(&self.build, 32),
            cut(&self.entropy, 64),
        )
    }

    /// A short, opaque handle for this machine. Peppered with the process
    /// secret so it cannot be precomputed or correlated across deployments,
    /// and truncated because sixteen bytes is far past the point of collision
    /// for a table that holds at most a few hundred entries.
    pub fn hash(&self, pepper: &[u8; 32]) -> DeviceId {
        let mut h = Sha256::new();
        h.update(b"synx-device-v1");
        h.update(pepper);
        h.update(self.canonical().as_bytes());
        let d = h.finalize();
        let mut id = [0u8; 16];
        id.copy_from_slice(&d[..16]);
        DeviceId(id)
    }

    /// How much of the print was actually filled in, 0..1.
    ///
    /// Not a security measure - a client can fill in every field with lies -
    /// but a genuinely empty print is worth noticing in the log, because it
    /// means either a harness or somebody who has already started stripping
    /// things out.
    pub fn completeness(&self) -> f32 {
        let filled = [
            !self.install.is_empty(),
            !self.platform.is_empty(),
            self.cores > 0,
            self.memory_gb > 0.0,
            !self.gpu.is_empty(),
            !self.screen.is_empty(),
            !self.timezone.is_empty(),
            !self.locale.is_empty(),
            !self.agent.is_empty(),
            !self.entropy.is_empty(),
        ];
        filled.iter().filter(|b| **b).count() as f32 / filled.len() as f32
    }
}

/// The opaque per-machine handle.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DeviceId([u8; 16]);

impl DeviceId {
    pub fn short(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.0[..6])
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

// ---------------------------------------------------------- proof of work --

/// A challenge, signed rather than stored.
///
/// The obvious implementation keeps issued challenges in a set and removes
/// them when they are spent, and it is a denial of service: an attacker asks
/// for a million challenges and never spends them, and the set is the memory
/// limit. Signing the challenge instead makes the server stateless about it -
/// the timestamp is inside the token and the MAC proves the server issued it,
/// so nothing has to be remembered and nothing can be exhausted.
///
/// Layout: `nonce(16) || issued_ms(8) || mac(8)`, base64url.
pub fn issue_challenge(secret: &[u8; 32]) -> String {
    use rand::RngCore;
    let mut body = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut body[..16]);
    body[16..].copy_from_slice(&now_ms().to_le_bytes());
    let tag = tag(secret, b"challenge", &body);
    let mut out = Vec::with_capacity(32);
    out.extend_from_slice(&body);
    out.extend_from_slice(&tag[..8]);
    URL_SAFE_NO_PAD.encode(out)
}

/// Why a registration was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterError {
    BadChallenge,
    ChallengeExpired,
    BadProof,
    RateLimited,
    ProtocolMismatch,
    ServerFull,
}

impl RegisterError {
    pub fn as_str(self) -> &'static str {
        match self {
            RegisterError::BadChallenge => "that challenge was not issued by this server",
            RegisterError::ChallengeExpired => "that challenge has expired; ask for another",
            RegisterError::BadProof => "the proof of work does not solve the challenge",
            RegisterError::RateLimited => "too many registrations from this address",
            RegisterError::ProtocolMismatch => "this build speaks a different protocol version",
            RegisterError::ServerFull => "the grid is full",
        }
    }

    pub fn status(self) -> u16 {
        match self {
            RegisterError::RateLimited => 429,
            RegisterError::ServerFull => 503,
            RegisterError::ProtocolMismatch => 426,
            _ => 400,
        }
    }
}

/// Check a challenge is ours and is still fresh, and that the nonce solves it.
///
/// The work is `SHA-256(challenge || ':' || nonce)` having `bits` leading
/// zeroes. Cheap to verify - one hash - and exponential to produce, which is
/// the whole point: a browser spends a few milliseconds and a script that
/// wants ten thousand identities spends a few minutes of CPU per thousand.
pub fn verify_challenge(
    secret: &[u8; 32],
    challenge: &str,
    nonce: &str,
    bits: u32,
) -> Result<(), RegisterError> {
    let raw = URL_SAFE_NO_PAD.decode(challenge).map_err(|_| RegisterError::BadChallenge)?;
    if raw.len() != 32 {
        return Err(RegisterError::BadChallenge);
    }
    let (body, mac) = raw.split_at(24);
    let want = tag(secret, b"challenge", body);
    // Constant time, because a MAC compared with `==` leaks its own answer one
    // byte at a time to anybody willing to measure.
    if !constant_eq(&want[..8], mac) {
        return Err(RegisterError::BadChallenge);
    }
    let issued = u64::from_le_bytes(body[16..24].try_into().unwrap());
    let now = now_ms();
    if now.saturating_sub(issued) > CHALLENGE_TTL_MS || issued > now + 30_000 {
        return Err(RegisterError::ChallengeExpired);
    }
    if bits == 0 {
        return Ok(());
    }
    if nonce.len() > 40 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(RegisterError::BadProof);
    }
    // The shared implementation, which is also the one the game solves with.
    // Two SHA-256s that agree on the NIST vectors still have to agree on how
    // the message is assembled, and the only way to be sure of that is for
    // there to be one function that assembles it.
    if synx_net::pow::solves(challenge.as_bytes(), nonce.as_bytes(), bits) {
        Ok(())
    } else {
        Err(RegisterError::BadProof)
    }
}

fn tag(secret: &[u8; 32], domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut m = <HmacSha256 as Mac>::new_from_slice(secret).expect("hmac takes any key length");
    m.update(domain);
    m.update(body);
    let out = m.finalize().into_bytes();
    let mut t = [0u8; 32];
    t.copy_from_slice(&out);
    t
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

// ------------------------------------------------------------------ tokens --

/// A session, as the server remembers it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: u64,
    pub name: String,
    pub device: DeviceId,
    pub issued_ms: u64,
    pub expires_ms: u64,
    /// When this session last did anything, for the idle sweep.
    pub seen: Instant,
    /// True while a WebSocket is open on it. One at a time.
    pub connected: bool,
    /// Which address registered it. Used only to log a session that then
    /// connects from somewhere else, which is normal on a phone and worth
    /// noticing in bulk.
    pub origin: Option<IpAddr>,
    /// Anti-cheat strikes carried across the whole session rather than reset
    /// per race, so leaving and rejoining a room does not clear them.
    pub strikes: u32,
}

/// Why a token was refused at the door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
    Expired,
    Unknown,
    AlreadyConnected,
    Banned,
}

impl TokenError {
    pub fn as_str(self) -> &'static str {
        match self {
            TokenError::Malformed => "that token is not a token",
            TokenError::BadSignature => "that token was not issued by this server",
            TokenError::Expired => "that session has expired",
            TokenError::Unknown => "that session is not open; the server has restarted",
            TokenError::AlreadyConnected => "that session is already connected",
            TokenError::Banned => "this session has been removed from the grid",
        }
    }
}

/// Every live session, and the bans, for the life of the process.
#[derive(Default)]
pub struct Registry {
    sessions: HashMap<u64, Session>,
    /// Devices removed for cheating. Cleared on restart along with everything
    /// else, which is a limitation the deployment target imposes rather than a
    /// choice - see the note at the top of the file.
    banned: HashMap<DeviceId, Instant>,
    next_id: u64,
    /// Lifetime counters for the stats endpoint.
    pub issued: u64,
    pub refused: u64,
}

impl Registry {
    /// Mint a session and its token.
    pub fn open(
        &mut self,
        secret: &[u8; 32],
        name: String,
        device: DeviceId,
        origin: Option<IpAddr>,
        ttl: Duration,
    ) -> (String, Session) {
        // A random high id rather than a counter, so a token cannot be guessed
        // from another one and a log line does not leak how busy the server is.
        use rand::RngCore;
        let mut id = rand::thread_rng().next_u64();
        while id == 0 || self.sessions.contains_key(&id) {
            id = rand::thread_rng().next_u64();
        }
        self.next_id = self.next_id.wrapping_add(1);

        let issued_ms = now_ms();
        let expires_ms = issued_ms + ttl.as_millis() as u64;
        let s = Session {
            id,
            name,
            device,
            issued_ms,
            expires_ms,
            seen: Instant::now(),
            connected: false,
            origin,
            strikes: 0,
        };
        self.sessions.insert(id, s.clone());
        self.issued += 1;
        (encode_token(secret, id, expires_ms, &device), s)
    }

    /// Check a token and claim the session for a connection.
    pub fn claim(&mut self, secret: &[u8; 32], token: &str) -> Result<Session, TokenError> {
        match self.claim_inner(secret, token) {
            Ok(s) => {
                debug!(
                    session = s.id,
                    name = %s.name,
                    device = %s.device.short(),
                    age_s = (now_ms().saturating_sub(s.issued_ms)) / 1000,
                    registered_from = ?s.origin,
                    strikes = s.strikes,
                    "session claimed"
                );
                Ok(s)
            }
            Err(e) => {
                self.refused += 1;
                Err(e)
            }
        }
    }

    fn claim_inner(&mut self, secret: &[u8; 32], token: &str) -> Result<Session, TokenError> {
        let (id, expires_ms, device) = decode_token(secret, token)?;
        if now_ms() > expires_ms {
            self.sessions.remove(&id);
            return Err(TokenError::Expired);
        }
        if self.banned.contains_key(&device) {
            return Err(TokenError::Banned);
        }
        let s = self.sessions.get_mut(&id).ok_or(TokenError::Unknown)?;
        if s.connected {
            return Err(TokenError::AlreadyConnected);
        }
        s.connected = true;
        s.seen = Instant::now();
        Ok(s.clone())
    }

    pub fn release(&mut self, id: u64) {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.connected = false;
            s.seen = Instant::now();
        }
    }

    pub fn touch(&mut self, id: u64) {
        if let Some(s) = self.sessions.get_mut(&id) {
            s.seen = Instant::now();
        }
    }

    /// Record anti-cheat strikes. Returns true once the session is over its
    /// budget and should be removed from the grid.
    pub fn strike(&mut self, id: u64, n: u32, budget: u32) -> bool {
        let Some(s) = self.sessions.get_mut(&id) else { return false };
        s.strikes = s.strikes.saturating_add(n);
        if s.strikes < budget {
            return false;
        }
        // Past the budget the session is not merely removed from a room, it
        // stops being a way back in - otherwise leaving and rejoining is a
        // free reset, and the strike count means nothing.
        let (device, name, strikes) = (s.device, s.name.clone(), s.strikes);
        self.ban(device, &format!("{name} collected {strikes} impossible positions"));
        true
    }

    pub fn ban(&mut self, device: DeviceId, why: &str) {
        warn!(device = %device.short(), why, "device removed from the grid");
        self.banned.insert(device, Instant::now());
        self.sessions.retain(|_, s| s.device != device);
    }

    /// Forget expired and long-idle sessions, and bans older than an hour.
    ///
    /// Without this a server that has been up for a day holds a row for every
    /// player who ever pressed MULTIPLAYER. With it, the table is the people
    /// actually here plus whoever left in the last half hour.
    pub fn sweep(&mut self, idle: Duration) {
        let now = now_ms();
        let before = self.sessions.len();
        self.sessions.retain(|_, s| {
            if now > s.expires_ms {
                return false;
            }
            s.connected || s.seen.elapsed() < idle
        });
        self.banned.retain(|_, t| t.elapsed() < Duration::from_secs(3_600));
        let dropped = before - self.sessions.len();
        if dropped > 0 {
            debug!(dropped, live = self.sessions.len(), "session sweep");
        }
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn connected(&self) -> usize {
        self.sessions.values().filter(|s| s.connected).count()
    }

    pub fn bans(&self) -> usize {
        self.banned.len()
    }
}

/// `id(8) || expires_ms(8) || device(16) || mac(16)`, base64url.
///
/// The device id travels inside the token so that a ban can be enforced
/// without a lookup, and so a token cannot be moved between machines and still
/// carry the print it was issued against.
fn encode_token(secret: &[u8; 32], id: u64, expires_ms: u64, device: &DeviceId) -> String {
    let mut body = Vec::with_capacity(32);
    body.extend_from_slice(&id.to_le_bytes());
    body.extend_from_slice(&expires_ms.to_le_bytes());
    body.extend_from_slice(&device.0);
    let t = tag(secret, b"session", &body);
    body.extend_from_slice(&t[..16]);
    URL_SAFE_NO_PAD.encode(body)
}

fn decode_token(secret: &[u8; 32], token: &str) -> Result<(u64, u64, DeviceId), TokenError> {
    if token.len() > 128 {
        return Err(TokenError::Malformed);
    }
    let raw = URL_SAFE_NO_PAD.decode(token).map_err(|_| TokenError::Malformed)?;
    if raw.len() != 48 {
        return Err(TokenError::Malformed);
    }
    let (body, mac) = raw.split_at(32);
    if !constant_eq(&tag(secret, b"session", body)[..16], mac) {
        return Err(TokenError::BadSignature);
    }
    let id = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let expires = u64::from_le_bytes(body[8..16].try_into().unwrap());
    let mut d = [0u8; 16];
    d.copy_from_slice(&body[16..32]);
    Ok((id, expires, DeviceId(d)))
}

// ------------------------------------------------------------------- shape --

/// What the game posts to `/api/session`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    pub name: String,
    pub challenge: String,
    #[serde(default)]
    pub nonce: String,
    #[serde(default)]
    pub protocol: u16,
    #[serde(default)]
    pub device: DevicePrint,
}

/// ...and what it gets back.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub token: String,
    pub name: String,
    pub session: String,
    pub device: String,
    pub expires_ms: u64,
    pub server_time_ms: u64,
    pub protocol: u16,
    /// Where to open the socket. Given rather than assumed so the deployment
    /// can move it without a client release.
    pub ws: String,
}

/// The answer to `/api/handshake`.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    pub challenge: String,
    pub bits: u32,
    pub ttl_ms: u64,
    pub server_time_ms: u64,
    pub protocol: u16,
    pub build: &'static str,
    /// True when the instance has finished loading and can take players. The
    /// client uses this to tell "waking up" from "here".
    pub ready: bool,
}

/// Log what registered, in one line, at info.
pub fn log_registration(s: &Session, print: &DevicePrint, ip: Option<IpAddr>) {
    info!(
        session = s.id,
        name = %s.name,
        device = %s.device.short(),
        ip = ?ip,
        platform = %print.platform,
        cores = print.cores,
        memory_gb = print.memory_gb,
        gpu = %print.gpu,
        screen = %print.screen,
        tz = %print.timezone,
        locale = %print.locale,
        build = %print.build,
        wasm_abi = print.wasm_abi,
        print_completeness = print.completeness(),
        "session opened"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> [u8; 32] {
        [7u8; 32]
    }

    #[test]
    fn names_are_reduced_to_something_drawable() {
        assert_eq!(clean_name("Ryker"), "RYKER");
        assert_eq!(clean_name("  spaced   out  "), "SPACED OUT");
        assert_eq!(clean_name("nova\u{200b}"), "NOVA");
        assert_eq!(clean_name("a\nb"), "AB");
        // stripped to the allowed alphabet, then cut to the field width
        assert_eq!(clean_name("<script>alert(1)</script>"), "SCRIPTALERT1SCRI");
        assert_eq!(clean_name("A REALLY VERY LONG NAME INDEED").chars().count(), MAX_NAME);
        assert!(clean_name("").starts_with("DRIVER "));
        assert!(clean_name("!!!").starts_with("DRIVER "));
        assert!(clean_name("\u{1f600}\u{1f600}").starts_with("DRIVER "));
    }

    #[test]
    fn a_token_round_trips_and_resists_editing() {
        let s = secret();
        let dev = DeviceId([3u8; 16]);
        let t = encode_token(&s, 12345, now_ms() + 60_000, &dev);
        let (id, _exp, d) = decode_token(&s, &t).unwrap();
        assert_eq!(id, 12345);
        assert_eq!(d, dev);

        // one flipped character and it is not ours any more
        let mut bad = t.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(decode_token(&s, &bad), Err(TokenError::BadSignature) | Err(TokenError::Malformed)));

        // and a different key cannot verify it
        assert_eq!(decode_token(&[9u8; 32], &t), Err(TokenError::BadSignature));

        assert_eq!(decode_token(&s, "not-base64-!!"), Err(TokenError::Malformed));
        assert_eq!(decode_token(&s, ""), Err(TokenError::Malformed));
        assert_eq!(decode_token(&s, &"A".repeat(400)), Err(TokenError::Malformed));
    }

    #[test]
    fn a_session_is_singular_and_expires() {
        let s = secret();
        let mut r = Registry::default();
        let (tok, sess) = r.open(&s, "RYKER".into(), DeviceId([1; 16]), None, Duration::from_secs(60));
        let claimed = r.claim(&s, &tok).unwrap();
        assert_eq!(claimed.id, sess.id);
        assert_eq!(r.claim(&s, &tok), Err(TokenError::AlreadyConnected));
        r.release(sess.id);
        assert!(r.claim(&s, &tok).is_ok());

        // a token for a session the registry has forgotten - which is what a
        // restart looks like to a client - is refused, not honoured
        let (orphan, _) = r.open(&s, "NOVA".into(), DeviceId([2; 16]), None, Duration::from_secs(60));
        let mut fresh = Registry::default();
        assert_eq!(fresh.claim(&s, &orphan), Err(TokenError::Unknown));
    }

    #[test]
    fn a_ban_follows_the_device_not_the_session() {
        let s = secret();
        let mut r = Registry::default();
        let dev = DeviceId([4; 16]);
        let (a, sa) = r.open(&s, "A".into(), dev, None, Duration::from_secs(60));
        r.ban(dev, "test");
        assert_eq!(r.claim(&s, &a), Err(TokenError::Banned));
        assert!(r.sessions.get(&sa.id).is_none(), "the banned session was left open");

        // a new token for the same device is still refused
        let (b, _) = r.open(&s, "A".into(), dev, None, Duration::from_secs(60));
        assert_eq!(r.claim(&s, &b), Err(TokenError::Banned));
    }

    /// The client solves the proof of work with `synx_net::pow`, compiled into
    /// WebAssembly. The server verifies it with the same function - but the
    /// rest of the server signs tokens with the audited `sha2`, so this is the
    /// one place the two implementations are put side by side and required to
    /// agree. If they ever diverge, registration silently becomes impossible
    /// for every player; here it is a red test instead.
    #[test]
    fn the_shared_sha256_agrees_with_the_audited_one() {
        for msg in [
            b"".as_slice(),
            b"abc".as_slice(),
            b"the quick brown fox jumps over the lazy dog".as_slice(),
            &[0u8; 55],
            &[0u8; 56],
            &[0u8; 64],
            &[0xffu8; 130],
        ] {
            let mine = synx_net::pow::sha256(msg);
            let theirs = Sha256::digest(msg);
            assert_eq!(&mine[..], &theirs[..], "digests differ for a {} byte message", msg.len());
        }
    }

    #[test]
    fn a_challenge_must_be_ours_fresh_and_solved() {
        let s = secret();
        let c = issue_challenge(&s);
        // zero bits: the signature is still checked
        assert!(verify_challenge(&s, &c, "", 0).is_ok());
        assert_eq!(verify_challenge(&[1u8; 32], &c, "", 0), Err(RegisterError::BadChallenge));
        assert_eq!(verify_challenge(&s, "aaaa", "", 0), Err(RegisterError::BadChallenge));

        // eight bits is one in 256, so a short search always finds it -
        // solved through the same function the game uses
        let n = synx_net::pow::solve(c.as_bytes(), 8, 0, 100_000).expect("no solution found");
        let nonce = n.to_string();
        assert!(verify_challenge(&s, &c, &nonce, 8).is_ok());
        assert_eq!(verify_challenge(&s, &c, "0", 24), Err(RegisterError::BadProof));
        // a nonce that is not a plain token is refused before it is hashed
        assert_eq!(verify_challenge(&s, &c, "../../etc", 8), Err(RegisterError::BadProof));
        assert_eq!(verify_challenge(&s, &c, &"1".repeat(80), 8), Err(RegisterError::BadProof));
    }

    #[test]
    fn the_device_hash_is_stable_and_peppered() {
        let p = DevicePrint {
            install: "abc".into(),
            platform: "Windows".into(),
            cores: 8,
            gpu: "NVIDIA".into(),
            ..Default::default()
        };
        let a = p.hash(&secret());
        assert_eq!(a, p.hash(&secret()), "the same print hashed differently");
        assert_ne!(a, p.hash(&[8u8; 32]), "the pepper does nothing");

        let mut q = p.clone();
        q.cores = 9;
        assert_ne!(a, q.hash(&secret()));
        assert!(p.completeness() > 0.0 && p.completeness() < 1.0);
    }

    /// A print full of enormous strings must not make the server hash them.
    #[test]
    fn an_oversized_print_is_truncated_before_it_is_hashed() {
        let p = DevicePrint {
            install: "x".repeat(1_000_000),
            gpu: "y".repeat(1_000_000),
            agent: "z".repeat(1_000_000),
            ..Default::default()
        };
        assert!(p.canonical().len() < 700, "canonical form was {} bytes", p.canonical().len());
        let _ = p.hash(&secret());
    }

    #[test]
    fn the_sweep_keeps_the_connected_and_drops_the_stale() {
        let s = secret();
        let mut r = Registry::default();
        let (tok, live) = r.open(&s, "LIVE".into(), DeviceId([1; 16]), None, Duration::from_secs(600));
        r.claim(&s, &tok).unwrap();
        let (_, gone) = r.open(&s, "GONE".into(), DeviceId([2; 16]), None, Duration::from_secs(600));

        // A zero idle window rather than a manufactured past `Instant`:
        // subtracting an hour from `Instant::now()` overflows on a machine
        // that has not been up for one, which is exactly the machine a fresh
        // container is.
        r.sweep(Duration::ZERO);
        assert!(r.sessions.contains_key(&live.id), "a connected session was swept");
        assert!(!r.sessions.contains_key(&gone.id), "an idle session survived");
    }
}
