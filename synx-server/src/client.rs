//! Who is allowed to talk to this server.
//!
//! The game and this server used to be built from one tree and shipped
//! together. They are separate repositories now and meet only at a URL, which
//! is better in every way except one: a URL is open to everybody, and the two
//! guarantees that came free from being one build have to be stated explicitly.
//!
//! This module states them.
//!
//! THE FIRST IS AGREEMENT. Two independently built halves can disagree about
//! what a byte means, and the failure is nasty precisely because it is not a
//! crash: cars slide through barriers, speeds read wrong, corrections fire for
//! no reason. [`synx_net::WIRE_FINGERPRINT`] is a compile-time digest of the
//! format's shape, and a client whose fingerprint is not ours is refused with
//! "update the game" rather than admitted to a race it will experience as a
//! haunting.
//!
//! THE SECOND IS PROVENANCE, and it is worth being exact about what is and is
//! not achievable, because the honest answer is not "nothing" and it is also
//! not "airtight":
//!
//! - **Origin** is checked, and against a browser it is decisive. A page on
//!   another site cannot forge the `Origin` header - the browser sets it and
//!   refuses scripts the ability to change it - so this one test is what stops
//!   some other web game quietly adopting this server as free infrastructure.
//!   Against a native process it proves nothing at all; a hand-written client
//!   sends whatever header it likes.
//!
//! - **Attestation** is what covers that gap. The desktop client holds a
//!   secret in its native binary, never in the webview, and signs a
//!   server-issued challenge with it. Forging that means extracting a key from
//!   a compiled executable. That is possible for someone determined, and this
//!   comment will not pretend otherwise - but it is a wholly different order of
//!   effort from copying a URL out of devtools, and it is the reason the game
//!   ships as a desktop application.
//!
//! Neither check replaces the proof of work, the session token, or the physics
//! validator. They are the outermost layer of several, and the only one whose
//! job is to answer "is this my client?" rather than "is this abusive?".

use axum::http::HeaderMap;

use crate::config::Config;

/// Why a client was turned away at the door.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The `Origin` header names somewhere this server does not serve.
    Origin,
    /// The client's wire format is not this server's wire format.
    Fingerprint,
    /// A signature was presented and it is not the right one.
    Attestation,
    /// No signature was presented and this server requires one.
    Unattested,
    /// The client proved itself, and is an older build than this server will
    /// take. Separate from `Fingerprint` because the wire format may be
    /// perfectly compatible: this is a release being retired on purpose.
    Outdated,
}

impl Refusal {
    /// The short machine-readable tag, which is what the client switches on.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Origin => "bad-origin",
            Refusal::Fingerprint => "wire-mismatch",
            Refusal::Attestation => "bad-attestation",
            Refusal::Unattested => "unattested",
            Refusal::Outdated => "outdated-client",
        }
    }

    /// The sentence a player sees. Each one says what happened and what to do;
    /// none of them says more about the check than somebody probing it has
    /// already worked out by being refused.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Origin => "this server does not serve clients from there",
            Refusal::Fingerprint => {
                "this build of the game speaks a different wire format; update the game"
            }
            Refusal::Attestation => "this client could not prove it is SYNX",
            Refusal::Unattested => "this server only accepts the SYNX game client",
            Refusal::Outdated => {
                "this version of SYNX is no longer accepted; update the game"
            }
        }
    }

    pub fn status(self) -> u16 {
        match self {
            // 426 is the one status that means "your build is wrong", which is
            // exactly the fingerprint case and nothing else here.
            Refusal::Fingerprint | Refusal::Outdated => 426,
            _ => 403,
        }
    }
}

// ---------------------------------------------------------------- origins --

/// An origin split into the two parts that decide whether it matches.
///
/// Deliberately not a URL parser. An `Origin` header is a much smaller grammar
/// than a URL - scheme, host, optional port, nothing else - and the failure
/// mode of a lenient parser here is admitting a client that should have been
/// refused, so this reads exactly that grammar and rejects anything else.
#[derive(PartialEq, Eq, Debug)]
struct Origin<'a> {
    scheme: &'a str,
    host: &'a str,
    port: Option<&'a str>,
}

fn parse_origin(raw: &str) -> Option<Origin<'_>> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 256 {
        return None;
    }
    let (scheme, rest) = raw.split_once("://")?;
    if scheme.is_empty() || rest.is_empty() {
        return None;
    }
    // An Origin has no path, and something claiming to be one that carries a
    // path is not an origin - refuse rather than truncate to the part that
    // looks acceptable.
    if rest.contains('/') || rest.contains('@') {
        return None;
    }
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (h, Some(p)),
        // A colon that is not a port separator means an IPv6 literal, which
        // Tauri does not produce and this server does not need to accept.
        Some(_) => return None,
        None => (rest, None),
    };
    if host.is_empty() {
        return None;
    }
    Some(Origin { scheme, host, port })
}

/// Does `presented` match the allowlist entry `allowed`?
///
/// Scheme and host must be equal, case-insensitively. The port matches only if
/// the allowlist entry names one: `http://127.0.0.1` admits any port on the
/// loopback, which is what makes a dev server on an arbitrary port work,
/// while `http://127.0.0.1:8000` pins it to that one.
fn origin_matches(allowed: &str, presented: &Origin<'_>) -> bool {
    let Some(a) = parse_origin(allowed) else {
        return false;
    };
    a.scheme.eq_ignore_ascii_case(presented.scheme)
        && a.host.eq_ignore_ascii_case(presented.host)
        && match a.port {
            None => true,
            Some(p) => presented.port == Some(p),
        }
}

/// What the `Origin` header on this request means.
pub enum OriginVerdict {
    /// It names somewhere this server serves.
    Allowed,
    /// There is no `Origin` header, so this is not a browser. Nothing is
    /// proven either way and the caller must fall back to attestation.
    Absent,
    /// It names somewhere else.
    Refused,
}

/// Does this raw `Origin` string match any entry in `allowed`?
///
/// Shared with the CORS layer in `main.rs` so that the preflight and the
/// handler can never disagree: being told yes by one and no by the other is
/// the kind of split-brain that costs an afternoon to diagnose.
pub fn origin_allows(allowed: &[String], raw: &str) -> bool {
    match parse_origin(raw) {
        Some(p) => allowed.iter().any(|a| origin_matches(a, &p)),
        None => false,
    }
}

pub fn check_origin(cfg: &Config, headers: &HeaderMap) -> OriginVerdict {
    // An empty allowlist is an explicit "anywhere", not an accident: the boot
    // log warns about it, and it is reachable only by setting the variable to
    // a value that parses to nothing.
    if cfg.allowed_origins.is_empty() {
        return OriginVerdict::Allowed;
    }
    let raw = match headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        Some(v) if !v.trim().is_empty() && v.trim() != "null" => v,
        // "null" is what a sandboxed or `file://` document sends. It names
        // nowhere, so it cannot be matched against anything, and treating it
        // as absent puts it in front of attestation rather than through it.
        _ => return OriginVerdict::Absent,
    };
    // An unparseable Origin is refused rather than treated as absent. A
    // browser does not send one, so this is something hand-made, and letting
    // it fall through to the "not a browser" path would turn a malformed
    // header into a way around the allowlist.
    if origin_allows(&cfg.allowed_origins, raw) {
        OriginVerdict::Allowed
    } else {
        OriginVerdict::Refused
    }
}

// ------------------------------------------------------------ attestation --

/// What a client claims about itself, alongside its signature.
pub struct Claim<'a> {
    pub challenge: &'a str,
    pub protocol: u16,
    pub fingerprint: u32,
    pub build: &'a str,
    pub attestation: Option<&'a str>,
}

/// The whole doorway: agreement first, then provenance.
///
/// Order matters. The fingerprint is checked before the signature because a
/// player running an old build should be told to update - which they can act
/// on - rather than told their client could not prove itself, which they
/// cannot. Both are checked before anything is allocated on their behalf.
pub fn admit(cfg: &Config, headers: &HeaderMap, claim: &Claim<'_>) -> Result<(), Refusal> {
    // A client that does not send a fingerprint at all is an older build than
    // this check. It is refused for the same reason a wrong one is, and with
    // the same sentence, because "update the game" is the same fix.
    if claim.fingerprint != synx_net::WIRE_FINGERPRINT {
        return Err(Refusal::Fingerprint);
    }

    let origin = check_origin(cfg, headers);
    if cfg.strict_client {
        if let OriginVerdict::Refused = origin {
            return Err(Refusal::Origin);
        }
    }

    if cfg.client_secrets.is_empty() {
        // No secret configured: attestation is not possible, and the boot log
        // has already said so. Refusing here would make an unconfigured server
        // reject its own client, which is a worse failure than an open one
        // that announces itself.
        return Ok(());
    }

    let Some(tag) = claim.attestation.filter(|t| !t.is_empty()) else {
        return if cfg.strict_client { Err(Refusal::Unattested) } else { Ok(()) };
    };

    // ANY of the configured keys will do. See the note on `client_secrets`:
    // holding more than one is what lets a key be rotated without breaking
    // every copy of the game that is already installed.
    //
    // Every key is tried even after one matches. The work is a handful of
    // HMACs over a short message, and stopping early would leak - in the time
    // taken to answer - which key a client presented, which is the one thing
    // an attacker with a stolen old key would like to learn.
    let mut matched = false;
    for secret in &cfg.client_secrets {
        matched |= synx_net::auth::verify_attest_hex(
            secret,
            claim.challenge.as_bytes(),
            claim.protocol,
            claim.fingerprint,
            claim.build.as_bytes(),
            tag.as_bytes(),
        );
    }
    if !matched {
        return if cfg.strict_client { Err(Refusal::Attestation) } else { Ok(()) };
    }

    // THE VERSION FLOOR, and it is checked here on purpose - after the
    // signature rather than before it.
    //
    // The build string is inside the signature, so by this point it is a fact
    // rather than a claim: an attested client cannot say it is newer than it
    // is. Checked earlier, it would be reading a field anybody could write.
    //
    // This is the lever that retires a release without waiting for anyone to
    // update anything, and it is the reason a leaked key is survivable: raise
    // the floor above the builds that carry it, and they stop being accepted.
    if let Some(floor) = cfg.min_client {
        let theirs = crate::config::parse_version(claim.build).unwrap_or((0, 0, 0));
        if theirs < floor && cfg.strict_client {
            return Err(Refusal::Outdated);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One accepted key, or none. Most of these tests predate the server
    /// holding more than one and read better without the extra bracket.
    fn cfg(origins: &[&str], secret: Option<&str>, strict: bool) -> Config {
        let keys: Vec<&str> = secret.into_iter().collect();
        keyed(origins, &keys, strict)
    }

    /// The general form: any number of accepted keys.
    fn keyed(origins: &[&str], secrets: &[&str], strict: bool) -> Config {
        let mut c = Config::from_env();
        c.allowed_origins = origins.iter().map(|s| s.to_string()).collect();
        c.client_secrets = secrets.iter().map(|s| s.as_bytes().to_vec()).collect();
        c.strict_client = strict;
        c.min_client = None;
        c
    }

    fn with_origin(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, v.parse().unwrap());
        h
    }

    // ------------------------------------------------------------ parsing --

    #[test]
    fn parses_the_origins_tauri_actually_sends() {
        for o in ["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"] {
            assert!(parse_origin(o).is_some(), "{o}");
        }
    }

    #[test]
    fn a_port_is_read_as_a_port() {
        let o = parse_origin("http://127.0.0.1:52497").unwrap();
        assert_eq!(o.host, "127.0.0.1");
        assert_eq!(o.port, Some("52497"));
    }

    #[test]
    fn nonsense_is_refused_rather_than_salvaged() {
        for bad in ["", "localhost", "http://", "://x", "http://host/path", "http://a:b"] {
            assert!(parse_origin(bad).is_none(), "{bad:?} should not parse");
        }
    }

    // ----------------------------------------------------------- matching --

    #[test]
    fn an_entry_without_a_port_admits_any_port() {
        let p = parse_origin("http://127.0.0.1:52497").unwrap();
        assert!(origin_matches("http://127.0.0.1", &p));
    }

    #[test]
    fn an_entry_with_a_port_pins_it() {
        let p = parse_origin("http://127.0.0.1:52497").unwrap();
        assert!(!origin_matches("http://127.0.0.1:8000", &p));
    }

    /// The check that carries the most weight: a lookalike host must not pass.
    #[test]
    fn a_lookalike_host_does_not_match() {
        let p = parse_origin("https://tauri.localhost.evil.example").unwrap();
        assert!(!origin_matches("https://tauri.localhost", &p));
        let p = parse_origin("https://eviltauri.localhost").unwrap();
        assert!(!origin_matches("https://tauri.localhost", &p));
    }

    #[test]
    fn the_scheme_is_part_of_the_match() {
        let p = parse_origin("http://tauri.localhost").unwrap();
        assert!(!origin_matches("https://tauri.localhost", &p));
    }

    #[test]
    fn a_web_page_elsewhere_is_refused() {
        let c = cfg(&["tauri://localhost"], None, true);
        assert!(matches!(
            check_origin(&c, &with_origin("https://someone-elses-game.example")),
            OriginVerdict::Refused
        ));
    }

    #[test]
    fn a_missing_origin_is_absent_not_allowed() {
        let c = cfg(&["tauri://localhost"], None, true);
        assert!(matches!(check_origin(&c, &HeaderMap::new()), OriginVerdict::Absent));
        assert!(matches!(check_origin(&c, &with_origin("null")), OriginVerdict::Absent));
    }

    // -------------------------------------------------------------- admit --

    fn claim<'a>(challenge: &'a str, tag: Option<&'a str>) -> Claim<'a> {
        Claim {
            challenge,
            protocol: synx_net::PROTOCOL_VERSION,
            fingerprint: synx_net::WIRE_FINGERPRINT,
            build: "synx 1.0.0",
            attestation: tag,
        }
    }

    /// Two keys standing in for "the one the installed builds carry" and "the
    /// one the next release will carry".
    const OLD_KEY: &str = "the-old-key-long-enough";
    const NEW_KEY: &str = "the-new-key-long-enough";

    fn sign(secret: &str, challenge: &str) -> String {
        sign_build(secret, challenge, "synx 1.0.0")
    }

    fn sign_build(secret: &str, challenge: &str, build: &str) -> String {
        let mut out = [0u8; 64];
        let hex = synx_net::auth::attest_hex(
            secret.as_bytes(),
            challenge.as_bytes(),
            synx_net::PROTOCOL_VERSION,
            synx_net::WIRE_FINGERPRINT,
            build.as_bytes(),
            &mut out,
        );
        String::from_utf8(hex.to_vec()).unwrap()
    }

    #[test]
    fn the_real_client_is_admitted() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        let tag = sign("a-secret-at-least-16", "chal");
        assert!(admit(&c, &with_origin("tauri://localhost"), &claim("chal", Some(&tag))).is_ok());
    }

    #[test]
    fn a_client_without_the_secret_is_refused() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        let tag = sign("the-wrong-secret-here", "chal");
        assert_eq!(
            admit(&c, &with_origin("tauri://localhost"), &claim("chal", Some(&tag))),
            Err(Refusal::Attestation)
        );
    }

    #[test]
    fn a_client_with_no_signature_at_all_is_refused() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        assert_eq!(
            admit(&c, &with_origin("tauri://localhost"), &claim("chal", None)),
            Err(Refusal::Unattested)
        );
    }

    /// A tag is bound to the challenge it was signed for, so one observed on
    /// the wire cannot be presented again for a different handshake.
    #[test]
    fn a_tag_does_not_transfer_to_another_challenge() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        let tag = sign("a-secret-at-least-16", "chal-one");
        assert_eq!(
            admit(&c, &with_origin("tauri://localhost"), &claim("chal-two", Some(&tag))),
            Err(Refusal::Attestation)
        );
    }

    /// Even holding the secret does not get a web page in from the wrong site.
    #[test]
    fn a_correct_signature_from_a_refused_origin_is_still_refused() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        let tag = sign("a-secret-at-least-16", "chal");
        assert_eq!(
            admit(&c, &with_origin("https://elsewhere.example"), &claim("chal", Some(&tag))),
            Err(Refusal::Origin)
        );
    }

    /// The desktop client is the case with no browser origin at all, and it is
    /// admitted on its signature.
    #[test]
    fn a_native_client_is_admitted_on_its_signature_alone() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        let tag = sign("a-secret-at-least-16", "chal");
        assert!(admit(&c, &HeaderMap::new(), &claim("chal", Some(&tag))).is_ok());
    }

    #[test]
    fn a_stale_wire_format_is_refused_before_anything_else() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), true);
        let mut k = claim("chal", None);
        k.fingerprint = synx_net::WIRE_FINGERPRINT ^ 1;
        // Wrong origin and no signature too, but the fingerprint is the
        // actionable one and must be the one reported.
        assert_eq!(admit(&c, &with_origin("https://elsewhere.example"), &k), Err(Refusal::Fingerprint));
    }

    #[test]
    fn an_unconfigured_server_still_serves_its_own_client() {
        let c = cfg(&["tauri://localhost"], None, true);
        assert!(admit(&c, &with_origin("tauri://localhost"), &claim("chal", None)).is_ok());
    }

    // ------------------------------------------------- rotating a key -----

    /// The property the whole list exists for: while both keys are configured,
    /// a client built with EITHER works. That is the window in which an update
    /// can be shipped without the copies already installed going dark.
    #[test]
    fn both_the_old_and_the_new_key_are_accepted_during_a_rotation() {
        let c = keyed(&["tauri://localhost"], &[OLD_KEY, NEW_KEY], true);
        for key in [OLD_KEY, NEW_KEY] {
            let tag = sign(key, "chal");
            assert!(
                admit(&c, &with_origin("tauri://localhost"), &claim("chal", Some(&tag))).is_ok(),
                "a client built with {key} should still be admitted"
            );
        }
    }

    /// ...and dropping the old entry is what actually retires it.
    #[test]
    fn removing_a_key_retires_the_builds_that_carry_it() {
        let c = keyed(&["tauri://localhost"], &[NEW_KEY], true);
        let tag = sign(OLD_KEY, "chal");
        assert_eq!(
            admit(&c, &with_origin("tauri://localhost"), &claim("chal", Some(&tag))),
            Err(Refusal::Attestation)
        );
    }

    /// A key too short to be worth having is dropped rather than accepted, so
    /// a truncated environment variable cannot weaken the check to something
    /// guessable without anybody noticing.
    #[test]
    fn short_keys_are_not_configured() {
        std::env::set_var("SYNX_CLIENT_SECRET", "short,another-key-long-enough");
        let c = Config::from_env();
        std::env::remove_var("SYNX_CLIENT_SECRET");
        assert_eq!(c.client_secrets.len(), 1, "only the long key should survive");
    }

    // --------------------------------------------------- version floor -----

    /// The floor retires a release without touching the client, which is what
    /// makes a leaked key survivable.
    #[test]
    fn a_build_below_the_floor_is_refused_even_though_it_signed_correctly() {
        let mut c = keyed(&["tauri://localhost"], &[NEW_KEY], true);
        c.min_client = Some((1, 2, 0));
        let mut k = claim("chal", None);
        k.build = "synx 1.1.9";
        let tag = sign_build(NEW_KEY, "chal", k.build);
        k.attestation = Some(&tag);
        assert_eq!(admit(&c, &with_origin("tauri://localhost"), &k), Err(Refusal::Outdated));
    }

    #[test]
    fn a_build_at_or_above_the_floor_is_admitted() {
        let mut c = keyed(&["tauri://localhost"], &[NEW_KEY], true);
        c.min_client = Some((1, 2, 0));
        for v in ["synx 1.2.0", "synx 1.2.1", "synx 2.0.0"] {
            let mut k = claim("chal", None);
            k.build = v;
            let tag = sign_build(NEW_KEY, "chal", v);
            k.attestation = Some(&tag);
            assert!(admit(&c, &with_origin("tauri://localhost"), &k).is_ok(), "{v}");
        }
    }

    /// The floor is checked AFTER the signature, so the version it reads is one
    /// the client could not have invented. A client that lies about being new
    /// invalidates its own tag and is refused for that instead.
    #[test]
    fn claiming_a_newer_build_than_you_signed_for_fails_the_signature() {
        let mut c = keyed(&["tauri://localhost"], &[NEW_KEY], true);
        c.min_client = Some((1, 2, 0));
        let tag = sign_build(NEW_KEY, "chal", "synx 1.0.0");
        let mut k = claim("chal", Some(&tag));
        k.build = "synx 9.9.9"; // the lie
        assert_eq!(
            admit(&c, &with_origin("tauri://localhost"), &k),
            Err(Refusal::Attestation)
        );
    }

    #[test]
    fn versions_parse_the_way_the_build_string_is_written() {
        use crate::config::parse_version;
        assert_eq!(parse_version("synx 1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("1"), Some((1, 0, 0)));
        assert_eq!(parse_version("1.0.0-beta"), Some((1, 0, 0)));
        assert_eq!(parse_version("nonsense"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn permissive_mode_logs_rather_than_refuses() {
        let c = cfg(&["tauri://localhost"], Some("a-secret-at-least-16"), false);
        assert!(admit(&c, &with_origin("https://elsewhere.example"), &claim("chal", None)).is_ok());
    }
}
