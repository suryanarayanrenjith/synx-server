//! Who is allowed to talk to this server.
//!
//! The game and this server are separate programs that meet at a URL, and a
//! URL is open to everybody. Two questions are worth asking at the door, and
//! this module asks exactly those two - no more, because a check that cannot
//! actually establish what it claims is worse than no check at all: it makes
//! the log look reassuring while proving nothing.
//!
//! THE FIRST IS AGREEMENT, and it is the one that earns its place.
//!
//! Two independently built halves can disagree about what a byte means, and
//! the failure is nasty precisely because it is not a crash: cars slide
//! through barriers, speeds read wrong, corrections fire for no reason.
//! [`synx_net::WIRE_FINGERPRINT`] is a compile-time digest of the format's own
//! shape - every opcode, every field width, every quantisation scale - so it
//! cannot drift from the code it describes. A client whose fingerprint is not
//! ours is refused with "update the game" rather than admitted to a race it
//! would experience as a haunting.
//!
//! THE SECOND IS ORIGIN, and it is worth being exact about its scope.
//!
//! Against a BROWSER it is decisive. A page on another site cannot forge the
//! `Origin` header - the browser sets it and refuses scripts the ability to
//! change it - so this one test is what stops some other web game quietly
//! adopting your server as free infrastructure. Against a NATIVE process it
//! proves nothing whatsoever; a hand-written client sends whatever header it
//! likes. Both halves of that are true, and the second does not cancel the
//! first.
//!
//! WHAT IS DELIBERATELY NOT HERE.
//!
//! There is no "is this the official client" check, because SYNX is open
//! source and there is no such thing. Anyone can clone this server, anyone can
//! build the game, and the two should meet without either having been issued a
//! credential by anybody. A shared secret compiled into a public download is
//! not a secret in any case - it ships to every user, and `strings` recovers
//! it - so a check built on one would have bought a reassuring log line and
//! very little else.
//!
//! What actually keeps a public server standing is elsewhere, and does not
//! care which client is talking: the physics validator in `validate.rs` (a
//! hand-written client still cannot teleport or outrun the envelope), the
//! registration proof of work, the per-address rate limits and connection
//! caps, and the strike table that removes a car which keeps failing them.
//! Those are the load-bearing layers. This module is the doormat.

use axum::http::HeaderMap;

use crate::config::Config;

/// Why a client was turned away at the door.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    /// The `Origin` header names somewhere this server does not serve.
    Origin,
    /// The client's wire format is not this server's wire format.
    Fingerprint,
}

impl Refusal {
    /// The short machine-readable tag, which is what the client switches on.
    pub fn code(self) -> &'static str {
        match self {
            Refusal::Origin => "bad-origin",
            Refusal::Fingerprint => "wire-mismatch",
        }
    }

    /// The sentence a player sees: what happened, and what to do about it.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::Origin => "this server does not serve clients from there",
            Refusal::Fingerprint => {
                "this build of the game speaks a different wire format; update the game"
            }
        }
    }

    pub fn status(self) -> u16 {
        match self {
            // 426 is the one status that means "your build is wrong", which is
            // exactly the fingerprint case and nothing else here.
            Refusal::Fingerprint => 426,
            Refusal::Origin => 403,
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
    /// There is no `Origin` header, so the caller is not a browser. Nothing is
    /// proven either way: a desktop build legitimately omits it, and so does a
    /// hand-written client, which is exactly why this is a third answer rather
    /// than a refusal.
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
        // nowhere, so it cannot be matched against anything, and reading it as
        // absent is the honest answer rather than a refusal.
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

// ------------------------------------------------------------ the door ----

/// The whole doorway, in the order that costs least.
///
/// The fingerprint is a `u32` compare and the origin is a short string walk,
/// so a client that will not be admitted is turned away before this server
/// allocates anything on its behalf.
pub fn admit(cfg: &Config, headers: &HeaderMap, fingerprint: u32) -> Result<(), Refusal> {
    if fingerprint != synx_net::WIRE_FINGERPRINT {
        return Err(Refusal::Fingerprint);
    }
    if matches!(check_origin(cfg, headers), OriginVerdict::Refused) {
        return Err(Refusal::Origin);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(origins: &[&str]) -> Config {
        let mut c = Config::from_env();
        c.allowed_origins = origins.iter().map(|s| s.to_string()).collect();
        c
    }

    fn with_origin(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(axum::http::header::ORIGIN, v.parse().unwrap());
        h
    }

    // --------------------------------------------------------- parsing -----

    #[test]
    fn an_origin_is_scheme_host_and_optional_port() {
        let o = parse_origin("https://example.com:8443").unwrap();
        assert_eq!(o.scheme, "https");
        assert_eq!(o.host, "example.com");
        assert_eq!(o.port, Some("8443"));
    }

    /// The failure mode of a lenient parser here is admitting somebody who
    /// should have been refused, so anything that is not exactly an origin is
    /// rejected rather than trimmed down into one that looks acceptable.
    #[test]
    fn things_that_are_not_origins_are_refused_rather_than_trimmed() {
        for bad in [
            "",
            "example.com",        // no scheme
            "https://",           // no host
            "https://a.com/path", // an Origin never carries a path
            "https://user@a.com", // nor credentials
            "https://[::1]",      // a bare IPv6 literal: the colons are not a port
            "://a.com",
        ] {
            assert!(parse_origin(bad).is_none(), "{bad:?} should not parse");
        }
    }

    /// A bracketed IPv6 literal WITH a port does parse, because the last colon
    /// really is a port separator. That is harmless and worth pinning rather
    /// than pretending otherwise: it is read as an ordinary host, and an
    /// ordinary host matches nothing unless somebody puts it on the allowlist.
    #[test]
    fn a_bracketed_ipv6_host_parses_but_still_matches_nothing_by_default() {
        assert!(parse_origin("https://[::1]:80").is_some());
        let c = Config::from_env();
        assert!(!origin_allows(&c.allowed_origins, "https://[::1]:80"));
    }

    // -------------------------------------------------------- matching -----

    #[test]
    fn scheme_and_host_are_compared_case_insensitively() {
        let c = cfg(&["https://Example.COM"]);
        assert!(origin_allows(&c.allowed_origins, "HTTPS://example.com"));
    }

    /// An allowlist entry without a port admits any port, which is what makes
    /// a dev server on an arbitrary port work. One WITH a port pins it.
    #[test]
    fn a_port_in_the_allowlist_pins_the_port_and_its_absence_does_not() {
        let loose = cfg(&["http://127.0.0.1"]);
        assert!(origin_allows(&loose.allowed_origins, "http://127.0.0.1:8000"));
        assert!(origin_allows(&loose.allowed_origins, "http://127.0.0.1"));

        let pinned = cfg(&["http://127.0.0.1:8000"]);
        assert!(origin_allows(&pinned.allowed_origins, "http://127.0.0.1:8000"));
        assert!(!origin_allows(&pinned.allowed_origins, "http://127.0.0.1:9999"));
    }

    #[test]
    fn a_different_host_or_scheme_is_refused() {
        let c = cfg(&["https://synx.example"]);
        assert!(!origin_allows(&c.allowed_origins, "https://evil.example"));
        assert!(!origin_allows(&c.allowed_origins, "http://synx.example"));
    }

    /// The exact origins a Tauri build presents on each platform. If this ever
    /// breaks, the desktop game cannot reach its own server.
    #[test]
    fn the_shipped_desktop_origins_are_allowed_by_default() {
        let c = Config::from_env();
        for o in ["tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"] {
            assert!(origin_allows(&c.allowed_origins, o), "{o} must be allowed");
        }
    }

    // --------------------------------------------------------- the door ----

    #[test]
    fn a_client_from_an_allowed_origin_is_admitted() {
        let c = cfg(&["tauri://localhost"]);
        assert!(admit(&c, &with_origin("tauri://localhost"), synx_net::WIRE_FINGERPRINT).is_ok());
    }

    #[test]
    fn a_client_from_somewhere_else_is_refused() {
        let c = cfg(&["tauri://localhost"]);
        assert_eq!(
            admit(&c, &with_origin("https://someone-elses-game.example"), synx_net::WIRE_FINGERPRINT),
            Err(Refusal::Origin)
        );
    }

    /// No `Origin` at all is a native process, not a browser. Nothing is
    /// proven either way, and refusing it would lock out every desktop build
    /// on a platform that omits the header.
    #[test]
    fn a_request_with_no_origin_header_is_not_refused_for_that() {
        let c = cfg(&["tauri://localhost"]);
        assert!(admit(&c, &HeaderMap::new(), synx_net::WIRE_FINGERPRINT).is_ok());
    }

    /// The check that actually earns its place: a build that would misread the
    /// wire is stopped here, rather than discovered later as a car sliding
    /// through a barrier at the wrong scale.
    #[test]
    fn a_different_wire_format_is_refused_before_anything_else() {
        let c = cfg(&["tauri://localhost"]);
        let stale = synx_net::WIRE_FINGERPRINT ^ 1;
        // Refused for the wire even though the origin is fine...
        assert_eq!(admit(&c, &with_origin("tauri://localhost"), stale), Err(Refusal::Fingerprint));
        // ...and still for the wire when the origin is not.
        assert_eq!(
            admit(&c, &with_origin("https://elsewhere.example"), stale),
            Err(Refusal::Fingerprint)
        );
    }

    #[test]
    fn a_wire_mismatch_asks_for_an_upgrade_and_a_bad_origin_does_not() {
        assert_eq!(Refusal::Fingerprint.status(), 426);
        assert_eq!(Refusal::Origin.status(), 403);
    }
}
