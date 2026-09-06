//! What the two halves of the game prove to each other before they talk.
//!
//! The game and the server are built from separate repositories now, and they
//! meet only at a URL. That buys independence and costs the one guarantee a
//! shared crate used to give for free: that both sides agree on what a byte
//! means. Two things in this module put that guarantee back.
//!
//! [`WIRE_FINGERPRINT`] is a digest of the format's own shape - every opcode,
//! every field width, every quantisation scale. It is computed at compile time
//! from the constants themselves, so it cannot drift from the code it
//! describes: change a scale factor and the fingerprint changes with it,
//! whether or not anyone remembered to bump a version. The client sends its
//! fingerprint before it sends a car, and a mismatch is refused with a
//! sentence a player can act on, rather than discovered later as a vehicle
//! sliding through a barrier at the wrong scale.
//!
//! [`attest`] is the other half: a signature proving the client is the shipped
//! game. See the note on that function for what it does and does not prove -
//! it is worth being precise about, because the honest answer depends entirely
//! on where the secret lives.

use crate::pow::Sha256;

/// SHA-256's block size, which is what an HMAC pads its key out to.
const BLOCK: usize = 64;

/// HMAC-SHA256 over a list of parts.
///
/// Taking the message in pieces rather than as one slice is what keeps this
/// `no_std` and allocation-free: the payloads below are assembled from a
/// handful of fragments, and joining them would need a buffer whose size is a
/// guess. The pieces are fed to the hash in order, which is the same thing
/// without the guess.
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // A key longer than the block is replaced by its digest. A shorter one is
    // zero-padded. Both are the standard, and both matter: without the first,
    // long keys would be truncated rather than folded.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let mut h = Sha256::new();
        h.update(key);
        let d = h.finish();
        k[..32].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    let mut i = 0;
    while i < BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
        i += 1;
    }

    let inner = {
        let mut h = Sha256::new();
        h.update(&ipad);
        for p in parts {
            h.update(p);
        }
        h.finish()
    };

    let mut h = Sha256::new();
    h.update(&opad);
    h.update(&inner);
    h.finish()
}

/// One-shot HMAC over a single message.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[msg])
}

/// Compare two byte strings without letting the clock say where they differ.
///
/// A signature check that returns early on the first wrong byte tells an
/// attacker, in the time it takes to answer, how much of their guess was
/// right - which turns forging a 32-byte tag from an impossible search into
/// thirty-two short ones. The loop below always runs to the end.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Lowercase hex, into a caller-supplied buffer, returning the written slice.
///
/// `no_std` and no allocator, so the buffer comes from the caller. A 32-byte
/// digest needs 64 bytes of output; anything shorter gets nothing rather than
/// a truncated signature that would later fail to verify for the wrong reason.
pub fn to_hex<'a>(bytes: &[u8], out: &'a mut [u8]) -> &'a [u8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if out.len() < bytes.len() * 2 {
        return &[];
    }
    let mut i = 0;
    while i < bytes.len() {
        out[i * 2] = HEX[(bytes[i] >> 4) as usize];
        out[i * 2 + 1] = HEX[(bytes[i] & 0x0f) as usize];
        i += 1;
    }
    &out[..bytes.len() * 2]
}

/// Parse lowercase or uppercase hex into a caller-supplied buffer.
pub fn from_hex<'a>(hex: &[u8], out: &'a mut [u8]) -> Option<&'a [u8]> {
    if hex.len() % 2 != 0 || out.len() < hex.len() / 2 {
        return None;
    }
    let n = hex.len() / 2;
    let mut i = 0;
    while i < n {
        let hi = hex_val(hex[i * 2])?;
        let lo = hex_val(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(&out[..n])
}

fn hex_val(c: u8) -> Option<u8> {
    Some(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return None,
    })
}

// ------------------------------------------------------------ attestation --

/// Domain tag. Every signature this project produces names what it is for, so
/// a tag minted for one purpose can never be replayed as another.
const ATTEST_DOMAIN: &[u8] = b"synx-attest-v1";

/// Sign a server-issued challenge as the shipped client.
///
/// WHAT THIS PROVES, EXACTLY.
///
/// It proves the signer holds the client secret. Nothing more. Whether that is
/// worth anything depends on where the secret is kept, and the answer differs
/// sharply between the two shapes this game could have taken:
///
/// - In a **browser** build the secret would have to travel inside JavaScript,
///   where anybody can read it out of the sources panel in about four seconds.
///   There it proves nothing at all.
/// - In the **desktop** build it is compiled into the native binary and never
///   crosses into the webview: the page asks the host to sign a challenge and
///   receives only the tag. Extracting it means reverse-engineering a stripped
///   release executable. That is not impossible, and this comment will not
///   pretend otherwise - but it is a different order of effort, and it is the
///   reason SYNX ships as a desktop application rather than a web page.
///
/// The challenge is issued by the server, single-use and short-lived, so a tag
/// observed on the wire cannot be replayed. The protocol version, fingerprint
/// and build are inside the signature rather than beside it, so none of them
/// can be swapped after signing.
pub fn attest(
    secret: &[u8],
    challenge: &[u8],
    protocol: u16,
    fingerprint: u32,
    build: &[u8],
) -> [u8; 32] {
    hmac_sha256_parts(
        secret,
        &[
            ATTEST_DOMAIN,
            b"\x00",
            challenge,
            b"\x00",
            &protocol.to_le_bytes(),
            &fingerprint.to_le_bytes(),
            build,
            b"\x00",
        ],
    )
}

/// [`attest`], hex-encoded into `out`, which must hold 64 bytes.
pub fn attest_hex<'a>(
    secret: &[u8],
    challenge: &[u8],
    protocol: u16,
    fingerprint: u32,
    build: &[u8],
    out: &'a mut [u8],
) -> &'a [u8] {
    let tag = attest(secret, challenge, protocol, fingerprint, build);
    to_hex(&tag, out)
}

/// Verify a hex-encoded tag against the same inputs.
pub fn verify_attest_hex(
    secret: &[u8],
    challenge: &[u8],
    protocol: u16,
    fingerprint: u32,
    build: &[u8],
    presented_hex: &[u8],
) -> bool {
    let mut want = [0u8; 64];
    let want = attest_hex(secret, challenge, protocol, fingerprint, build, &mut want);
    ct_eq(want, presented_hex)
}

// ------------------------------------------------------- wire fingerprint --

/// A digest of this protocol's shape, computed at compile time.
///
/// Every number that decides what a byte means is folded in below: the opcodes,
/// the field widths, the flag bits, the quantisation scales. Because it is
/// derived from the constants rather than maintained beside them, it cannot
/// fall out of step with them - changing a scale factor changes this value in
/// the same edit, whether or not anyone thought to bump a version number.
///
/// [`crate::PROTOCOL_VERSION`] remains the number humans read and deploy
/// against; this is the one that catches the change nobody noticed.
pub const WIRE_FINGERPRINT: u32 = fingerprint();

/// FNV-1a, one 64-bit step. Not a cryptographic hash and not asked to be one:
/// this detects honest divergence between two builds, and an attacker who
/// wants to claim a fingerprint can simply send it.
const fn mix(h: u64, v: u64) -> u64 {
    (h ^ v).wrapping_mul(0x0000_0100_0000_01b3)
}

/// Scales fold in as fixed point. A `const fn` may do float arithmetic, but
/// reading a float's bit pattern is a different and less portable thing to ask
/// for, and a thousandth is finer than any change to these that would matter.
const fn milli(v: f32) -> u64 {
    (v as f64 * 1000.0) as u64
}

const fn fingerprint() -> u32 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;

    // Sizes and rates.
    h = mix(h, crate::PROTOCOL_VERSION as u64);
    h = mix(h, crate::MAX_PLAYERS as u64);
    h = mix(h, crate::MAX_CLIENT_BINARY as u64);
    h = mix(h, crate::MAX_CLIENT_TEXT as u64);
    h = mix(h, crate::MAX_SERVER_FRAME as u64);
    h = mix(h, crate::CLIENT_SEND_HZ as u64);
    h = mix(h, crate::SERVER_SNAPSHOT_HZ as u64);
    h = mix(h, crate::MAX_CLOCK_SKEW_MS as u64);

    // Message layout.
    h = mix(h, crate::msg::CAR_BODY_BYTES as u64);
    h = mix(h, crate::msg::SNAPSHOT_ENTRY_BYTES as u64);
    h = mix(h, crate::msg::SNAPSHOT_HEADER_BYTES as u64);
    h = mix(h, crate::msg::SNAP_LIVE as u64);
    h = mix(h, crate::msg::SNAP_OVER as u64);
    h = mix(h, crate::msg::SNAP_COUNTDOWN as u64);

    // Opcodes, in both directions.
    h = mix(h, crate::c2s::STATE as u64);
    h = mix(h, crate::c2s::TIME_REQ as u64);
    h = mix(h, crate::c2s::PONG as u64);
    h = mix(h, crate::s2c::SNAPSHOT as u64);
    h = mix(h, crate::s2c::CORRECTION as u64);
    h = mix(h, crate::s2c::TIME as u64);
    h = mix(h, crate::s2c::PING as u64);

    // Flag bits.
    h = mix(h, crate::flag::BOOSTING as u64);
    h = mix(h, crate::flag::DRIFTING as u64);
    h = mix(h, crate::flag::OFFROAD as u64);
    h = mix(h, crate::flag::RACE_MODE as u64);
    h = mix(h, crate::flag::FINISHED as u64);
    h = mix(h, crate::flag::WRONG_WAY as u64);
    h = mix(h, crate::flag::IDLE as u64);
    h = mix(h, crate::flag::CLAMPED as u64);

    // Quantisation. A change here alters not one field width, which is exactly
    // why it belongs in a fingerprint: it is the class of change a version
    // number is most likely to be spared.
    h = mix(h, milli(crate::quant::ANGLE_SCALE));
    h = mix(h, milli(crate::quant::VEL_SCALE));
    h = mix(h, milli(crate::quant::RATE_SCALE));
    h = mix(h, milli(crate::quant::LATERAL_SCALE));

    // Correction reasons, which the client renders as words.
    h = mix(h, crate::Correction::Speed as u64);
    h = mix(h, crate::Correction::OffCourse as u64);
    h = mix(h, crate::Correction::Teleport as u64);
    h = mix(h, crate::Correction::Altitude as u64);
    h = mix(h, crate::Correction::Clock as u64);
    h = mix(h, crate::Correction::Checkpoint as u64);
    h = mix(h, crate::Correction::Flood as u64);
    h = mix(h, crate::Correction::NotFinite as u64);

    (h ^ (h >> 32)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4231 case 2, which pins the HMAC to a published vector rather than
    /// to itself.
    #[test]
    fn hmac_matches_rfc4231() {
        let tag = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        let mut hex = [0u8; 64];
        assert_eq!(
            core::str::from_utf8(to_hex(&tag, &mut hex)).unwrap(),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// A key longer than the block is folded, not truncated.
    #[test]
    fn long_keys_are_hashed_not_cut() {
        let a = hmac_sha256(&[0xaa; 131], b"x");
        let b = hmac_sha256(&[0xaa; 132], b"x");
        assert_ne!(a, b, "two long keys must not collide through truncation");
    }

    #[test]
    fn attestation_round_trips() {
        let mut out = [0u8; 64];
        let tag = attest_hex(b"secret", b"chal", 1, WIRE_FINGERPRINT, b"synx 1.0.0", &mut out);
        assert!(verify_attest_hex(b"secret", b"chal", 1, WIRE_FINGERPRINT, b"synx 1.0.0", tag));
    }

    /// Every input is inside the signature, so changing any one of them
    /// invalidates it. This is the property that stops a tag minted for one
    /// build being presented by another.
    #[test]
    fn every_field_is_bound_into_the_tag() {
        let base = attest(b"k", b"c", 1, 7, b"b");
        assert_ne!(base, attest(b"K", b"c", 1, 7, b"b"), "secret");
        assert_ne!(base, attest(b"k", b"d", 1, 7, b"b"), "challenge");
        assert_ne!(base, attest(b"k", b"c", 2, 7, b"b"), "protocol");
        assert_ne!(base, attest(b"k", b"c", 1, 8, b"b"), "fingerprint");
        assert_ne!(base, attest(b"k", b"c", 1, 7, b"c"), "build");
    }

    /// The separators matter: without them a challenge ending in one byte and
    /// a build starting with the next would sign identically to the pair with
    /// that byte moved across the boundary.
    #[test]
    fn field_boundaries_are_unambiguous() {
        assert_ne!(attest(b"k", b"ab", 1, 7, b"c"), attest(b"k", b"a", 1, 7, b"bc"));
    }

    #[test]
    fn ct_eq_is_still_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn hex_round_trips() {
        let mut h = [0u8; 64];
        let hex = to_hex(&[0x00, 0x0f, 0xa5, 0xff], &mut h);
        assert_eq!(core::str::from_utf8(hex).unwrap(), "000fa5ff");
        let mut raw = [0u8; 4];
        assert_eq!(from_hex(hex, &mut raw).unwrap(), &[0x00, 0x0f, 0xa5, 0xff]);
        assert!(from_hex(b"0g", &mut raw).is_none());
        assert!(from_hex(b"abc", &mut raw).is_none());
    }

    /// Deliberately not a golden value: pinning one would mean updating it by
    /// hand on every intended change, which is the habit this replaces. What
    /// matters is that it is stable within a build and not degenerate.
    #[test]
    fn fingerprint_is_stable_and_nontrivial() {
        assert_eq!(WIRE_FINGERPRINT, super::fingerprint());
        assert_ne!(WIRE_FINGERPRINT, 0);
        assert_ne!(WIRE_FINGERPRINT, u32::MAX);
    }
}
