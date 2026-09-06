//! The one thing two independently built halves must agree on.
//!
//! The game and the server are separate programs now, built from separate
//! trees, and they meet only at a URL. That buys independence and costs the
//! guarantee a shared crate used to give away: that both sides agree on what a
//! byte means.
//!
//! The failure that costs is not a crash. Two builds that disagree about a
//! quantisation scale connect happily and then diverge quietly - cars slide
//! through barriers, speeds read wrong, corrections fire for no reason - and
//! the symptom looks like a physics bug for as long as it takes somebody to
//! think of the wire.
//!
//! [`WIRE_FINGERPRINT`] closes that. It is a compile-time digest of the
//! format's own shape, derived from the constants themselves rather than
//! maintained beside them, so it cannot fall out of step with what it
//! describes. The client sends it before it sends a car, and a mismatch is
//! refused with a sentence a player can act on.

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

    /// The fingerprint is a compile-time constant, so the only way it can be
    /// wrong is by being trivially wrong. A zero would mean the fold never
    /// ran and every build would agree with every other one - which is the
    /// exact failure this module exists to prevent, silently.
    #[test]
    fn the_fingerprint_is_not_a_degenerate_value() {
        assert_ne!(WIRE_FINGERPRINT, 0);
        assert_ne!(WIRE_FINGERPRINT, u32::MAX);
    }

    /// The fold has to actually depend on what goes into it. If `mix` ignored
    /// its input, the fingerprint would still look like a plausible random
    /// number while matching between builds that differ.
    #[test]
    fn every_input_changes_the_result() {
        let base = mix(0xcbf2_9ce4_8422_2325, 1);
        assert_ne!(base, mix(0xcbf2_9ce4_8422_2325, 2));
        assert_ne!(base, mix(0xcbf2_9ce4_8422_2326, 1));
    }

    /// Scales fold in as thousandths, which is what lets a `const fn` read
    /// them at all. The conversion still has to distinguish values that differ
    /// by an amount anybody would care about.
    #[test]
    fn quantisation_scales_fold_in_finely_enough_to_matter() {
        assert_eq!(milli(1.0), 1000);
        assert_ne!(milli(1.0), milli(1.001));
    }
}
