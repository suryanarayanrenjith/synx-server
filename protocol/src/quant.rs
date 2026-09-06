//! Quantization helpers for compact network state encoding.

use core::f32::consts::PI;

/// `i16` per radian over the full turn. `32767 / pi`.
const ANGLE_SCALE: f32 = 10430.219;
/// `i16` per world unit per second. Range +-256 u/s against a 122 u/s ceiling.
const VEL_SCALE: f32 = 128.0;
/// `i16` per radian per second. Range +-8 rad/s against a 3.6 rad/s clamp.
const RATE_SCALE: f32 = 4096.0;
/// `i16` per world unit of lateral offset. Range +-128 against a 32 u corridor.
const LATERAL_SCALE: f32 = 256.0;

#[inline]
fn clampf(v: f32, lo: f32, hi: f32) -> f32 {
    if v.is_nan() {
        return 0.0;
    }
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Wrap an angle into `[-pi, pi]` before it is quantised.
///
/// Yaw accumulates: a car that has driven three laps of a roundabout has a yaw
/// of about nineteen radians, and quantising that directly would saturate at
/// pi and freeze the car pointing one way. Wrapping first is what makes an
/// `i16` the right size for an unbounded quantity.
#[inline]
pub fn wrap_pi(a: f32) -> f32 {
    if !a.is_finite() {
        return 0.0;
    }
    let two_pi = 2.0 * PI;
    let mut r = a % two_pi;
    if r > PI {
        r -= two_pi;
    } else if r < -PI {
        r += two_pi;
    }
    r
}

#[inline]
pub fn q_angle(a: f32) -> i16 {
    (clampf(wrap_pi(a) * ANGLE_SCALE, -32767.0, 32767.0)) as i16
}

#[inline]
pub fn deq_angle(q: i16) -> f32 {
    q as f32 / ANGLE_SCALE
}

#[inline]
pub fn q_vel(v: f32) -> i16 {
    (clampf(v * VEL_SCALE, -32767.0, 32767.0)) as i16
}

#[inline]
pub fn deq_vel(q: i16) -> f32 {
    q as f32 / VEL_SCALE
}

#[inline]
pub fn q_rate(v: f32) -> i16 {
    (clampf(v * RATE_SCALE, -32767.0, 32767.0)) as i16
}

#[inline]
pub fn deq_rate(q: i16) -> f32 {
    q as f32 / RATE_SCALE
}

#[inline]
pub fn q_lateral(v: f32) -> i16 {
    (clampf(v * LATERAL_SCALE, -32767.0, 32767.0)) as i16
}

#[inline]
pub fn deq_lateral(q: i16) -> f32 {
    q as f32 / LATERAL_SCALE
}

/// A signed `-1..1` knob - the steering wheel - in one byte.
#[inline]
pub fn q_unit(v: f32) -> i8 {
    (clampf(v, -1.0, 1.0) * 127.0) as i8
}

#[inline]
pub fn deq_unit(q: i8) -> f32 {
    q as f32 / 127.0
}

/// An unsigned `0..1` knob - a brake pedal, a fuel gauge, a damage total.
#[inline]
pub fn q_byte(v: f32) -> u8 {
    (clampf(v, 0.0, 1.0) * 255.0 + 0.5) as u8
}

#[inline]
pub fn deq_byte(q: u8) -> f32 {
    q as f32 / 255.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every codec has to survive its own range without changing sign or
    /// wrapping to the other end of it, which is the failure that looks like a
    /// physics bug rather than like a network one.
    #[test]
    fn round_trips_inside_a_visible_tolerance() {
        for i in -180..=180 {
            let a = i as f32 * PI / 180.0;
            let back = deq_angle(q_angle(a));
            assert!((back - a).abs() < 1e-3, "angle {a} came back {back}");
        }
        for v in [-122.0f32, -40.0, -0.01, 0.0, 0.01, 40.0, 122.0] {
            assert!((deq_vel(q_vel(v)) - v).abs() < 0.01);
        }
        for v in [-3.6f32, -1.0, 0.0, 1.0, 3.6] {
            assert!((deq_rate(q_rate(v)) - v).abs() < 1e-3);
        }
        for v in [-32.0f32, -18.0, 0.0, 18.0, 32.0] {
            assert!((deq_lateral(q_lateral(v)) - v).abs() < 0.01);
        }
        for v in [-1.0f32, -0.5, 0.0, 0.5, 1.0] {
            assert!((deq_unit(q_unit(v)) - v).abs() < 0.01);
        }
        for v in [0.0f32, 0.25, 0.5, 1.0] {
            assert!((deq_byte(q_byte(v)) - v).abs() < 0.01);
        }
    }

    #[test]
    fn saturates_instead_of_wrapping() {
        // 900 u/s is impossible, but if it ever arrived it must read as fast
        // rather than as fast in the other direction
        assert!(deq_vel(q_vel(900.0)) > 100.0);
        assert!(deq_vel(q_vel(-900.0)) < -100.0);
        assert!(deq_lateral(q_lateral(9000.0)) > 100.0);
    }

    #[test]
    fn an_accumulated_yaw_still_points_the_right_way() {
        // three laps of a roundabout plus a quarter turn
        let a = 6.0 * PI + PI / 2.0;
        let back = deq_angle(q_angle(a));
        assert!((back - PI / 2.0).abs() < 1e-3, "wrapped yaw came back {back}");
    }

    #[test]
    fn a_nan_becomes_a_zero_rather_than_a_random_integer() {
        assert_eq!(q_angle(f32::NAN), 0);
        assert_eq!(q_vel(f32::NAN), 0);
        assert_eq!(q_byte(f32::NAN), 0);
        assert_eq!(wrap_pi(f32::INFINITY), 0.0);
    }
}
