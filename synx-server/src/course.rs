//! The road, as the server knows it.
//!
//! The server does not simulate cars. What it does is decide whether a
//! position a client claims is a position a car could be in, and every one of
//! those questions is a question about the road: is this inside the barriers,
//! is this at the height of the tarmac, has this car actually driven the
//! distance it says it has. So the server needs the centreline, and only the
//! centreline.
//!
//! It is not generated here. `mkcourse` emits `assets/course.bin` from the
//! game's own course generator and the game's own shipped centreline, and this
//! reads it. That is deliberate on two counts: the server cannot drift from
//! the road the game is driving, and starting up does not spend a second
//! generating twenty-nine thousand samples it could have read.
//!
//! The file is `include_bytes!`d rather than opened, so there is no path to
//! get wrong, nothing to mount, and no way for the binary and its data to be
//! deployed out of step. Half a megabyte of read-only data costs nothing that
//! matters.

use std::f32::consts::PI;

use tracing::info;

/// The course, as parallel arrays. `f32` throughout - see the note in
/// `mkcourse.rs` about why the precision is more than the tolerances need.
pub struct Course {
    pub x: Vec<f32>,
    pub y: Vec<f32>,
    pub z: Vec<f32>,
    pub yaw: Vec<f32>,
    pub tunnel: Vec<u8>,
    pub step: f32,
    pub length: f32,
    pub count: usize,
    pub shipped: usize,
    pub checksum: u32,
}

/// A point on the centreline.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sample {
    pub x: f32,
    pub y: f32,
    pub z: f32,
    pub yaw: f32,
}

/// The answer to "where on the road is this?".
#[derive(Clone, Copy, Debug, Default)]
pub struct Projection {
    /// Arc length of the nearest point.
    pub s: f32,
    /// Signed distance from the centreline; the sign is which side.
    pub lateral: f32,
    /// Straight-line distance to the nearest sample, before the along-track
    /// refinement. Used to notice a car that is nowhere near the road at all.
    pub gap: f32,
}

const MAGIC: &[u8; 8] = b"SYNXCRS1";
const HEADER: usize = 8 + 4 + 4 + 4 + 4;

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

#[inline]
fn f32_at(b: &[u8], off: usize) -> f32 {
    f32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

#[inline]
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// Shortest signed angle from `a` to `b`.
#[inline]
pub fn ang_diff(a: f32, b: f32) -> f32 {
    let mut d = (b - a) % (2.0 * PI);
    if d > PI {
        d -= 2.0 * PI;
    } else if d < -PI {
        d += 2.0 * PI;
    }
    d
}

impl Course {
    /// Parse the embedded asset.
    ///
    /// Every field is checked against the declared count before it is used,
    /// and the checksum is verified, because this is the one input to the
    /// server that can be wrong without anybody noticing until a validator
    /// starts refusing legitimate positions on one corner of one route.
    pub fn parse(bytes: &[u8]) -> Result<Course, String> {
        if bytes.len() < HEADER + 4 {
            return Err(format!("course asset is {} bytes, too short to be one", bytes.len()));
        }
        if &bytes[..8] != MAGIC {
            return Err("course asset does not start with SYNXCRS1".into());
        }
        let count = u32_at(bytes, 8) as usize;
        let step = f32_at(bytes, 12);
        let length = f32_at(bytes, 16);
        let shipped = u32_at(bytes, 20) as usize;

        let want = HEADER + count * 16 + count + 4;
        if bytes.len() != want {
            return Err(format!(
                "course asset is {} bytes; {count} samples needs {want}",
                bytes.len()
            ));
        }
        if count < 2 || step <= 0.0 || !step.is_finite() || !length.is_finite() {
            return Err("course asset header is not sane".into());
        }
        let stated = u32_at(bytes, bytes.len() - 4);
        let actual = fnv1a(&bytes[..bytes.len() - 4]);
        if stated != actual {
            return Err(format!("course asset checksum {actual:08x} does not match {stated:08x}"));
        }

        let mut c = Course {
            x: Vec::with_capacity(count),
            y: Vec::with_capacity(count),
            z: Vec::with_capacity(count),
            yaw: Vec::with_capacity(count),
            tunnel: Vec::with_capacity(count),
            step,
            length,
            count,
            shipped,
            checksum: actual,
        };
        for i in 0..count {
            let o = HEADER + i * 16;
            c.x.push(f32_at(bytes, o));
            c.y.push(f32_at(bytes, o + 4));
            c.z.push(f32_at(bytes, o + 8));
            c.yaw.push(f32_at(bytes, o + 12));
        }
        let t0 = HEADER + count * 16;
        c.tunnel.extend_from_slice(&bytes[t0..t0 + count]);
        Ok(c)
    }

    /// The course that ships with this build.
    pub fn embedded() -> Course {
        let bytes = include_bytes!("../assets/course.bin");
        match Course::parse(bytes) {
            Ok(c) => {
                info!(
                    samples = c.count,
                    step = c.step,
                    length_units = c.length,
                    length_km = c.length * 0.000_733,
                    shipped = c.shipped,
                    checksum = format!("{:08x}", c.checksum),
                    "course loaded"
                );
                c
            }
            // There is no sensible degraded mode: without the road there is no
            // validation, and a server that cannot validate is a server that
            // must not accept players.
            Err(e) => panic!("the embedded course asset is unusable: {e}"),
        }
    }

    /// Interpolated point and heading at arc length `s`.
    pub fn at(&self, s: f32) -> Sample {
        let f = (s / self.step).clamp(0.0, self.count as f32 - 1.001);
        let i = f as usize;
        let t = f - i as f32;
        let j = (self.count - 1).min(i + 1);
        Sample {
            x: self.x[i] + (self.x[j] - self.x[i]) * t,
            y: self.y[i] + (self.y[j] - self.y[i]) * t,
            z: self.z[i] + (self.z[j] - self.z[i]) * t,
            yaw: self.yaw[i] + ang_diff(self.yaw[i], self.yaw[j]) * t,
        }
    }

    /// Nearest point on the centreline, searched around `hint`.
    ///
    /// # The window, and the fallback
    ///
    /// The hint is the last known arc length, and a car cannot have moved more
    /// than about two units per millisecond, so a window of a few hundred
    /// samples covers anything a legitimate client can do between two packets.
    /// Searching the whole course would be twenty-nine thousand distance tests
    /// per packet per player, which at four players and thirty hertz is three
    /// and a half million a second for an answer a window gives exactly.
    ///
    /// But a hostile client is exactly the thing that WILL claim to be
    /// somewhere the window does not cover, and answering "the nearest point
    /// within 400 samples of where you were" would then report a plausible
    /// lateral for a car that is four kilometres off the road. So when the
    /// windowed best is not convincing - further from the centreline than any
    /// legal position can be - the search widens to the whole course. That is
    /// the slow path, it is only ever taken by a client that is about to be
    /// corrected anyway, and it is bounded by a token bucket upstream.
    pub fn project(&self, x: f32, z: f32, hint: f32) -> Projection {
        const WINDOW: isize = 420;
        let centre = ((hint / self.step) as isize).clamp(0, self.count as isize - 1);
        let lo = (centre - WINDOW).max(0) as usize;
        let hi = (centre + WINDOW).min(self.count as isize - 1) as usize;

        let (mut best, mut best_d2) = (lo, f32::INFINITY);
        for i in lo..=hi {
            let dx = x - self.x[i];
            let dz = z - self.z[i];
            let d2 = dx * dx + dz * dz;
            if d2 < best_d2 {
                best_d2 = d2;
                best = i;
            }
        }
        // Nothing legal is further than the widest corridor plus a margin; if
        // the window did not find anything closer than that, it looked in the
        // wrong place.
        if best_d2 > 220.0 * 220.0 {
            for i in 0..self.count {
                let dx = x - self.x[i];
                let dz = z - self.z[i];
                let d2 = dx * dx + dz * dz;
                if d2 < best_d2 {
                    best_d2 = d2;
                    best = i;
                }
            }
        }
        self.refine(x, z, best, best_d2.sqrt())
    }

    /// Turn a nearest-sample index into an arc length and a signed offset.
    ///
    /// The sample grid is six units apart, so taking the sample itself as the
    /// answer would quantise every arc length to six units and make the
    /// progress checks useless. The offset along the local heading refines it
    /// to the continuous value, and the offset across it is the lateral.
    fn refine(&self, x: f32, z: f32, i: usize, gap: f32) -> Projection {
        let yaw = self.yaw[i];
        let (sy, cy) = yaw.sin_cos();
        let dx = x - self.x[i];
        let dz = z - self.z[i];
        // forward is (sin yaw, cos yaw), right is (cos yaw, -sin yaw): the
        // solver's convention, and getting it wrong mirrors every lateral
        let along = dx * sy + dz * cy;
        let across = dx * cy - dz * sy;
        let s = (i as f32 * self.step + along).clamp(0.0, self.length);
        Projection { s, lateral: across, gap }
    }

    /// Is the road in a bore here? Used to relax the altitude check, since a
    /// tunnel roof and a tunnel floor are different heights of "on the road".
    pub fn tunnel_at(&self, s: f32) -> bool {
        let i = ((s / self.step) as usize).min(self.count - 1);
        self.tunnel[i] == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn course() -> Course {
        Course::parse(include_bytes!("../assets/course.bin")).expect("the shipped course parses")
    }

    #[test]
    fn the_shipped_asset_is_the_road_the_game_drives() {
        let c = course();
        // js/wasm.js declares COURSE_LENGTH = 175800 and the generator is
        // seeded, so both numbers are facts about the build rather than
        // measurements of it.
        assert_eq!(c.count, 29_300);
        assert!((c.length - 175_800.0).abs() < 1.0, "course is {} units", c.length);
        assert!((c.step - 6.0).abs() < 1e-6);
        assert_eq!(c.shipped, 4_494);
    }

    #[test]
    fn a_corrupt_asset_is_refused_rather_than_half_read() {
        let mut bytes = include_bytes!("../assets/course.bin").to_vec();
        let n = bytes.len();
        bytes[n / 2] ^= 0xff;
        assert!(Course::parse(&bytes).is_err(), "a flipped bit was accepted");

        assert!(Course::parse(b"").is_err());
        assert!(Course::parse(b"NOTSYNX_and_then_some_padding_bytes").is_err());

        let mut short = include_bytes!("../assets/course.bin").to_vec();
        short.truncate(4096);
        assert!(Course::parse(&short).is_err());
    }

    /// Projecting a point that is exactly on the centreline has to return that
    /// arc length and a lateral of zero. This is the test that catches a
    /// handedness error, which is otherwise invisible until every car on the
    /// left of the road is reported as being on the right.
    #[test]
    fn projecting_a_point_on_the_line_returns_it() {
        let c = course();
        for s in [60.0f32, 5_000.0, 55_000.0, 112_500.0, 150_000.0] {
            let p = c.at(s);
            let got = c.project(p.x, p.z, s);
            assert!((got.s - s).abs() < 3.0, "at {s} the projection came back {}", got.s);
            assert!(got.lateral.abs() < 0.5, "at {s} the lateral came out {}", got.lateral);
        }
    }

    /// ...and a point pushed sideways has to come back with that offset, with
    /// the sign the solver would have given it.
    #[test]
    fn the_lateral_has_the_right_sign_and_size() {
        let c = course();
        let s = 40_000.0f32;
        let p = c.at(s);
        let (sy, cy) = p.yaw.sin_cos();
        for offset in [-14.0f32, -3.0, 3.0, 14.0] {
            let x = p.x + cy * offset;
            let z = p.z - sy * offset;
            let got = c.project(x, z, s);
            assert!(
                (got.lateral - offset).abs() < 0.6,
                "offset {offset} projected to {}",
                got.lateral
            );
        }
    }

    /// A stale hint must not produce a confident wrong answer. This is the
    /// anti-cheat case: a client claiming to be a hundred kilometres from
    /// where it said it was last packet.
    #[test]
    fn a_hopeless_hint_widens_the_search() {
        let c = course();
        let target = 150_000.0f32;
        let p = c.at(target);
        let got = c.project(p.x, p.z, 500.0);
        assert!(
            (got.s - target).abs() < 20.0,
            "with a stale hint the projection landed at {} instead of {target}",
            got.s
        );
    }

    #[test]
    fn nothing_indexes_out_of_range_at_either_end() {
        let c = course();
        for s in [-1e9f32, -1.0, 0.0, c.length, c.length + 1e9] {
            let p = c.at(s);
            assert!(p.x.is_finite() && p.y.is_finite() && p.z.is_finite());
            let _ = c.tunnel_at(s.max(0.0).min(c.length));
        }
        let far = c.project(1e9, -1e9, 0.0);
        assert!(far.s.is_finite() && far.lateral.is_finite());
    }
}
