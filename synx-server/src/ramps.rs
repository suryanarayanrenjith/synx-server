//! The stunt course, as the validator has to see it.
//!
//! # WHY THE SERVER HAS TO KNOW ABOUT RAMPS AT ALL
//!
//! The altitude test in `validate.rs` asks whether a car is within a few units
//! of the road under it, and on ninety-nine kilometres of this course that is
//! exactly the right question. On the other one it is the wrong one: the game
//! puts launch ramps on every route, a crested ramp over the blocked bore on
//! MIRAGE CIRCUIT and a deck eighteen units up across the broken roof of the
//! AURORA FORGE hall - and a car on any of those is legitimately well above
//! the centreline the server measures from.
//!
//! Measured in the game itself, with the multiplayer car (stock engine, boost
//! held, flat out over each lip), the peak height of the car above the road
//! under it was:
//!
//! ```text
//!   SEAWALL LAUNCH   5.0      SKYLINE LAUNCH  8.7      FIRST LAUNCH   6.8
//!   SPINE LAUNCH     6.9      ASHFALL LAUNCH 10.8      SECOND LAUNCH 14.0
//!   THE BLOCKED BORE 13.3     THE BROKEN ROOF 19.1     LONG LAUNCH   13.8
//! ```
//!
//! against a tolerance of eight (sixteen in a tunnel). So five of the nine
//! were refused as `Altitude` in mid-air - the car snapped back onto the road
//! under it, and its owner read LINK CORRECTION on the best jump of the race -
//! and the roof deck, a kilometre long, refused every packet for twelve
//! seconds, which is a strike budget spent and a player removed from the race
//! for driving the route.
//!
//! # WHAT IS ALLOWED, AND WHY IT IS STILL A WALL
//!
//! Inside a ramp's window the ceiling is not a number, it is the highest the
//! solver can put a car, worked out the way the solver works it out
//! (`Ramp::height_at` and `update_air` in `crates/synx-core/src/vehicle.rs`):
//!
//!   * a LAUNCH ramp is the quadratic `h * u^2`, so its lip slope is `2h/len`
//!     and a car crossing it at `v` leaves with `v * 2h/len` upwards;
//!   * a CRESTED ramp leaves off its straight crest, `(lip - h)/crest`;
//!   * a ramp with a DESCENT is driven back down and launches nothing;
//!   * in the air the car falls at `AIR_G`, so the rise is `v_up^2 / 2 AIR_G`.
//!
//! The apex is the top of the structure, plus that rise at the route's speed
//! ceiling, plus the body's ride height and a little for its springs - plus
//! however far the road has fallen away since the lip, because the car is no
//! lower in the world for that. A car above it did not come out of the
//! solver. The window closes once a flight launched at the ceiling must have
//! landed. Below the road nothing changes at all.
//!
//! The table is the game's `COURSE_RAMPS` (`js/game.js`), mirrored rather than
//! shared because the two repositories meet only at a URL. `tools/check.py
//! ramps` in the game repository reads both and fails if they disagree.

use crate::course::Course;

/// The solver's gravity in the air, `AIR_G`, in world units per second
/// squared. Not 9.81: see the note on it in `vehicle.rs`.
const AIR_G: f32 = 27.0;

/// The body's ride height over the surface it is sitting on - the car's
/// reported `y` is the body, not the tyres - and the most its springs add on
/// top as they unload off a lip (`heave_v += 1.6` at the launch).
const RIDE: f32 = 1.05;
const HEAVE: f32 = 0.6;

/// How long after the lip a flight is still allowed to be in the air, beyond
/// what the bound itself works out, in world units of arc length. Covers the
/// car that comes off the lip slower than the ceiling and so is lower - and
/// still descending - further along than the fastest flight would be.
const LANDING_RUNOUT: f32 = 120.0;

/// One structure on the course. Arc lengths are the course's own.
#[derive(Clone, Copy, Debug)]
pub struct Ramp {
    pub id: &'static str,
    /// Where the climb starts.
    pub foot: f32,
    /// Where the structure ends: the lip a car leaves, or - for the roof, which
    /// a car drives back down - where its descent reaches the road again.
    pub end: f32,
    /// Its highest point above the road under it.
    pub top: f32,
    /// The slope of the surface a car leaves it from, rise over run: what
    /// decides how hard it throws a car upwards. Zero for a structure that is
    /// driven back down rather than left.
    pub slope: f32,
    /// Where a car leaves it, if it leaves it at all.
    pub lip: f32,
}

/// The game's `COURSE_RAMPS`, in course order. See the module note.
///
/// For a plain launch `s` is the lip, `len` the incline and `h` the lip's
/// height, and the lip slope is `2h/len`. THE BLOCKED BORE climbs 10.4 over
/// 106 and then runs a straight crest of forty units up to `lip` 12, which it
/// leaves at 1.6/40. THE BROKEN ROOF climbs 18 over 140 to a deck that runs to
/// 129,900 and is driven back down to the floor at 130,060 - no launch.
pub const RAMPS: [Ramp; 9] = [
    Ramp { id: "l1_seawall", foot: 1120.0 - 54.0, end: 1120.0, top: 2.8, slope: 2.0 * 2.8 / 54.0, lip: 1120.0 },
    Ramp { id: "l2_spine", foot: 23_900.0 - 46.0, end: 23_900.0, top: 3.4, slope: 2.0 * 3.4 / 46.0, lip: 23_900.0 },
    Ramp { id: "l3_bore", foot: 40_766.0 - 40.0 - 106.0, end: 40_766.0, top: 12.0, slope: (12.0 - 10.4) / 40.0, lip: 40_766.0 },
    Ramp { id: "l4_skyline", foot: 73_900.0 - 40.0, end: 73_900.0, top: 3.9, slope: 2.0 * 3.9 / 40.0, lip: 73_900.0 },
    Ramp { id: "l5_ashfall", foot: 94_900.0 - 36.0, end: 94_900.0, top: 4.2, slope: 2.0 * 4.2 / 36.0, lip: 94_900.0 },
    Ramp { id: "l6_roof", foot: 128_760.0, end: 130_060.0, top: 18.0, slope: 0.0, lip: 129_900.0 },
    Ramp { id: "jump_a", foot: 164_620.0 - 46.0, end: 164_620.0, top: 3.4, slope: 2.0 * 3.4 / 46.0, lip: 164_620.0 },
    Ramp { id: "jump_b", foot: 165_060.0 - 38.0, end: 165_060.0, top: 4.1, slope: 2.0 * 4.1 / 38.0, lip: 165_060.0 },
    Ramp { id: "jump_c", foot: 165_500.0 - 32.0, end: 165_500.0, top: 4.8, slope: 2.0 * 4.8 / 32.0, lip: 165_500.0 },
];

impl Ramp {
    /// The upward speed a car leaves the lip with at `v_max`. The solver reads
    /// it back off the profile - `(air_y - prev) / dt` - so it is the along-
    /// track speed times the slope, with no trigonometry in it.
    fn launch(&self, v_max: f32) -> f32 {
        v_max * self.slope
    }

    /// How much a launch at `v_max` lifts a car above the structure's top.
    fn rise(&self, v_max: f32) -> f32 {
        let up = self.launch(v_max);
        up * up / (2.0 * AIR_G)
    }

    /// The highest a car can be above the road at the lip, body included.
    pub fn apex(&self, v_max: f32) -> f32 {
        self.top + RIDE + HEAVE + self.rise(v_max)
    }

    /// Where the window closes: the end of the structure plus the longest a
    /// flight launched at `v_max` can stay up - the climb to the apex and the
    /// fall from it - plus a margin for slower flights landing later.
    pub fn window_end(&self, v_max: f32) -> f32 {
        let t_up = self.launch(v_max) / AIR_G;
        let t_down = (2.0 * self.apex(v_max) / AIR_G).sqrt();
        self.end + v_max * (t_up + t_down) + LANDING_RUNOUT
    }
}

/// The extra headroom a car at arc length `s` has above the road, on top of
/// the ordinary tolerance, because a structure is there. Zero away from every
/// ramp, which is nearly everywhere.
///
/// `v_max` is the route's speed ceiling; `course` supplies the road heights
/// for the fall-away term.
pub fn headroom(course: &Course, s: f32, v_max: f32) -> f32 {
    let mut best = 0.0f32;
    for r in RAMPS.iter() {
        if s < r.foot - 10.0 || s > r.window_end(v_max) {
            continue;
        }
        // However far the road has dropped since the lip: the car is no lower
        // in the world for it, so it is that much higher above the road.
        let fall = (course.at(r.lip).y - course.at(s).y).max(0.0);
        best = best.max(r.apex(v_max) + fall);
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    fn course() -> Course {
        Course::parse(include_bytes!("../assets/course.bin")).unwrap()
    }

    /// The bound is a physical one, and it has to sit ABOVE every flight the
    /// game actually produced - the table in the module note, measured with
    /// the multiplayer car at the ceiling. If the solver ever throws a car
    /// higher than this, a legitimate player is being refused.
    #[test]
    fn every_measured_flight_is_under_its_bound() {
        let c = course();
        let v = crate::maps::Ruleset::Stock.ceiling();
        // id, arc length of the measured peak, its height above the road there
        let measured = [
            ("l1_seawall", 1140.0f32, 4.99f32),
            ("l2_spine", 23_932.0, 6.86),
            ("l3_bore", 40_776.0, 13.28),
            ("l4_skyline", 73_940.0, 8.74),
            ("l5_ashfall", 94_949.0, 10.80),
            ("l6_roof", 128_901.0, 19.05),
            ("jump_a", 164_651.0, 6.79),
            ("jump_b", 165_145.0, 14.04),
            ("jump_c", 165_557.0, 13.75),
        ];
        let mut worst = f32::INFINITY;
        let mut report = String::new();
        for (id, s, h) in measured {
            let room = headroom(&c, s, v);
            worst = worst.min(room - h);
            report.push_str(&format!("\n  {id:<11} measured {h:>5.2}  bound {room:>5.2}  margin {:>+6.2}", room - h));
        }
        // The bound on its own - the validator stacks the ordinary tolerance
        // of eight on top of it, and this test does not lean on that.
        assert!(worst >= 0.0, "a flight cleared its bound:{report}");
        eprintln!("ramp headroom against the game's own flights:{report}");
    }

    /// ...and it is a bound, not a licence. Where the structure throws
    /// nothing - the crest of the bore, the roof deck - it is the structure's
    /// own height to within the springs, so the allowance is not a blanket
    /// "anything goes near a ramp"; and no ramp anywhere allows more than the
    /// steepest kicker on the course can throw.
    #[test]
    fn the_bound_is_tight_where_nothing_is_thrown() {
        let v = crate::maps::Ruleset::Stock.ceiling();
        let roof = RAMPS.iter().find(|r| r.id == "l6_roof").unwrap();
        assert!((roof.apex(v) - 19.05).abs() < 1.0, "the roof predicted {:.2}", roof.apex(v));
        let bore = RAMPS.iter().find(|r| r.id == "l3_bore").unwrap();
        assert!((bore.apex(v) - 13.28).abs() < 1.5, "the bore predicted {:.2}", bore.apex(v));
        for r in RAMPS.iter() {
            assert!(r.apex(v) < 30.0, "{} allows {:.1} above the road", r.id, r.apex(v));
        }
    }

    /// Away from every structure there is no headroom at all: the altitude
    /// test is exactly what it always was on the rest of the course.
    #[test]
    fn no_headroom_away_from_the_ramps() {
        let c = course();
        let v = crate::maps::Ruleset::Stock.ceiling();
        for s in [500.0f32, 10_000.0, 30_000.0, 60_000.0, 100_000.0, 120_000.0, 150_000.0, 170_000.0] {
            assert_eq!(headroom(&c, s, v), 0.0, "headroom at {s}");
        }
        // and the window does close after the lip
        let sea = &RAMPS[0];
        assert_eq!(headroom(&c, sea.window_end(v) + 1.0, v), 0.0);
    }

    #[test]
    fn the_table_is_in_course_order_and_well_formed() {
        for w in RAMPS.windows(2) {
            assert!(w[1].foot > w[0].end, "{} overlaps {}", w[1].id, w[0].id);
        }
        for r in RAMPS.iter() {
            assert!(r.foot < r.lip && r.lip <= r.end, "{} is not a structure", r.id);
            assert!(r.top > 0.0 && r.slope >= 0.0, "{} has no height", r.id);
        }
    }
}
