//! The seven routes, and the physical envelope a car on one of them has.
//!
//! # Where these numbers come from
//!
//! Every one of them is copied from somewhere in the game and is a fact about
//! it rather than a choice made here:
//!
//!   the arc lengths   `LEVELS` in `web/js/game.js`
//!   the corridors     `ROAD_HALF`/`DRIVE_HALF` in `crates/synx-core/src/track.rs`,
//!                     with Neon Horizon's override from its `LEVELS` entry
//!   the speeds        the engine constants in `crates/synx-core/src/vehicle.rs`
//!
//! They are duplicated rather than shared because the server must not depend on
//! the game core - see `course.rs` for why - so the risk of drift is real and
//! is answered the only honest way available: the test at the bottom of this
//! file asserts every route lies inside the course the server actually loaded,
//! and `tools/checkmaps.js` diffs this table against `web/js/game.js` in the
//! build. A number changed in one place and not the other fails the build.
//!
//! # Why the envelope matters
//!
//! The server does not simulate the car, so its entire notion of "that is not
//! possible" is this table. A ceiling that is too generous is a speed hack that
//! goes unnoticed; one that is too tight corrects an honest player on a
//! downhill. Both are stated precisely rather than padded, and the tolerance
//! that absorbs jitter is applied once, in `validate.rs`, where it can be seen.

use serde::Serialize;

/// Course-wide corridor, from `track.rs`. The barriers are at `outer_half`;
/// `drive_half` is where the tarmac stops and the surface penalty starts.
pub const ROAD_HALF: f32 = 20.0;
pub const DRIVE_HALF: f32 = 18.0;

/// The stock engine, from `vehicle.rs`: `TOP_SPEED = 290 km/h` in world units.
pub const TOP_SPEED: f32 = 290.0 / 3.6;
/// What boost multiplies the ceiling by. `BOOST_TOP`.
pub const BOOST_TOP: f32 = 1.34;
/// The Forge rebuild: `SWAP_TOP`, `SWAP_CAP`.
pub const SWAP_TOP: f32 = 88.0;
pub const SWAP_CAP: f32 = 122.0;
/// What the synchronised drive multiplies the ceiling by. `RACE_MODE_MULTIPLIER`.
pub const RACE_MODE_TOP: f32 = 1.5;
/// Hard reverse limit from the solver: `v_long` is clamped to this below zero.
pub const MAX_REVERSE: f32 = 18.0;

/// How many gates a route is cut into.
///
/// Twenty-four over a twelve-kilometre route puts one every five hundred
/// units, which is about six seconds at racing speed. Close enough that
/// skipping one is a shortcut worth catching; far enough apart that the check
/// is one comparison per packet rather than a search.
pub const CHECKPOINTS: u8 = 24;

/// Which car everybody in the room is driving.
///
/// The campaign hands the rebuilt engine out at the end of Chapter 6, which
/// means two players who have got different distances through the story would
/// otherwise arrive at the same start line in different cars. Multiplayer
/// therefore does not read the save at all: the room picks one ruleset and
/// everybody gets it, so a race is decided by driving.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
#[repr(u8)]
pub enum Ruleset {
    /// The street car. What Chapter 1 hands you.
    Stock = 0,
    /// The Forge rebuild, and the synchronised drive that came with it.
    Rebuilt = 1,
}

impl Ruleset {
    pub fn from_str(s: &str) -> Option<Ruleset> {
        match s {
            "stock" => Some(Ruleset::Stock),
            "rebuilt" => Some(Ruleset::Rebuilt),
            _ => None,
        }
    }

    /// The fastest a car under this ruleset can legally be going.
    ///
    /// This is `Vehicle::ceiling()` evaluated with every multiplier switched
    /// on at once. The solver clamps `v_long` to it every step, so it is a hard
    /// wall and not a soft target - which is what makes it usable as a test.
    pub fn ceiling(self) -> f32 {
        match self {
            // speed_cap is infinite on the stock engine, and race mode is not
            // available under this ruleset, so boost is the only multiplier
            Ruleset::Stock => TOP_SPEED * BOOST_TOP,
            Ruleset::Rebuilt => SWAP_CAP.min(SWAP_TOP * BOOST_TOP * RACE_MODE_TOP),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Ruleset::Stock => "STOCK",
            Ruleset::Rebuilt => "REBUILT",
        }
    }
}

/// One route.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Map {
    pub id: u8,
    pub name: &'static str,
    /// One line saying what the country is, for the map picker. Same text as
    /// `REGION_NOTE` in `web/js/freeroam.js`.
    pub note: &'static str,
    /// Arc length of the start line and of the finish gantry.
    pub from: f32,
    pub to: f32,
    /// Half the driveable width and half the width to the barriers.
    pub drive_half: f32,
    pub road_half: f32,
}

impl Map {
    pub fn length(&self) -> f32 {
        self.to - self.from
    }

    pub fn km(&self) -> f32 {
        self.length() * 0.000_733
    }

    /// Arc length of gate `i`, `0..=CHECKPOINTS`. Gate 0 is the start line and
    /// gate `CHECKPOINTS` is the finish.
    pub fn gate(&self, i: u8) -> f32 {
        let t = (i.min(CHECKPOINTS) as f32) / CHECKPOINTS as f32;
        self.from + self.length() * t
    }

    /// How many gates an arc length has legitimately passed.
    pub fn gates_passed(&self, s: f32) -> u8 {
        if s <= self.from {
            return 0;
        }
        let t = (s - self.from) / self.length();
        ((t * CHECKPOINTS as f32).floor() as i32).clamp(0, CHECKPOINTS as i32) as u8
    }

    /// Where seat `slot` starts.
    ///
    /// Staggered rather than in a line: four cars abreast on a thirty-six
    /// metre corridor leaves no room to move on the first corner, and a grid
    /// is what a racing start looks like anyway. The inside of the road is the
    /// front, which is the only asymmetry, and the room rotates who gets it
    /// between races.
    pub fn grid(&self, slot: u8, of: u8) -> (f32, f32) {
        let lanes = [-6.5f32, 6.5, -6.5, 6.5];
        let rows = [0.0f32, 0.0, -11.0, -11.0];
        let i = (slot as usize).min(3);
        let _ = of;
        (self.from + rows[i], lanes[i] * (self.drive_half / DRIVE_HALF))
    }
}

/// The routes, in the order the game lists them.
pub const MAPS: [Map; 7] = [
    Map {
        id: 0,
        name: "VECTOR RUN",
        note: "SEAWALL NEON // COAST AT DUSK",
        from: 60.0,
        to: 13_000.0,
        drive_half: DRIVE_HALF,
        road_half: ROAD_HALF,
    },
    Map {
        id: 1,
        name: "THE SPINE",
        note: "FREIGHT RAMPS // CANYON TUNNELS",
        from: 13_000.0,
        to: 32_000.0,
        drive_half: DRIVE_HALF,
        road_half: ROAD_HALF,
    },
    Map {
        id: 2,
        name: "MIRAGE CIRCUIT",
        note: "MESA TERRACES // OPEN SKY",
        from: 32_000.0,
        to: 54_000.0,
        drive_half: DRIVE_HALF,
        road_half: ROAD_HALF,
    },
    Map {
        id: 3,
        name: "SUNSET ZERO",
        note: "MIDNIGHT CITY // WET TARMAC",
        from: 54_000.0,
        to: 79_900.0,
        drive_half: DRIVE_HALF,
        road_half: ROAD_HALF,
    },
    Map {
        id: 4,
        name: "ASHFALL ZERO",
        note: "DEAD DISTRICT // ASH AND LAVA",
        from: 79_900.0,
        to: 111_500.0,
        drive_half: DRIVE_HALF,
        road_half: ROAD_HALF,
    },
    Map {
        id: 5,
        name: "AURORA FORGE",
        note: "CLOSED COURSE // PRODUCTION HALL",
        from: 112_080.0,
        to: 131_300.0,
        drive_half: DRIVE_HALF,
        road_half: ROAD_HALF,
    },
    Map {
        id: 6,
        name: "NEON HORIZON",
        note: "ELEVATED DECK // MEGACITY SPAN",
        from: 132_070.0,
        to: 173_000.0,
        // the finale's deck is sixty-four units across where the rest of the
        // road is forty; see the `roadHalf`/`driveHalf` on its LEVELS entry
        drive_half: 30.0,
        road_half: 32.0,
    },
];

pub fn map(id: u8) -> Option<&'static Map> {
    MAPS.get(id as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::course::Course;

    #[test]
    fn every_route_lies_on_the_course_the_server_loaded() {
        let c = Course::parse(include_bytes!("../assets/course.bin")).unwrap();
        for m in MAPS.iter() {
            assert!(m.from >= 0.0, "{} starts before the course", m.name);
            assert!(m.to <= c.length, "{} ends past the end of the road", m.name);
            assert!(m.to > m.from, "{} is not a route", m.name);
            assert!(m.km() > 8.0, "{} is only {:.1} km", m.name, m.km());
        }
    }

    #[test]
    fn the_routes_are_in_order_and_do_not_overlap() {
        for w in MAPS.windows(2) {
            assert!(w[1].from >= w[0].to, "{} overlaps {}", w[1].name, w[0].name);
        }
    }

    #[test]
    fn gates_are_monotonic_and_bracket_the_route() {
        for m in MAPS.iter() {
            assert!((m.gate(0) - m.from).abs() < 0.01);
            assert!((m.gate(CHECKPOINTS) - m.to).abs() < 0.01);
            for i in 1..=CHECKPOINTS {
                assert!(m.gate(i) > m.gate(i - 1));
            }
            assert_eq!(m.gates_passed(m.from - 1.0), 0);
            assert_eq!(m.gates_passed(m.from), 0);
            assert_eq!(m.gates_passed(m.to), CHECKPOINTS);
            assert_eq!(m.gates_passed(m.to + 5_000.0), CHECKPOINTS);
            let mid = m.gate(12) + 1.0;
            assert_eq!(m.gates_passed(mid), 12);
        }
    }

    #[test]
    fn the_grid_fits_inside_the_barriers() {
        for m in MAPS.iter() {
            for slot in 0..4u8 {
                let (s, lat) = m.grid(slot, 4);
                assert!(lat.abs() < m.drive_half, "{} slot {slot} starts off the road", m.name);
                assert!(s > m.from - 20.0 && s < m.to, "{} slot {slot} starts off the route", m.name);
            }
        }
    }

    /// The ceilings are the whole anti-cheat model for speed, so they are
    /// asserted against the numbers in the solver rather than left implicit.
    #[test]
    fn the_ceilings_match_the_solver() {
        // 290 km/h * 1.34 = 388.6 km/h = 107.9 world units/s
        assert!((Ruleset::Stock.ceiling() - 107.94).abs() < 0.05);
        // the rebuild is capped at 122 u/s, which the solver tests as 200 mph
        assert!((Ruleset::Rebuilt.ceiling() - 122.0).abs() < 0.001);
        assert!(Ruleset::Rebuilt.ceiling() > Ruleset::Stock.ceiling());
    }
}
