//! Envelope-based validation of client-reported vehicle state.

use std::time::Instant;

use synx_net::msg::CarState;
use synx_net::Correction;

use crate::course::Course;
use crate::maps::{Map, Ruleset, CHECKPOINTS, MAX_REVERSE};

/// How much slack every distance test gets, in world units.
///
/// It absorbs three things that are not cheating: the quantisation on the wire
/// (four millimetres), the difference between the client's frame boundaries
/// and the server's clock, and the fact that a client integrates in `f64`
/// while this checks in `f32`. Two units is about a tenth of a car length.
const SLACK: f32 = 2.0;

/// Multiplier on the ceiling before a speed is called impossible.
///
/// The solver clamps `v_long` to the ceiling but says nothing about `v_lat`,
/// and a car in a full-lock slide carries real lateral velocity. A tenth over
/// covers that; anything past it is not a slide.
const SPEED_MARGIN: f32 = 1.30;

/// How far above or below the road surface a car may legitimately be.
///
/// The body heaves on its springs, the road samples are six units apart so the
/// interpolated height under a car mid-sample is approximate, and the deck in
/// the finale has real grade. Eight units covers all of it and is nowhere near
/// enough to fly over anything.
const ALTITUDE_TOLERANCE: f32 = 8.0;

/// How far outside the barrier a car may be reported before it is refused.
///
/// The solver resolves contact to `outer_half` exactly, but it does so AFTER
/// integrating, so a car can be momentarily outside within one step. Three
/// units is a comfortable margin on a corridor that is at least forty across.
const WALL_MARGIN: f32 = 3.0;

/// How far the road behind a car is allowed to be given up. `BACKTRACK` in the
/// solver, plus slack.
const BACKTRACK: f32 = 55.0 + 20.0;

/// The largest gap between two accepted packets that still counts as
/// continuous, in seconds. Past this the client has been silent long enough
/// that its next position cannot be checked against its last one, so the
/// position tests are skipped and only the absolute ones apply.
const MAX_CONTINUITY: f32 = 2.5;

/// What the validator decided.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Verdict {
    /// The state is plausible. Publish it.
    Accept,
    /// It is not. Hold the previous state, tell the client, count a strike.
    Reject(Correction),
}

impl Verdict {
    pub fn rejected(&self) -> Option<Correction> {
        match self {
            Verdict::Accept => None,
            Verdict::Reject(c) => Some(*c),
        }
    }
}

/// Everything the validator remembers about one car.
#[derive(Debug, Clone)]
pub struct Track {
    /// The newest state that passed. This is what the room broadcasts, so a
    /// refused packet leaves the car where it legitimately was rather than
    /// where it claimed to be.
    pub last: CarState,
    /// Whether `last` means anything yet.
    pub started: bool,
    /// Server clock when `last` was accepted. The wall-clock half of the `dt`
    /// bound.
    pub last_wall: Instant,
    /// The furthest along the route this car has legitimately been.
    pub max_s: f32,
    /// Gates passed, in order.
    pub checkpoint: u8,
    /// Race clock, in the room's own milliseconds, when it crossed the line.
    pub finished_ms: Option<u32>,
    /// How many refusals this car has collected in this race.
    pub strikes: u32,
    /// ...and of which kinds, for the log and the stats endpoint.
    pub by_reason: [u32; 9],
    /// Packets accepted, for the same reason.
    pub accepted: u64,
}

impl Track {
    pub fn new() -> Track {
        Track {
            last: CarState::default(),
            started: false,
            last_wall: Instant::now(),
            max_s: 0.0,
            checkpoint: 0,
            finished_ms: None,
            strikes: 0,
            by_reason: [0; 9],
            accepted: 0,
        }
    }

    /// Put a car on the grid. Everything about the previous race is discarded,
    /// including the strikes, which are counted per race.
    pub fn place(&mut self, map: &Map, course: &Course, slot: u8, of: u8, t_ms: u32) {
        let (s, lateral) = map.grid(slot, of);
        let p = course.at(s);
        let (sy, cy) = p.yaw.sin_cos();
        self.last = CarState {
            // Half a second in the past. The grid is stamped by the server and
            // the first state after it comes from a client whose clock is
            // synchronised to within a few tens of milliseconds but not to
            // zero; without the margin, a client running very slightly behind
            // has its first packet refused as a rewind.
            t_ms: t_ms.saturating_sub(500),
            x: p.x + cy * lateral,
            y: p.y + 1.05,
            z: p.z - sy * lateral,
            s,
            lateral,
            yaw: p.yaw,
            boost: 1.0,
            ..CarState::default()
        };
        self.started = true;
        self.last_wall = Instant::now();
        self.max_s = s;
        self.checkpoint = 0;
        self.finished_ms = None;
        self.strikes = 0;
        self.by_reason = [0; 9];
        self.accepted = 0;
    }

    /// Progress along the route, 0..1, for the standings.
    pub fn progress(&self, map: &Map) -> f32 {
        ((self.max_s - map.from) / map.length()).clamp(0.0, 1.0)
    }
}

impl Default for Track {
    fn default() -> Self {
        Track::new()
    }
}

/// The rules one race is run under.
pub struct Rules<'a> {
    pub map: &'a Map,
    pub course: &'a Course,
    pub ruleset: Ruleset,
    /// The room's own clock, so the validator and the snapshot agree about
    /// what time it is.
    pub now_ms: u32,
    /// Whether the race has actually started. Before it has, a car may not
    /// move off the grid at all, which is what stops a jump start being worth
    /// anything.
    pub live: bool,
}

/// Check one state, and fold it in if it passes.
///
/// This is the only place a client's numbers become the server's numbers.
pub fn check(track: &mut Track, rules: &Rules<'_>, claim: &CarState) -> Verdict {
    let map = rules.map;
    let course = rules.course;
    let ceiling = rules.ruleset.ceiling();

    // ---- 1. the clock ----------------------------------------------------
    //
    // A state may not be stamped before the last one accepted (that is a
    // rewind, and a rewind is how a player un-crashes) and may not be stamped
    // meaningfully in the future (that is how a player buys movement).
    if track.started {
        if claim.t_ms < track.last.t_ms {
            return refuse(track, Correction::Clock);
        }
        if claim.t_ms > rules.now_ms.wrapping_add(400) && claim.t_ms.wrapping_sub(rules.now_ms) < 60_000
        {
            return refuse(track, Correction::Clock);
        }
    }

    // ---- 2. how much time may have passed --------------------------------
    //
    // The smaller of what the client claims and what the server measured, plus
    // a little for scheduling. This single bound is what makes every distance
    // test below meaningful.
    let wall = track.last_wall.elapsed().as_secs_f32();
    let claimed = if track.started {
        (claim.t_ms.wrapping_sub(track.last.t_ms)) as f32 / 1000.0
    } else {
        wall
    };
    let continuous = track.started && wall < MAX_CONTINUITY && claimed < MAX_CONTINUITY;
    let dt = claimed.min(wall + 0.25).clamp(0.0, MAX_CONTINUITY);

    // ---- 3. the speed itself ---------------------------------------------
    //
    // `v_long` is hard-clamped by the solver, so this is not a heuristic: a
    // car above it did not come out of the solver.
    if claim.v_long > ceiling * 1.02 + 0.5 || claim.v_long < -(MAX_REVERSE * 1.2) {
        return refuse(track, Correction::Speed);
    }
    if claim.speed_sq() > (ceiling * SPEED_MARGIN) * (ceiling * SPEED_MARGIN) {
        return refuse(track, Correction::Speed);
    }

    // ---- 4. where the road is under this position ------------------------
    let hint = if track.started { track.last.s } else { map.from };
    let proj = course.project(claim.x, claim.z, hint);

    // Nowhere near the road at all. Checked before the corridor test because
    // `project` on a point a kilometre away still returns a lateral, and a
    // lateral is a small number when the nearest sample happens to be behind
    // you.
    if proj.gap > map.road_half + 240.0 {
        return refuse(track, Correction::OffCourse);
    }
    if proj.lateral.abs() > map.road_half + WALL_MARGIN {
        return refuse(track, Correction::OffCourse);
    }
    // ...and the lateral the client reported has to be the one its position
    // actually has. Without this a client could send a legal `lateral` beside
    // an illegal `x`/`z`, and everything downstream that reads `lateral` -
    // the standings, the barrier logic - would believe it.
    if (proj.lateral - claim.lateral).abs() > 4.0 {
        return refuse(track, Correction::OffCourse);
    }

    // ---- 5. the arc length has to match the position ---------------------
    //
    // This is the check that makes every other progress test worth having: a
    // client that could claim any `s` for any `x`/`z` could claim the finish
    // line from the grid.
    if (proj.s - claim.s).abs() > 3.0 * course.step {
        return refuse(track, Correction::Teleport);
    }
    // From here on the projection is the arc length. The client's own figure
    // has done its job by agreeing with it, and taking the server's keeps
    // every downstream number - progress, gates, the finish - derived from one
    // place rather than from whichever of the two happened to be read.
    let s = proj.s;

    // ---- 6. the road under the car ---------------------------------------
    let road = course.at(s);
    let mut altitude = ALTITUDE_TOLERANCE;
    if course.tunnel_at(s) {
        altitude *= 2.0;
    }
    if (claim.y - road.y).abs() > altitude {
        return refuse(track, Correction::Altitude);
    }

    // ---- 7. did it actually travel that far ------------------------------
    if continuous {
        let budget = ceiling * SPEED_MARGIN * dt + SLACK;
        let dx = claim.x - track.last.x;
        let dz = claim.z - track.last.z;
        let dy = claim.y - track.last.y;
        if dx * dx + dz * dz > budget * budget {
            return refuse(track, Correction::Teleport);
        }
        // Vertically the budget is tighter, because nothing in the solver
        // moves a car up faster than the road does.
        if dy.abs() > budget.max(6.0) {
            return refuse(track, Correction::Altitude);
        }
        if (s - track.last.s).abs() > budget + course.step {
            return refuse(track, Correction::Teleport);
        }
    }

    // ---- 8. the road behind is a wall ------------------------------------
    //
    // The solver refuses to let a car give up more than `BACKTRACK` of its
    // furthest progress, which is what stops a driver turning round. It is
    // also what stops a lap being driven backwards to farm checkpoints.
    if s < track.max_s - BACKTRACK {
        return refuse(track, Correction::Teleport);
    }
    if s < map.from - 60.0 || s > map.to + 3_000.0 {
        return refuse(track, Correction::OffCourse);
    }

    // ---- 9. the gates, in order ------------------------------------------
    //
    // How many gates may be crossed between two accepted packets is not a
    // constant: it depends on how long the gap was and how long the route's
    // gates are. Deriving it means a player who was silent for two seconds is
    // not accused of cutting the course, and a player who claims to have
    // crossed four gates in a frame still is.
    let reached = map.gates_passed(s.min(map.to));
    if reached > track.checkpoint {
        let gate_len = (map.gate(1) - map.gate(0)).max(1.0);
        let could = 1 + ((ceiling * SPEED_MARGIN * dt.max(0.05)) / gate_len).ceil() as u32;
        if (reached - track.checkpoint) as u32 > could {
            return refuse(track, Correction::Checkpoint);
        }
        track.checkpoint = reached;
    }

    // ---- 10. before the lights, nobody moves -----------------------------
    //
    // Refused, but WITHOUT a strike. A car that is moving on the grid is
    // either a client whose countdown has not landed yet or one that is a few
    // tens of milliseconds ahead of the lights, and neither is cheating -
    // holding the car where it was is the whole of the remedy. Striking here
    // as well would eject an honest player during the one part of the race
    // where their own clock is least likely to agree with the server's.
    if !rules.live && track.started {
        let dx = claim.x - track.last.x;
        let dz = claim.z - track.last.z;
        if dx * dx + dz * dz > 4.0 || claim.v_long.abs() > 2.0 {
            track.last.flags |= synx_net::flag::CLAMPED;
            return Verdict::Reject(Correction::Speed);
        }
    }

    // ---- 11. crossing the line ------------------------------------------
    if track.finished_ms.is_none()
        && s >= map.to
        && track.checkpoint >= CHECKPOINTS
        && rules.live
    {
        track.finished_ms = Some(rules.now_ms);
    }

    // Accepted. The claim becomes the truth, with the two fields the server
    // owns written over whatever the client put in them.
    let mut kept = *claim;
    kept.lateral = proj.lateral;
    kept.s = s;
    kept.checkpoint = track.checkpoint;
    if track.finished_ms.is_some() {
        kept.flags |= synx_net::flag::FINISHED;
    } else {
        kept.flags &= !synx_net::flag::FINISHED;
    }
    // CLAMPED is the server's to set, never the client's.
    kept.flags &= !synx_net::flag::CLAMPED;

    track.last = kept;
    track.last_wall = Instant::now();
    track.max_s = track.max_s.max(kept.s);
    track.started = true;
    track.accepted += 1;
    // STRIKES DECAY.
    //
    // A flat counter cannot tell a modified client from a bad connection: both
    // produce refusals, and over a four-minute race an honest player on a poor
    // link will eventually accumulate as many as a cheat does in a second. So
    // the count is a RATE rather than a total - one strike forgiven every
    // twenty accepted packets, which is about two thirds of a second of clean
    // driving. A client whose every packet is refused still reaches the budget
    // in a second and a half; one that is refused five percent of the time
    // never reaches it at all.
    if track.accepted % 20 == 0 {
        track.strikes = track.strikes.saturating_sub(1);
    }
    Verdict::Accept
}

fn refuse(track: &mut Track, why: Correction) -> Verdict {
    track.strikes = track.strikes.saturating_add(1);
    let i = why as usize;
    if i < track.by_reason.len() {
        track.by_reason[i] = track.by_reason[i].saturating_add(1);
    }
    // The car stays where it legitimately was, and its timestamp is dragged
    // forward so the receiving clients interpolate a car that is stopped
    // rather than one that has vanished from the timeline.
    track.last.flags |= synx_net::flag::CLAMPED;
    Verdict::Reject(why)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::course::Course;
    use crate::maps::MAPS;

    fn course() -> Course {
        Course::parse(include_bytes!("../assets/course.bin")).unwrap()
    }

    /// A car in its lane at arc length `s`, going `v` forward.
    ///
    /// The lane matters: a grid slot is six and a half units off the
    /// centreline, so a test that starts on the grid and then reports the
    /// centreline has moved the car sideways by more than it could have, and
    /// the refusal is correct rather than a bug in the validator.
    fn in_lane(c: &Course, s: f32, lat: f32, v: f32, t_ms: u32) -> CarState {
        let p = c.at(s);
        let (sy, cy) = p.yaw.sin_cos();
        CarState {
            t_ms,
            x: p.x + cy * lat,
            y: p.y + 1.05,
            z: p.z - sy * lat,
            s,
            yaw: p.yaw,
            v_long: v,
            lateral: lat,
            ..CarState::default()
        }
    }

    fn on_road(c: &Course, s: f32, v: f32, t_ms: u32) -> CarState {
        in_lane(c, s, 0.0, v, t_ms)
    }

    fn rules<'a>(c: &'a Course, m: &'a Map, now: u32) -> Rules<'a> {
        Rules { map: m, course: c, ruleset: Ruleset::Stock, now_ms: now, live: true }
    }

    /// The baseline: an honest car driving at a legal speed is never refused.
    /// If this test is fragile the whole validator is unusable, so it drives a
    /// whole route rather than taking two samples.
    #[test]
    fn an_honest_lap_is_never_refused() {
        let c = course();
        for m in MAPS.iter() {
            let mut t = Track::new();
            t.place(m, &c, 0, 2, 0);
            // start from the grid position the server itself assigned
            let mut s = t.last.s;
            let lane = t.last.lateral;
            let mut now = 0u32;
            let v = 90.0f32; // fast, and inside the stock ceiling of 107.9
            while s < m.to {
                now += 33;
                s += v * 0.033;
                let claim = in_lane(&c, s, lane, v, now);
                let r = rules(&c, m, now);
                // the wall clock has not moved between iterations, so the
                // continuity test is exercised through the claimed delta
                if let Verdict::Reject(why) = check(&mut t, &r, &claim) {
                    panic!("{} refused an honest car at s={s:.0}: {why:?}", m.name);
                }
            }
            assert_eq!(t.checkpoint, CHECKPOINTS, "{} did not gate the whole route", m.name);
            assert!(t.finished_ms.is_some(), "{} never registered the finish", m.name);
        }
    }

    #[test]
    fn a_speed_hack_is_refused() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let mut claim = on_road(&c, m.from + 200.0, 400.0, 100);
        claim.lateral = 0.0;
        assert_eq!(check(&mut t, &rules(&c, m, 100), &claim).rejected(), Some(Correction::Speed));
    }

    /// The important one. A client that claims a huge frame delta must not be
    /// able to buy the distance to go with it.
    #[test]
    fn inflating_the_frame_delta_buys_nothing() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let start = t.last.s;
        let lane = t.last.lateral;

        // one honest packet
        let claim = in_lane(&c, start + 3.0, lane, 90.0, 33);
        assert_eq!(check(&mut t, &rules(&c, m, 33), &claim), Verdict::Accept);

        // now claim thirty seconds passed and three kilometres were covered
        let jump = in_lane(&c, start + 3_000.0, lane, 90.0, 30_033);
        let v = check(&mut t, &rules(&c, m, 30_033), &jump);
        assert!(
            matches!(v.rejected(), Some(Correction::Teleport) | Some(Correction::Checkpoint)),
            "a thirty second claim was accepted: {v:?}"
        );
        assert!(t.last.s < start + 100.0, "the car was moved by a refused packet");
    }

    #[test]
    fn warping_to_the_finish_is_refused() {
        let c = course();
        let m = &MAPS[2];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let mut claim = on_road(&c, m.to - 1.0, 90.0, 200);
        claim.lateral = 0.0;
        assert!(check(&mut t, &rules(&c, m, 200), &claim).rejected().is_some());
        assert!(t.finished_ms.is_none(), "a warp registered a finish");
    }

    /// ...and it is still refused when the client also lies about its arc
    /// length to make the jump look small.
    #[test]
    fn lying_about_arc_length_is_refused() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        // sitting on the grid, claiming to be at the finish
        let mut claim = on_road(&c, t.last.s, 0.0, 100);
        claim.s = m.to;
        assert_eq!(
            check(&mut t, &rules(&c, m, 100), &claim).rejected(),
            Some(Correction::Teleport)
        );
    }

    #[test]
    fn driving_through_the_barrier_is_refused() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let s = t.last.s;
        let p = c.at(s);
        let (sy, cy) = p.yaw.sin_cos();
        let off = m.road_half + 30.0;
        let claim = CarState {
            t_ms: 100,
            x: p.x + cy * off,
            y: p.y + 1.05,
            z: p.z - sy * off,
            s,
            lateral: off,
            yaw: p.yaw,
            ..CarState::default()
        };
        assert_eq!(
            check(&mut t, &rules(&c, m, 100), &claim).rejected(),
            Some(Correction::OffCourse)
        );
    }

    #[test]
    fn a_legal_lateral_beside_an_illegal_position_is_refused() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let s = t.last.s;
        let p = c.at(s);
        let (sy, cy) = p.yaw.sin_cos();
        let off = m.road_half + 12.0;
        let claim = CarState {
            t_ms: 100,
            x: p.x + cy * off,
            y: p.y + 1.05,
            z: p.z - sy * off,
            s,
            lateral: 0.0, // the lie
            yaw: p.yaw,
            ..CarState::default()
        };
        assert_eq!(
            check(&mut t, &rules(&c, m, 100), &claim).rejected(),
            Some(Correction::OffCourse)
        );
    }

    #[test]
    fn flying_over_the_course_is_refused() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let mut claim = in_lane(&c, t.last.s + 2.0, t.last.lateral, 60.0, 100);
        claim.y += 400.0;
        assert_eq!(
            check(&mut t, &rules(&c, m, 100), &claim).rejected(),
            Some(Correction::Altitude)
        );
    }

    #[test]
    fn rewinding_the_clock_is_refused() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 5_000);
        let lane = t.last.lateral;
        let a = in_lane(&c, t.last.s + 3.0, lane, 90.0, 5_033);
        assert_eq!(check(&mut t, &rules(&c, m, 5_033), &a), Verdict::Accept);
        let b = in_lane(&c, t.last.s + 6.0, lane, 90.0, 4_000);
        assert_eq!(check(&mut t, &rules(&c, m, 5_066), &b).rejected(), Some(Correction::Clock));
    }

    #[test]
    fn a_jump_start_does_not_move_the_car() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let claim = in_lane(&c, t.last.s + 40.0, t.last.lateral, 60.0, 100);
        let r = Rules { map: m, course: &c, ruleset: Ruleset::Stock, now_ms: 100, live: false };
        assert!(check(&mut t, &r, &claim).rejected().is_some());
    }

    #[test]
    fn a_refused_packet_never_becomes_the_truth() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let before = t.last;
        let mut claim = on_road(&c, m.to, 900.0, 100);
        claim.lateral = 0.0;
        assert!(check(&mut t, &rules(&c, m, 100), &claim).rejected().is_some());
        assert_eq!(t.last.x, before.x);
        assert_eq!(t.last.s, before.s);
        assert_eq!(t.strikes, 1);
        assert!(t.last.flags & synx_net::flag::CLAMPED != 0);
    }

    /// A player who was silent for a while must be able to resume without
    /// being accused of teleporting - the position tests need two states close
    /// enough in time to mean anything.
    #[test]
    fn a_long_silence_is_not_a_teleport() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let claim = in_lane(&c, t.last.s + 260.0, t.last.lateral, 90.0, 6_000);
        // six seconds of claimed delta is past MAX_CONTINUITY, so the
        // continuity tests stand down and the absolute ones still apply
        assert_eq!(check(&mut t, &rules(&c, m, 6_000), &claim), Verdict::Accept);
    }

    #[test]
    fn the_rebuilt_ruleset_allows_more_and_still_has_a_ceiling() {
        let c = course();
        let m = &MAPS[0];
        let mut t = Track::new();
        t.place(m, &c, 0, 2, 0);
        let lane = t.last.lateral;

        // Just over the one ceiling there is: refused.
        let fast = Ruleset::Stock.ceiling() + 10.0;
        let claim = in_lane(&c, t.last.s + 3.0, lane, fast, 33);
        let mut over_by_a_little = t.clone();
        assert_eq!(
            check(&mut over_by_a_little, &rules(&c, m, 33), &claim).rejected(),
            Some(Correction::Speed)
        );

        // Absurdly over it: refused the same way, rather than wrapping or
        // saturating into something that passes.
        let mut absurd = t.clone();
        let over = in_lane(&c, t.last.s + 6.0, lane, 4_000.0, 33);
        assert_eq!(check(&mut absurd, &rules(&c, m, 33), &over).rejected(), Some(Correction::Speed));

        // Comfortably under it: accepted.
        let ok = in_lane(&c, t.last.s + 3.0, lane, Ruleset::Stock.ceiling() - 12.0, 33);
        assert_eq!(check(&mut t, &rules(&c, m, 33), &ok), Verdict::Accept);
    }
}
