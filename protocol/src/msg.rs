//! Message definitions and codecs for the SYNX wire protocol.

use crate::quant::{
    deq_byte, deq_lateral, deq_rate, deq_unit, deq_vel, q_angle, q_byte, q_lateral, q_rate,
    q_unit, q_vel,
};
use crate::wire::{Reader, WireError, Writer};
use crate::{c2s, quant, s2c, MAX_PLAYERS};

/// Bytes one car's quantised state occupies on the wire.
pub const CAR_BODY_BYTES: usize = 40;

/// One entry in a snapshot: the car, plus the two things only the server
/// knows about it.
pub const SNAPSHOT_ENTRY_BYTES: usize = 4 + CAR_BODY_BYTES;

/// Fixed cost of a snapshot before any car is in it.
pub const SNAPSHOT_HEADER_BYTES: usize = 7;

/// A car, in the units the game uses, decoded.
///
/// This is deliberately `f32` and not `f64`. The simulation is `f64` and stays
/// that way; but nothing here is ever integrated - these values are set,
/// interpolated and drawn - so the precision that matters is the precision of
/// the screen, and carrying `f32` halves the size of the ring buffers the
/// client keeps per remote car.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct CarState {
    /// When this was true, in milliseconds on the server's clock.
    pub t_ms: u32,
    pub x: f32,
    pub y: f32,
    pub z: f32,
    /// Arc length along the course centreline.
    pub s: f32,
    /// Signed distance from the centreline; the sign is which side.
    pub lateral: f32,
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    /// Body-frame velocity. Kept rather than world-frame `vx`/`vz` because it
    /// is what dead reckoning needs and what the tyre smoke reads.
    pub v_long: f32,
    pub v_lat: f32,
    pub yaw_rate: f32,
    /// Steering input, -1..1, for the front wheels and the driver figure.
    pub steer: f32,
    /// See [`crate::flag`].
    pub flags: u8,
    /// Brake lamp brightness, 0..1.
    pub brake: f32,
    /// Boost reserve, 0..1.
    pub boost: f32,
    /// Accumulated body damage, 0..1.
    pub damage: f32,
    /// The last checkpoint this car has legitimately passed.
    pub checkpoint: u8,
}

impl CarState {
    /// True when the car was in a menu, paused or otherwise not driving.
    #[inline]
    pub fn is_idle(&self) -> bool {
        self.flags & crate::flag::IDLE != 0
    }

    #[inline]
    pub fn has_finished(&self) -> bool {
        self.flags & crate::flag::FINISHED != 0
    }

    /// Speed over the ground, squared, in world units per second.
    ///
    /// Squared rather than the speed itself because this crate is `no_std` and
    /// has no square root, and because every caller either compares it against
    /// another squared quantity or has `std` to hand and can take the root
    /// itself. Neither needs one here.
    #[inline]
    pub fn speed_sq(&self) -> f32 {
        self.v_long * self.v_long + self.v_lat * self.v_lat
    }

    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), WireError> {
        w.u32(self.t_ms)?;
        w.f32(self.x)?;
        w.f32(self.y)?;
        w.f32(self.z)?;
        w.f32(self.s)?;
        w.i16(q_lateral(self.lateral))?;
        w.i16(q_angle(self.yaw))?;
        w.i16(q_angle(self.pitch))?;
        w.i16(q_angle(self.roll))?;
        w.i16(q_vel(self.v_long))?;
        w.i16(q_vel(self.v_lat))?;
        w.i16(q_rate(self.yaw_rate))?;
        w.i8(q_unit(self.steer))?;
        w.u8(self.flags)?;
        w.u8(q_byte(self.brake))?;
        w.u8(q_byte(self.boost))?;
        w.u8(q_byte(self.damage))?;
        w.u8(self.checkpoint)?;
        Ok(())
    }

    pub fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        Ok(CarState {
            t_ms: r.u32()?,
            // finite, not merely present: a NaN position poisons every
            // interpolation it touches and never washes back out
            x: r.f32_finite()?,
            y: r.f32_finite()?,
            z: r.f32_finite()?,
            s: r.f32_finite()?,
            lateral: deq_lateral(r.i16()?),
            yaw: quant::deq_angle(r.i16()?),
            pitch: quant::deq_angle(r.i16()?),
            roll: quant::deq_angle(r.i16()?),
            v_long: deq_vel(r.i16()?),
            v_lat: deq_vel(r.i16()?),
            yaw_rate: deq_rate(r.i16()?),
            steer: deq_unit(r.i8()?),
            flags: r.u8()?,
            brake: deq_byte(r.u8()?),
            boost: deq_byte(r.u8()?),
            damage: deq_byte(r.u8()?),
            checkpoint: r.u8()?,
        })
    }
}

// -------------------------------------------------------- client to server --

/// `STATE`: one car, from the client that owns it.
pub fn write_state(buf: &mut [u8], seq: u16, car: &CarState) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    w.u8(c2s::STATE)?;
    w.u16(seq)?;
    car.write(&mut w)?;
    Ok(w.len())
}

/// Decoded `STATE`, as the server sees it.
pub struct StateMsg {
    pub seq: u16,
    pub car: CarState,
}

pub fn read_state(body: &[u8]) -> Result<StateMsg, WireError> {
    let mut r = Reader::new(body);
    Ok(StateMsg { seq: r.u16()?, car: CarState::read(&mut r)? })
}

pub fn write_time_req(buf: &mut [u8], client_ms: u32) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    w.u8(c2s::TIME_REQ)?;
    w.u32(client_ms)?;
    Ok(w.len())
}

pub fn write_pong(buf: &mut [u8], nonce: u32) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    w.u8(c2s::PONG)?;
    w.u32(nonce)?;
    Ok(w.len())
}

// -------------------------------------------------------- server to client --

/// One car in a snapshot.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SnapshotEntry {
    /// Which seat in the room this car belongs to, 0..[`MAX_PLAYERS`].
    pub slot: u8,
    /// Race position, 1-based. Zero before the race is running.
    pub place: u8,
    /// The server's measured round trip to that player, milliseconds, so the
    /// scoreboard can show it without a second message.
    pub rtt_ms: u16,
    pub car: CarState,
}

/// A whole snapshot, decoded.
///
/// Fixed-size and `Copy`: there is no allocation anywhere in the receive path,
/// which matters more on the client (a per-frame allocation in WebAssembly is
/// a growth of linear memory away from detaching every typed-array view the
/// renderer holds) than it does on the server.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Snapshot {
    /// The server's clock when the snapshot was assembled.
    pub t_ms: u32,
    /// Bit 0: the race is live. Bit 1: the race has finished.
    pub flags: u8,
    pub count: u8,
    pub entries: [SnapshotEntry; MAX_PLAYERS],
}

impl Default for Snapshot {
    fn default() -> Self {
        Snapshot { t_ms: 0, flags: 0, count: 0, entries: [SnapshotEntry::default(); MAX_PLAYERS] }
    }
}

/// Bit 0 of [`Snapshot::flags`]: cars are racing, not sitting on the grid.
pub const SNAP_LIVE: u8 = 1 << 0;
/// Bit 1: the race is over and the results are final.
pub const SNAP_OVER: u8 = 1 << 1;
/// Bit 2: the countdown is running.
pub const SNAP_COUNTDOWN: u8 = 1 << 2;

pub fn write_snapshot(
    buf: &mut [u8],
    t_ms: u32,
    flags: u8,
    entries: &[SnapshotEntry],
) -> Result<usize, WireError> {
    if entries.len() > MAX_PLAYERS {
        return Err(WireError::Range);
    }
    let mut w = Writer::new(buf);
    w.u8(s2c::SNAPSHOT)?;
    w.u8(entries.len() as u8)?;
    w.u8(flags)?;
    w.u32(t_ms)?;
    for e in entries {
        w.u8(e.slot)?;
        w.u8(e.place)?;
        w.u16(e.rtt_ms)?;
        e.car.write(&mut w)?;
    }
    Ok(w.len())
}

pub fn read_snapshot(body: &[u8]) -> Result<Snapshot, WireError> {
    let mut r = Reader::new(body);
    let count = r.u8()?;
    if count as usize > MAX_PLAYERS {
        return Err(WireError::Range);
    }
    let flags = r.u8()?;
    let t_ms = r.u32()?;
    let mut snap = Snapshot { t_ms, flags, count, entries: [SnapshotEntry::default(); MAX_PLAYERS] };
    for i in 0..count as usize {
        let slot = r.u8()?;
        if slot as usize >= MAX_PLAYERS {
            return Err(WireError::Range);
        }
        snap.entries[i] = SnapshotEntry {
            slot,
            place: r.u8()?,
            rtt_ms: r.u16()?,
            car: CarState::read(&mut r)?,
        };
    }
    Ok(snap)
}

/// A correction, as the client decodes it.
#[derive(Clone, Copy, Debug)]
pub struct CorrectionMsg {
    pub reason: u8,
    pub car: CarState,
}

pub fn write_correction(buf: &mut [u8], reason: u8, car: &CarState) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    w.u8(s2c::CORRECTION)?;
    w.u8(reason)?;
    car.write(&mut w)?;
    Ok(w.len())
}

pub fn read_correction(body: &[u8]) -> Result<CorrectionMsg, WireError> {
    let mut r = Reader::new(body);
    Ok(CorrectionMsg { reason: r.u8()?, car: CarState::read(&mut r)? })
}

pub fn write_time(buf: &mut [u8], echo: u32, server_ms: u32) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    w.u8(s2c::TIME)?;
    w.u32(echo)?;
    w.u32(server_ms)?;
    Ok(w.len())
}

pub fn write_ping(buf: &mut [u8], nonce: u32) -> Result<usize, WireError> {
    let mut w = Writer::new(buf);
    w.u8(s2c::PING)?;
    w.u32(nonce)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flag;

    fn a_car() -> CarState {
        CarState {
            t_ms: 1_234_567,
            x: 12_345.5,
            y: -64.25,
            z: -9_876.5,
            s: 132_000.5,
            lateral: -7.25,
            yaw: 2.5,
            pitch: 0.05,
            roll: -0.12,
            v_long: 84.5,
            v_lat: -3.25,
            yaw_rate: 1.5,
            steer: -0.5,
            flags: flag::BOOSTING | flag::DRIFTING,
            brake: 0.25,
            boost: 0.75,
            damage: 0.5,
            checkpoint: 17,
        }
    }

    fn close(a: f32, b: f32, eps: f32, what: &str) {
        assert!((a - b).abs() <= eps, "{what}: {a} vs {b}");
    }

    fn same(a: &CarState, b: &CarState) {
        assert_eq!(a.t_ms, b.t_ms);
        assert_eq!(a.x, b.x);
        assert_eq!(a.y, b.y);
        assert_eq!(a.z, b.z);
        assert_eq!(a.s, b.s);
        close(a.lateral, b.lateral, 0.01, "lateral");
        close(a.yaw, b.yaw, 1e-3, "yaw");
        close(a.pitch, b.pitch, 1e-3, "pitch");
        close(a.roll, b.roll, 1e-3, "roll");
        close(a.v_long, b.v_long, 0.01, "vLong");
        close(a.v_lat, b.v_lat, 0.01, "vLat");
        close(a.yaw_rate, b.yaw_rate, 1e-3, "yawRate");
        close(a.steer, b.steer, 0.01, "steer");
        assert_eq!(a.flags, b.flags);
        close(a.brake, b.brake, 0.01, "brake");
        close(a.boost, b.boost, 0.01, "boost");
        close(a.damage, b.damage, 0.01, "damage");
        assert_eq!(a.checkpoint, b.checkpoint);
    }

    #[test]
    fn state_round_trips() {
        let car = a_car();
        let mut buf = [0u8; 64];
        let n = write_state(&mut buf, 4242, &car).unwrap();
        assert_eq!(n, 3 + CAR_BODY_BYTES);
        assert_eq!(buf[0], c2s::STATE);
        let got = read_state(&buf[1..n]).unwrap();
        assert_eq!(got.seq, 4242);
        same(&car, &got.car);
    }

    #[test]
    fn a_full_snapshot_fits_in_one_segment() {
        let entries: [SnapshotEntry; MAX_PLAYERS] = core::array::from_fn(|i| SnapshotEntry {
            slot: i as u8,
            place: i as u8 + 1,
            rtt_ms: 42,
            car: a_car(),
        });
        let mut buf = [0u8; crate::MAX_SERVER_FRAME];
        let n = write_snapshot(&mut buf, 999, SNAP_LIVE, &entries).unwrap();
        assert_eq!(n, SNAPSHOT_HEADER_BYTES + MAX_PLAYERS * SNAPSHOT_ENTRY_BYTES);
        // the number that matters: one TCP segment, with the WebSocket header
        // and every layer under it still to fit
        assert!(n < 400, "a four car snapshot grew to {n} bytes");

        let snap = read_snapshot(&buf[1..n]).unwrap();
        assert_eq!(snap.count as usize, MAX_PLAYERS);
        assert_eq!(snap.t_ms, 999);
        assert_eq!(snap.flags, SNAP_LIVE);
        for i in 0..MAX_PLAYERS {
            assert_eq!(snap.entries[i].slot, i as u8);
            assert_eq!(snap.entries[i].place, i as u8 + 1);
            assert_eq!(snap.entries[i].rtt_ms, 42);
            same(&entries[i].car, &snap.entries[i].car);
        }
    }

    #[test]
    fn correction_round_trips() {
        let car = a_car();
        let mut buf = [0u8; 64];
        let n = write_correction(&mut buf, crate::Correction::Speed as u8, &car).unwrap();
        let got = read_correction(&buf[1..n]).unwrap();
        assert_eq!(crate::Correction::from_u8(got.reason), Some(crate::Correction::Speed));
        same(&car, &got.car);
    }

    /// A snapshot claiming more cars than a room can hold, or a seat that does
    /// not exist, is refused rather than indexed with.
    #[test]
    fn a_lying_count_is_refused() {
        let mut body = [0u8; 8];
        body[0] = (MAX_PLAYERS + 1) as u8;
        assert_eq!(read_snapshot(&body), Err(WireError::Range));

        let mut buf = [0u8; crate::MAX_SERVER_FRAME];
        let e = [SnapshotEntry { slot: 0, place: 1, rtt_ms: 0, car: a_car() }];
        let n = write_snapshot(&mut buf, 0, 0, &e).unwrap();
        buf[SNAPSHOT_HEADER_BYTES] = 99; // move the car to a seat that is not there
        assert_eq!(read_snapshot(&buf[1..n]), Err(WireError::Range));
    }

    /// Every message must survive being cut short at every possible length.
    /// This is the test that actually stands between a hostile peer and the
    /// process, so it is exhaustive rather than representative.
    #[test]
    fn every_truncation_is_an_error_not_a_panic() {
        let car = a_car();
        let mut buf = [0u8; crate::MAX_SERVER_FRAME];

        let n = write_state(&mut buf, 1, &car).unwrap();
        for cut in 0..n {
            let _ = read_state(&buf[1..cut.max(1)]);
        }
        let e = [SnapshotEntry { slot: 0, place: 1, rtt_ms: 0, car }; 2];
        let n = write_snapshot(&mut buf, 0, 0, &e).unwrap();
        for cut in 1..n {
            let _ = read_snapshot(&buf[1..cut]);
        }
        let n = write_correction(&mut buf, 1, &car).unwrap();
        for cut in 1..n {
            let _ = read_correction(&buf[1..cut]);
        }
    }
}
