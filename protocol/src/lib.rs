//! Shared no-std wire protocol for the SYNX game and server.

#![no_std]
#![forbid(unsafe_code)]

pub mod msg;
pub mod pow;
pub mod quant;
pub mod wire;

pub use msg::{CarState, CorrectionMsg, Snapshot, SnapshotEntry, CAR_BODY_BYTES};
pub use quant::{deq_angle, deq_unit, q_angle, q_unit};
pub use wire::{Reader, WireError, Writer};

/// Bumped whenever the byte layout or the meaning of a field changes.
///
/// The client sends this in its HELLO and the server refuses anything else.
/// A player running a stale build gets a clear "update the game" rather than a
/// car that drives sideways through the scenery.
pub const PROTOCOL_VERSION: u16 = 1;

/// The most players one room can hold.
///
/// Four is a design decision, not a technical ceiling, but several things are
/// sized off it - the snapshot buffer, the slot table, the client's remote car
/// table - so it is declared once and asserted against everywhere.
pub const MAX_PLAYERS: usize = 4;

/// The largest binary frame a client may send. Anything bigger is dropped and
/// the connection closed: no legitimate client message comes close, so a large
/// one is either a bug or an attack and neither deserves a buffer.
pub const MAX_CLIENT_BINARY: usize = 128;

/// ...and the largest text (JSON) frame. Lobby traffic only: a room code, a
/// map choice, a name, a chat line.
pub const MAX_CLIENT_TEXT: usize = 1024;

/// The largest binary frame the server will ever produce, so the client can
/// size one scratch buffer at startup and never allocate again.
pub const MAX_SERVER_FRAME: usize = 512;

/// How often a client publishes its own car, and how often the server
/// publishes the room. Both are ceilings the sender may drop below - see the
/// adaptive rate control on each side - and both are stated here so the
/// buffers that depend on them are sized from the same numbers.
pub const CLIENT_SEND_HZ: u32 = 30;
pub const SERVER_SNAPSHOT_HZ: u32 = 20;

/// How long a client's clock may differ from the server's before its packets
/// are treated as a replay attempt rather than as jitter, in milliseconds.
///
/// A state stamped in the future would let a player claim a position they have
/// not reached yet; one stamped far in the past would let them re-send an old
/// good state to hide a bad one. Both are refused.
pub const MAX_CLOCK_SKEW_MS: i64 = 1500;

// ------------------------------------------------------------- message ids --

/// Binary message ids, client to server. Text (JSON) lobby messages are
/// carried on the WebSocket's text channel and are not listed here.
pub mod c2s {
    /// The car, quantised. The hot path, and the only message sent per frame.
    pub const STATE: u8 = 0x01;
    /// Half of the clock handshake; the server answers with [`super::s2c::TIME`].
    pub const TIME_REQ: u8 = 0x02;
    /// Answer to the server's liveness probe.
    pub const PONG: u8 = 0x03;
}

/// Binary message ids, server to client.
pub mod s2c {
    /// Everybody's car, at one instant on the server's clock.
    pub const SNAPSHOT: u8 = 0x81;
    /// "That is not where you are." Sent only to the offending client.
    pub const CORRECTION: u8 = 0x82;
    /// The other half of the clock handshake.
    pub const TIME: u8 = 0x83;
    /// Liveness probe. A client that stops answering is dropped.
    pub const PING: u8 = 0x84;
}

// ------------------------------------------------------------------ flags --

/// Bits in [`CarState::flags`]. These drive presentation on the receiving
/// side - a boosting car has a lit tail, a drifting one throws smoke - and two
/// of them (`FINISHED`, `CLAMPED`) are authoritative state the server sets.
pub mod flag {
    pub const BOOSTING: u8 = 1 << 0;
    pub const DRIFTING: u8 = 1 << 1;
    pub const OFFROAD: u8 = 1 << 2;
    pub const RACE_MODE: u8 = 1 << 3;
    pub const FINISHED: u8 = 1 << 4;
    pub const WRONG_WAY: u8 = 1 << 5;
    /// The sender was in a menu or paused when this was sampled, so the
    /// receiver should hold the car still rather than dead-reckon it forward.
    pub const IDLE: u8 = 1 << 6;
    /// Set by the server on a state it had to clamp. The client that sent it
    /// gets a CORRECTION as well; everyone else just needs to know the car
    /// they are drawing was moved.
    pub const CLAMPED: u8 = 1 << 7;
}

/// Why the server sent a [`s2c::CORRECTION`].
///
/// This is not only diagnostics. The client shows the reason on screen, which
/// matters because the honest cause of most corrections is a bad connection
/// rather than a cheat, and a car that silently snaps backwards with no
/// explanation is indistinguishable from a broken game.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Correction {
    /// Moved further than the car's own top speed allows in the elapsed time.
    Speed = 1,
    /// Outside the barriers.
    OffCourse = 2,
    /// Arc length jumped forward without covering the road in between.
    Teleport = 3,
    /// Height does not match the road under the car.
    Altitude = 4,
    /// Timestamp outside the window the server will accept.
    Clock = 5,
    /// Went past a checkpoint without passing the one before it.
    Checkpoint = 6,
    /// Sending faster than the declared rate.
    Flood = 7,
    /// A number that is not a number.
    NotFinite = 8,
}

impl Correction {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Correction::Speed,
            2 => Correction::OffCourse,
            3 => Correction::Teleport,
            4 => Correction::Altitude,
            5 => Correction::Clock,
            6 => Correction::Checkpoint,
            7 => Correction::Flood,
            8 => Correction::NotFinite,
            _ => return None,
        })
    }
}
