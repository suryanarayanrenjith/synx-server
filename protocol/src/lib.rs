//! SYNX multiplayer wire protocol.
//!
//! # Why this is its own crate
//!
//! There are two implementations of this protocol - one in WebAssembly inside
//! the game, one native inside the server - and the single most expensive class
//! of bug in a networked game is the two of them disagreeing about a byte. A
//! field added on one side and forgotten on the other does not fail to compile;
//! it fails as "the other cars are in the wrong place", three weeks later, on
//! somebody else's machine.
//!
//! So there is exactly one implementation. This crate is `no_std`, has no
//! dependencies, and is linked into both halves. The encoder and the decoder
//! for every message sit next to each other in the same file, and a round-trip
//! test covers each one. A layout change that only lands on one side is
//! therefore impossible rather than merely unlikely.
//!
//! # Why binary, and why full snapshots
//!
//! The transport is a WebSocket, because the game runs in a web view and a
//! browser cannot open a UDP socket. A WebSocket is TCP, and TCP has
//! head-of-line
//! blocking: a lost segment stalls everything queued behind it until it is
//! retransmitted. There are two honest defences and this uses both.
//!
//!   MAKE THE FRAMES SMALL.  A whole four-car snapshot is under two hundred
//!   bytes, which is inside one segment, so a snapshot is never split across
//!   two of them and never waits for half of itself. That is what the
//!   quantisation in [`quant`] buys: not bandwidth (bandwidth was never the
//!   constraint at four players) but the guarantee that one snapshot is one
//!   packet.
//!
//!   MAKE THEM INDEPENDENT.  Every snapshot is complete. Nothing here is a
//!   delta against a previously acknowledged frame, which is the usual way to
//!   halve a snapshot and which would have been the wrong trade: a delta chain
//!   means the server can never skip a frame, so when a client's socket backs
//!   up the only thing the server can do is queue more work behind the stall.
//!   With independent snapshots it can throw the stale ones away and send the
//!   newest, which is the correct behaviour and the whole reason this format
//!   looks wasteful.
//!
//! # Layout rules
//!
//! Little-endian throughout, because both ends are little-endian and a
//! byte-swap on the hot path for a format nobody else reads is a cost with no
//! benefit. Every read is bounds-checked and returns [`WireError`] rather than
//! panicking: this decodes bytes that arrived from the internet, and a panic in
//! a decoder is a denial of service with extra steps.

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
