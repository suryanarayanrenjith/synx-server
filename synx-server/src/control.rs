//! JSON lobby messages carried on the WebSocket text channel.

use serde::{Deserialize, Serialize};

use crate::maps::{Map, MAPS};

/// The most characters a chat line may carry.
pub const MAX_CHAT: usize = 120;

/// Everything a client can ask for.
#[derive(Debug, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase", deny_unknown_fields)]
pub enum ClientMsg {
    /// Open a room and take the host seat.
    Create {
        #[serde(default)]
        map: u8,
        #[serde(default)]
        ruleset: String,
        #[serde(default)]
        private: bool,
        #[serde(default)]
        max: u8,
    },
    /// Join a specific room by its code.
    Join { code: String },
    /// Join whichever open room fits, or open one. `map` of 255 means any.
    Quick {
        #[serde(default = "any_map")]
        map: u8,
    },
    /// List the rooms that are open to anybody.
    ///
    /// This and the two below take no arguments, and are written as empty
    /// structs rather than as unit variants on purpose: serde ignores unknown
    /// fields on a unit variant of an internally tagged enum however the
    /// container is annotated, and "every message is exactly its documented
    /// shape" is worth three pairs of braces.
    Rooms {},
    Leave {},
    Ready { on: bool },
    /// Host only.
    Map { map: u8 },
    /// Accepted and refused. There is one car - see `maps::Ruleset` - and the
    /// field is kept only so an older client gets an answer rather than
    /// silence. Never read.
    Ruleset { #[allow(dead_code)] ruleset: String },
    /// Host only.
    Start {},
    /// Host only.
    Kick { slot: u8 },
    Chat { text: String },
}

fn any_map() -> u8 {
    255
}

/// Where a room is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Lobby,
    Countdown,
    Racing,
    Results,
}

/// One player, as everybody in the room sees them.
#[derive(Debug, Clone, Serialize)]
pub struct PlayerView {
    pub slot: u8,
    pub name: String,
    pub ready: bool,
    /// Round trip in milliseconds, as the server measured it.
    pub ping: u16,
    /// 1-based, or 0 before there is an order.
    pub place: u8,
    /// 0..1 along the route.
    pub progress: f32,
    /// Race time in milliseconds, once they have crossed the line.
    pub finish_ms: Option<u32>,
    /// False while a player is reconnecting; their car stays on the grid.
    pub connected: bool,
    pub host: bool,
}

/// One entry in the map picker. Sent once, in the welcome, so the client's
/// list and the server's cannot disagree about what exists.
#[derive(Debug, Clone, Serialize)]
pub struct MapView {
    pub id: u8,
    pub name: &'static str,
    pub note: &'static str,
    pub km: f32,
    pub from: f32,
    pub to: f32,
}

impl From<&'static Map> for MapView {
    fn from(m: &'static Map) -> MapView {
        MapView { id: m.id, name: m.name, note: m.note, km: m.km(), from: m.from, to: m.to }
    }
}

pub fn map_views() -> Vec<MapView> {
    MAPS.iter().map(MapView::from).collect()
}

/// One row on the results board.
#[derive(Debug, Clone, Serialize)]
pub struct ResultRow {
    pub slot: u8,
    pub name: String,
    pub place: u8,
    /// None when they did not finish.
    pub time_ms: Option<u32>,
    pub progress: f32,
    pub dnf: bool,
    /// How many of their packets the validator refused. Shown to the room,
    /// because a player who spent the race being corrected is information
    /// everybody else wants.
    pub corrections: u32,
}

/// Where a car starts.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct GridSlot {
    pub slot: u8,
    pub s: f32,
    pub lateral: f32,
}

/// Everything the server can say.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "t", rename_all = "lowercase")]
pub enum ServerMsg {
    /// Sent once, immediately on connect. Everything the client needs to size
    /// its buffers and draw its map picker.
    Welcome {
        protocol: u16,
        name: String,
        session: String,
        snapshot_hz: u32,
        send_hz: u32,
        server_time_ms: u32,
        max_players: u8,
        maps: Vec<MapView>,
        build: &'static str,
    },
    /// The room, whenever anything about it changes. Complete every time -
    /// there is no incremental lobby state, because a lobby that can drift out
    /// of step with the server is a lobby that will.
    Room {
        code: String,
        map: u8,
        ruleset: &'static str,
        phase: Phase,
        you: u8,
        host: u8,
        max_players: u8,
        private: bool,
        players: Vec<PlayerView>,
    },
    /// The lights are on. `start_at_ms` is on the server clock, which the
    /// client has already synchronised, so every car drops at the same instant
    /// regardless of latency.
    Countdown { start_at_ms: u32, map: u8, ruleset: &'static str, grid: Vec<GridSlot> },
    /// The board, when the race is over.
    Results { rows: Vec<ResultRow>, hold_ms: u32, map: u8 },
    /// Rooms open to anybody.
    Rooms { rooms: Vec<RoomBrief> },
    Chat { slot: u8, name: String, text: String },
    /// Something the interface should say out loud: a player joined, the host
    /// changed, a correction landed.
    Notice { kind: &'static str, text: String },
    /// A request could not be honoured. Never fatal on its own.
    Error { code: &'static str, message: String },
    /// The connection is about to close, and why.
    Bye { code: &'static str, message: String },
}

/// A room in the public list.
#[derive(Debug, Clone, Serialize)]
pub struct RoomBrief {
    pub code: String,
    pub map: u8,
    pub map_name: &'static str,
    pub players: u8,
    pub max_players: u8,
    pub phase: Phase,
    pub ruleset: &'static str,
}

/// Trim and sanitise a chat line.
///
/// Chat is drawn into the canvas HUD, never into HTML, so this is not escaping
/// - it is the same three problems `identity::clean_name` solves, for a
/// different field: control characters break the log, zero-width characters
/// let one player impersonate another, and unbounded length is a way to make
/// everybody else's frame time somebody else's decision.
pub fn clean_chat(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(MAX_CHAT);
    for ch in raw.chars() {
        if out.chars().count() >= MAX_CHAT {
            break;
        }
        // printable ASCII only, for the same reason names are
        if (' '..='~').contains(&ch) {
            out.push(ch);
        }
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_client_messages_parse() {
        let m: ClientMsg = serde_json::from_str(r#"{"t":"join","code":"ABC123"}"#).unwrap();
        assert!(matches!(m, ClientMsg::Join { .. }));
        let m: ClientMsg = serde_json::from_str(r#"{"t":"quick"}"#).unwrap();
        assert!(matches!(m, ClientMsg::Quick { map: 255 }));
        let m: ClientMsg =
            serde_json::from_str(r#"{"t":"create","map":6,"ruleset":"rebuilt","private":true,"max":3}"#)
                .unwrap();
        match m {
            ClientMsg::Create { map, ruleset, private, max } => {
                assert_eq!((map, private, max), (6, true, 3));
                assert_eq!(ruleset, "rebuilt");
            }
            _ => panic!("wrong variant"),
        }
    }

    /// A message with extra keys is refused rather than quietly accepted. That
    /// is not pedantry: a padded frame is how a client probes for a parser
    /// that will accept anything, and refusing it keeps the shape of what is
    /// accepted exactly as documented.
    #[test]
    fn unknown_fields_and_unknown_types_are_refused() {
        assert!(serde_json::from_str::<ClientMsg>(r#"{"t":"leave","junk":1}"#).is_err());
        assert!(serde_json::from_str::<ClientMsg>(r#"{"t":"nonsense"}"#).is_err());
        assert!(serde_json::from_str::<ClientMsg>(r#"{"t":"map"}"#).is_err());
        assert!(serde_json::from_str::<ClientMsg>("[]").is_err());
        assert!(serde_json::from_str::<ClientMsg>("").is_err());
        // a map id past the table is a valid parse and is refused by the room,
        // which is where the range actually lives
        assert!(serde_json::from_str::<ClientMsg>(r#"{"t":"map","map":250}"#).is_ok());
    }

    #[test]
    fn chat_is_reduced_to_something_drawable() {
        assert_eq!(clean_chat("  good race  ").as_deref(), Some("good race"));
        assert_eq!(clean_chat("a\nb\tc").as_deref(), Some("abc"));
        assert_eq!(clean_chat("\u{200b}\u{200b}"), None);
        assert_eq!(clean_chat(""), None);
        assert_eq!(clean_chat("x".repeat(5_000).as_str()).unwrap().len(), MAX_CHAT);
    }

    #[test]
    fn the_map_list_is_the_one_the_server_races_on() {
        let v = map_views();
        assert_eq!(v.len(), MAPS.len());
        for (a, b) in v.iter().zip(MAPS.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.name, b.name);
            assert!(a.km > 8.0);
        }
    }

    #[test]
    fn server_messages_serialise_with_a_tag() {
        let s = serde_json::to_string(&ServerMsg::Error {
            code: "full",
            message: "the grid is full".into(),
        })
        .unwrap();
        assert!(s.contains(r#""t":"error""#), "{s}");
    }
}
