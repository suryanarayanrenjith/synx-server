# SYNX multiplayer server

Lobbies of four, seven routes, an authoritative race director and a
physics-envelope validator, in Rust.

This folder is self-contained and is its own git repository. Point a host's
*root directory* at `server/` and nothing above it needs to exist.

```
server/
  Cargo.toml          workspace
  Dockerfile          two stage; the runtime image is ~35 MB
  render.yaml         blueprint, with every limit written down
  protocol/           the wire format — compiled into BOTH halves of the game
  synx-server/        the server itself
    assets/course.bin the road, emitted by the game's own course generator
```

---

## Run it

```bash
# locally
cd server
cargo run --release            # listens on $PORT, default 10000

```

```bash
# in a container, the way the host does
docker build -t synx-server server/
docker run -p 10000:10000 -e RUST_LOG=info,synx_server=debug synx-server
```

### Deploying to Render

Create a **Web Service**, or use `render.yaml` as a Blueprint:

| setting | value |
|---|---|
| Root Directory | `server` |
| Runtime | Docker |
| Health Check Path | `/healthz` |
| Region | Singapore — Render's nearest to India |
| Plan | Free |

Set `SYNX_TOKEN_SECRET` (Render can generate it). Everything else has a
sensible default and is printed at boot.

This folder is its own git repository, separate from the game, so it can be
pushed and deployed on its own.

---

## Endpoints

| | |
|---|---|
| `GET /healthz` | liveness. 200 when ready, 503 while starting. |
| `GET /wake` | wake the instance and say how awake it is. The game calls this the moment the MULTIPLAYER tile is in view. |
| `GET /api/handshake` | a proof-of-work challenge and the server clock. |
| `POST /api/session` | register; returns a session token. |
| `GET /api/rooms` | public lobbies. |
| `GET /api/stats` | everything the process knows about itself. |
| `WS /ws?token=…` | the game. |

---

## Overload and abuse

Every inbound path is bounded, and the cheap test always comes first.

| layer | what it does |
|---|---|
| **Load shedding** | An in-flight counter. Past `SYNX_MAX_INFLIGHT` the process answers 503 immediately instead of accepting work it cannot do. One atomic, and it is checked before anything else. |
| **Jail** | An address that trips a limit is refused outright for 30 s, doubling to an hour if it comes back and does it again. One hash lookup, so a sustained flood costs almost nothing. Escalation is **per episode, not per request** — a single burst is one mistake however many packets it arrives as. |
| **Per-address buckets** | HTTP requests, connection *attempts*, registrations, and each class of WebSocket message. Being *at* the concurrent connection cap is not abuse (four players behind one router) and is never punished; opening sockets in a loop is. |
| **Global accept gate** | New connections per second across the whole process, so a distributed flood is bounded even when no single address trips its own limit. |
| **Hard limits** | 16 kB request bodies, 8 kB WebSocket frames, a 15 s request timeout, a socket lifetime cap, and a write timeout so a peer that stops reading is dropped rather than buffered. |
| **Health probe exempt** | `/healthz` is never throttled: a rate-limited health check gets the instance restarted for no reason. |
| **Panic containment** | The release profile unwinds rather than aborts. A room task that panics ends that room and nothing else, and a supervisor reclaims its code; connection slots and session claims are released by `Drop` guards, so nothing leaks on a panic, an error, or a cancelled task. |

`GET /api/stats` reports all of it: requests served, refused and shed, addresses
jailed, in-flight count, and whether any room has ever panicked.

## Design notes

| the constraint | what it changed |
|---|---|
| **A small CPU budget** | The server does not simulate cars — it validates an envelope (`validate.rs`). Idle rooms tick at 4 Hz, racing rooms at 20. Snapshots are encoded once per room, not once per player. Tokio runs 2 workers, because a container reports the host's whole CPU count and the default would spawn eight to share a fraction of a core. |
| **WebSocket, therefore TCP** | Head-of-line blocking, answered twice: every snapshot is under 200 bytes so it fits one segment, and every snapshot is *independent* so the server can throw stale ones away instead of queueing them behind a stall (`tokio::sync::watch`, see `room.rs`). |
| **Ephemeral storage** | Nothing is written. Sessions live in memory and end with the process, which is stated plainly in `identity.rs` rather than papered over. |
| **Cold starts** | `/wake`, called by the game as soon as the multiplayer tile is in view rather than when a socket is needed, and an interface that says how long the instance has actually been up. The server does not ping itself. |

## Anti-cheat

The server owns the outcome of a race. It does not own the physics — see the
long comment at the top of `validate.rs` for why re-simulating would be worse
than useless when the client's `sin` and the server's disagree in the last
place.

What it checks, on every packet:

| exploit | caught by |
|---|---|
| speed hack | the ceiling, which the solver hard-clamps |
| teleport / warp to the finish | displacement against **real elapsed time** |
| noclip through barriers | lateral containment |
| flying over the course | altitude against the road surface |
| cutting the course | checkpoint order |
| lying about arc length | arc length against the projected position |
| rewinding to hide a crash | monotonic timestamps |
| inflating the frame delta | elapsed time bounded by the wall clock |
| jump start | no movement before the lights |

A refused packet never becomes the truth: the car stays where it legitimately
was and the client is sent a correction naming the reason. Strikes **decay** —
one forgiven per twenty accepted packets — so a bad connection is never
mistaken for a modified client, while a client whose every packet is refused
is removed in about a second and a half.

And at the door: unforgeable session tokens, one live socket per session,
proof of work on registration, per-address connection and registration caps,
token buckets on every inbound message class, hard frame-size limits, and a
`X-Forwarded-For` policy a client cannot spoof (`ws.rs`).

---

## Tests

```bash
cargo test                                   # 70 unit tests
node tools/harness.js http://127.0.0.1:10000 # 44 integration checks
```

The harness is the half `cargo test` cannot reach: it registers real sessions
through the real proof of work, opens real sockets, drives a real 9.5 km race
in real time, and then cheats four ways and checks it is caught. Two bugs that
only exist when all of that happens at once were found by it and are documented
where they were fixed (`room.rs`: one clock for the whole process, and a tick
deadline that is checked rather than raced against).

---

## Configuration

Every knob is an environment variable, every one has a sensible default, and
all of them are printed at boot. See `src/config.rs`.

The ones worth knowing:

| | |
|---|---|
| `PORT` | set by the host |
| `SYNX_TOKEN_SECRET` | signs session tokens; generated per process if unset |
| `SYNX_WORKERS` | tokio worker threads (default 2) |
| `SYNX_MAX_ROOMS` / `SYNX_MAX_CONNECTIONS` / `SYNX_MAX_PER_IP` | capacity |
| `SYNX_MAX_INFLIGHT` | requests in flight before the process sheds load |
| `SYNX_HTTP_RATE` / `SYNX_CONNECT_RATE` / `SYNX_ACCEPT_RATE` | abuse limits |
| `SYNX_REQUEST_TIMEOUT` / `SYNX_MAX_SOCKET` | how long anything may last |
| `SYNX_SNAPSHOT_HZ` / `SYNX_LOBBY_HZ` | tick rates |
| `SYNX_POW_BITS` | registration proof of work (16 ≈ a few ms in a browser) |
| `SYNX_CORRECTION_STRIKES` | refusals before a player is removed |
| `RUST_LOG` | `info,synx_server=debug` by default |

---

## Regenerating the course

`assets/course.bin` is the road the server validates against. It is **committed
on purpose** and emitted by the game's own generator, so the server cannot
drift from what the game is driving:

```bash
cargo run -p synx-core --release --bin mkcourse -- \
    web/data/scene.json server/synx-server/assets/course.bin
```

Re-run it from the game repository if `crates/synx-core/src/track.rs` or
`web/data/scene.json` ever changes; `build.ps1` does it as part of the normal
build. The server refuses to start if the asset is missing or corrupt.
