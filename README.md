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
| Root Directory | *(repository root)* |
| Runtime | Docker |
| Health Check Path | `/healthz` |
| Region | Singapore |
| Plan | Free |

There is nothing to set. Render injects `PORT`, the server obeys it, and
everything else has a default that is printed at boot.

Set `SYNX_ALLOWED_ORIGINS` only if you serve the web build from your own
domain — that domain has to be named there, or the browser's own `Origin`
header will get it turned away.

This repository is separate from the game and deploys on its own. Nothing is
shared by path: it carries its own copy of the wire format in `protocol/`, the
game carries its own, and the two are held together at runtime by the
fingerprint in the handshake rather than at build time by a directory that has
to exist.

---

## Endpoints

| | |
|---|---|
| `GET /healthz` | liveness. 200 when ready, 503 while starting. |
| `GET /wake` | wake the instance and say how awake it is. The game calls this the moment the MULTIPLAYER tile is in view. |
| `GET /api/handshake` | a proof-of-work challenge, the server clock, and this build's wire fingerprint. |
| `POST /api/session` | register; returns a session token. |
| `GET /api/rooms` | public lobbies. |
| `GET /api/stats` | everything the process knows about itself. |
| `WS /ws?token=…` | the game. |

---

## Who is allowed in

The game and this server are built separately and meet only at a URL. That is
the right shape, but a URL is open to everybody, so the two guarantees that
came free from being one build are now stated explicitly. Both live in
`src/client.rs`.

### Do we agree what a byte means?

`WIRE_FINGERPRINT` is a compile-time digest of the wire format's own shape —
every opcode, field width, flag bit and quantisation scale. It is computed from
the constants by a `const fn`, so it cannot fall out of step with them: change
a scale factor and the fingerprint changes in the same edit, whether or not
anyone remembered to bump a version.

The client sends it before it sends a car. A mismatch is `426` and *update the
game*, which beats the alternative — a race that runs and is subtly wrong.

### Is this the real client?

It is not asked, because it cannot be answered and pretending otherwise would
be worse than leaving it alone.

SYNX is open source and so is this server. Anyone can clone either, so there is
no "official" build to recognise — and the usual trick, a shared secret
compiled into the client, does not survive being a public download. It ships to
every user; `strings` recovers it. A check built on one buys a reassuring line
in the log and very little else.

So the door asks the two questions above and stops. What actually keeps a
public grid standing is behind it, and does not care who is calling:

| | |
|---|---|
| **The physics validator** | `validate.rs`. A hand-written client still cannot teleport, exceed the speed envelope, leave the road, skip a checkpoint or run a clock that disagrees with the server's. Every rejection is a correction and a strike. |
| **The proof of work** | Sixteen bits at registration: a few milliseconds once, hours for anybody minting sessions in bulk. |
| **The rate limits** | Per address, on HTTP, on connection attempts, on states, controls and chat. Over the line is throttled and then jailed. |
| **The caps** | Rooms, total connections, connections per address, requests in flight. |
| **The strike table** | Forty corrections and the car is removed. |

That list is the security posture. The door is a doormat, and `src/client.rs`
says so in as many words.

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

**There is almost nothing to configure, and that is deliberate.** This server is
meant to be cloned and run by anybody who wants their own grid: `git clone`,
`cargo run --release`, and you have one. Every variable that must be set before
that works is a step somebody can get wrong, and every knob nobody will ever
turn is a decision a reader has to rule out while looking for the two that
matter.

So there are two, and both exist because deployments genuinely differ rather
than because the value is arguable:

| | |
|---|---|
| `PORT` | the host picks it — Render, Fly and Railway all assign one and expect the process to obey. Defaults to 10000. |
| `SYNX_ALLOWED_ORIGINS` | comma separated. Unset, the server accepts the origins a SYNX desktop build presents. Set it if you serve the web build from your own domain. |

Two more are about the process rather than the game:

| | |
|---|---|
| `SYNX_WORKERS` | tokio worker threads (default 2; a container reports the host's whole CPU count, which would otherwise spawn eight to share a fraction of a core) |
| `RUST_LOG` | `info,synx_server=debug` by default |

Everything else — tick rates, capacity, session lifetimes, proof-of-work
difficulty, rate limits, race timing, strike budgets — is a named constant in
`src/config.rs` with the reasoning for its value written beside it. Changing
one is an informed edit to a constant rather than an undocumented variable set
in a dashboard nobody else can see. All of them are printed at boot, so what a
running process is actually doing can be read off the log.

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
