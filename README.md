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
| Region | Singapore — Render's nearest to India |
| Plan | Free |

Set two secrets:

| | |
|---|---|
| `SYNX_TOKEN_SECRET` | signs session tokens. Let Render generate it. |
| `SYNX_CLIENT_SECRET` | must match a value the game was **built** with. Comma separated; any one may match. See below. |

Everything else has a sensible default and is printed at boot.

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

Two checks, and they cover different halves of the problem:

**Origin** is decisive against a browser and worthless against a native
process. A page on another site cannot forge the header, so this is what stops
some other web game quietly adopting this server as free infrastructure. It is
enforced on the **WebSocket upgrade** as well as on the API — CORS does not
apply to sockets, so without that the socket would be the unguarded way into a
server whose front door is locked. Default allowlist is the origins a Tauri
desktop build actually presents, plus loopback for development.

**Attestation** covers what Origin cannot. The desktop client signs a
server-issued challenge with a key compiled into its native binary — never into
the webview, which the player can read. The challenge is single-use and
short-lived, so a tag seen on the wire cannot be replayed, and the protocol
version, fingerprint and build are inside the signature rather than beside it.

Forging that means extracting a key from a stripped release executable. That is
possible for someone determined, and the source says so rather than claiming
otherwise — but it is a wholly different order of effort from copying a string
out of devtools, and it is the reason the game ships as a desktop application.

Neither check replaces the proof of work, the session token or the physics
validator. They are the outermost layer of several, and the only one whose job
is *is this my client?* rather than *is this abusive?*.

### What a shared secret in a public download is worth

Be clear about this one, because the client is downloadable and the honest
answer is uncomfortable: **a secret compiled into a public binary is not a
secret**. It ships to every user. `strings`, a breakpoint on the HMAC, or an
afternoon with a disassembler all recover it. That is not a weakness in this
implementation — it is unsolvable in principle. Any credential handed to the
user is a credential the user has.

So it is not an authentication mechanism, and treating it as one leads to bad
decisions. What it actually buys is two things, both real:

- **A cost floor.** It moves *use this server for my own thing* from "copy a
  URL" to "reverse-engineer a binary". That filters out essentially all casual
  misuse, which is the overwhelming majority of it.
- **A build cohort tag.** Because the key is per-release, it identifies which
  vintage of the game is calling — and that, combined with the version floor
  below, is what makes a leak recoverable instead of permanent.

The things that actually keep the server safe are elsewhere and do not depend
on any of this: the physics validator (a custom client still cannot teleport or
speed), the proof of work, the per-address limits, the capacity caps, and the
strike-and-ban table. Attestation is the outermost layer, not the load-bearing
one.

### Turning it on

`SYNX_CLIENT_SECRET` must contain a value the game was built with:

```bash
# building the game
SYNX_CLIENT_SECRET=<a value> cargo tauri build

# running the server
SYNX_CLIENT_SECRET=<the same value>
```

A server started **without** one accepts any client and says so, loudly, at
boot. That is deliberate: an unconfigured server that refused its own game
would be a worse failure than an open one that announces itself, and it means a
development build and a development server work together with no setup.

`SYNX_STRICT_CLIENT=false` checks and logs without refusing — for the afternoon
you are moving a deployment and locking yourself out is a real risk. It is not
a setting to leave on.

### Rotating a key without breaking what people have installed

`SYNX_CLIENT_SECRET` takes a **list**, and a client is admitted if it matches
any entry. That exists because the single-value version is a trap: with one
secret, changing it here instantly bricks every copy anyone has already
downloaded, so rotating the key and shipping the update could never be two
separate decisions.

With a list they are:

```bash
# 1. both work. Installed copies keep running.
SYNX_CLIENT_SECRET=<old>,<new>

# 2. ship the release built with <new>, and wait as long as you like.

# 3. drop <old>. THIS is what retires the builds carrying it -
#    at a moment you choose.
SYNX_CLIENT_SECRET=<new>
```

Every configured key is tried even after one matches. The work is a handful of
HMACs over a short message, and stopping early would leak — in the time taken
to answer — which key a client presented, which is the one thing somebody
holding a stolen old key would like to learn.

### Retiring a release: `SYNX_MIN_CLIENT`

The client's build string travels **inside** the attestation signature, so an
attested client cannot claim to be newer than it is. That makes the version
floor trustworthy, and it is checked *after* the signature for exactly that
reason — before it, it would be reading a field anybody could write.

```bash
SYNX_MIN_CLIENT=1.2.0     # 1.1.x is told to update, and is not admitted
```

This is the lever that makes a leaked key survivable without shipping anything:
raise the floor above the builds that carry the compromised key and they stop
being accepted, immediately, for everyone. A refused client gets `426` and
*this version of SYNX is no longer accepted*, which is a sentence a player can
act on.

Unset, any version is accepted.

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
| `SYNX_CLIENT_SECRET` | comma-separated keys the game may be built with; unset means any client is accepted |
| `SYNX_MIN_CLIENT` | oldest client build admitted, `major.minor.patch`; unset means any |
| `SYNX_STRICT_CLIENT` | refuse a client that fails the door, rather than logging it (default true) |
| `SYNX_ALLOWED_ORIGINS` | comma separated; defaults to the Tauri origins plus loopback |
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
