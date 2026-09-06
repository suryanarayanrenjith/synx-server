# SYNX multiplayer server.
#
# Two stages, because the thing that gets deployed should be the binary and not
# the compiler that produced it. The runtime image is a few megabytes, which on
# a free instance is the difference between a cold start of seconds and one of
# minutes - and a cold start is the only latency a player on this tier actually
# notices.

# ---------------------------------------------------------------- build ----
FROM rust:1.88-slim-bookworm AS build
WORKDIR /src

# The manifests first, on their own layer. Dependencies change far less often
# than the code does, so this layer is reused across almost every deploy and
# turns a four-minute build into a forty-second one.
COPY Cargo.toml Cargo.lock ./
COPY protocol/Cargo.toml protocol/Cargo.toml
COPY synx-server/Cargo.toml synx-server/Cargo.toml
RUN mkdir -p protocol/src synx-server/src \
 && echo 'fn main() {}' > synx-server/src/main.rs \
 && echo '' > protocol/src/lib.rs \
 && cargo build --release --locked 2>/dev/null || true

# Now the real sources. `touch` because cargo decides what to rebuild from
# modification times, and COPY can preserve one older than the stub above.
COPY protocol protocol
COPY synx-server synx-server
RUN touch protocol/src/lib.rs synx-server/src/main.rs \
 && cargo build --release --locked

# -------------------------------------------------------------- runtime ----
# Debian slim rather than distroless or Alpine: the binary is glibc-linked, and
# `slim` still gives a shell for the one case where the host lets you into a
# container. It is 30 MB.
FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Not root. There is nothing in this container worth having, but a process that
# does not need privileges should not have them.
RUN useradd --system --create-home --uid 10001 synx
USER synx
WORKDIR /home/synx

COPY --from=build /src/target/release/synx-server /usr/local/bin/synx-server

# The host overrides this; the default is what a local `docker run` uses.
ENV PORT=10000 \
    RUST_LOG=info,synx_server=debug \
    RUST_BACKTRACE=1
EXPOSE 10000

# A container that knows whether it is working.
#
# Render is told the health path separately in render.yaml, but a plain
# `docker run` - or Compose, or a swarm, or anything else somebody deploys this
# under - has no idea this process has a health endpoint unless the image says
# so. `/healthz` answers without touching a lock or a room, so probing it every
# thirty seconds costs nothing.
#
# `start-period` is generous because the course asset is parsed at boot; until
# that is done the server is up but not ready, and failing the probe during
# startup would restart-loop a container that was about to be fine.
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3   CMD ["/usr/local/bin/synx-server", "--health"]

# The course asset is compiled into the binary (see src/course.rs), so there is
# nothing to mount and nothing to go missing.
ENTRYPOINT ["/usr/local/bin/synx-server"]
