//! SYNX multiplayer server entry point and route setup.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

mod api;
mod client;
mod config;
mod control;
mod course;
mod hub;
mod identity;
mod limits;
mod maps;
mod room;
mod validate;
mod ws;

/// Stamped into the welcome, the health response and the log, so a bug report
/// can name the build it came from.
pub const BUILD: &str = concat!("synx-server ", env!("CARGO_PKG_VERSION"));

fn main() {
    // The runtime is built by hand rather than through `#[tokio::main]` for
    // one reason: the worker count.
    //
    // The default is one worker per CPU as the OS reports it, and a container
    // sees the whole host rather than its own share of it - so a process with
    // a fraction of a core spawns eight or sixteen workers that spend their
    // time contending for it and stealing work from each other. Two is enough
    // to keep a slow socket write from stalling a room tick, and small enough
    // that the scheduler is not the workload.
    let workers: usize = std::env::var("SYNX_WORKERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2)
        .clamp(1, 8);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name("synx")
        // 512 kB rather than the 2 MB default. Nothing here recurses and
        // nothing here has a large stack frame, so the rest is address space
        // reserved for no reason.
        .thread_stack_size(512 * 1024)
        .enable_all()
        .build()
        .expect("tokio runtime");

    rt.block_on(serve(workers));
}

async fn serve(workers: usize) {
    // Timestamps in the log even though the host adds its own, because the
    // host's are when it received the line and these are when it happened, and
    // under load those are not the same.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,synx_server=debug")),
        )
        .with_target(false)
        .with_level(true)
        .compact()
        .init();

    info!("===========================================================");
    info!("{BUILD}  protocol {}  workers {workers}", synx_net::PROTOCOL_VERSION);
    info!("===========================================================");

    let config = Arc::new(config::Config::from_env());
    config.log();

    // The road, before anything can connect. A server that cannot validate
    // must not accept players, so a bad asset is fatal here rather than a
    // surprise on the first packet.
    let course = Arc::new(course::Course::embedded());
    for m in maps::MAPS.iter() {
        info!(
            id = m.id,
            name = m.name,
            km = m.km(),
            from = m.from,
            to = m.to,
            corridor = m.road_half * 2.0,
            "route"
        );
    }

    let hub = hub::Hub::new(config.clone(), course);

    // CORS answers the browser's question - "may this page call you?" - using
    // the same allowlist the door itself uses, so a client is never told yes
    // by the preflight and no by the handler.
    //
    // A predicate rather than a fixed list, because the dev entries name a
    // host without a port and the harness serves the game from whatever port
    // it was given. `client::origin_allows` is the single place that decides.
    let cors = if config.allowed_origins.is_empty() {
        CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any)
    } else {
        let allowed = config.allowed_origins.clone();
        CorsLayer::new()
            .allow_origin(AllowOrigin::predicate(move |origin, _req| {
                origin
                    .to_str()
                    .map(|o| client::origin_allows(&allowed, o))
                    .unwrap_or(false)
            }))
            .allow_methods(Any)
            .allow_headers(Any)
    };

    let app = Router::new()
        .route("/", get(api::index))
        .route("/healthz", get(api::healthz))
        .route("/wake", get(api::wake))
        .route("/api/handshake", get(api::handshake))
        .route("/api/session", post(api::session))
        .route("/api/rooms", get(api::rooms))
        .route("/api/stats", get(api::stats))
        .route("/ws", get(ws::upgrade))
        .fallback(api::not_found)
        // Order is outermost-last. A request meets the timeout, then the body
        // limit, then the gate, then the handler - so a body that is too large
        // is refused before the gate spends a lock on it, and nothing can hold
        // a task open indefinitely.
        .layer(axum::middleware::from_fn_with_state(hub.clone(), api::gate))
        .layer(RequestBodyLimitLayer::new(16 * 1024))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            config.request_timeout,
        ))
        .layer(cors)
        .with_state(hub.clone());

    tokio::spawn(api::housekeeping(hub.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!(%addr, error = %e, "could not bind; is PORT already in use?");
            std::process::exit(1);
        }
    };

    hub.mark_ready();
    info!(%addr, "listening; the grid is open");

    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown(hub.clone()));

    if let Err(e) = server.await {
        error!(error = %e, "server stopped");
    }
    // One last line with the shape of the session, because it is often the
    // only record that the process was ever healthy.
    hub.housekeeping();
    info!("stopped");
}

/// Ctrl-C, or SIGTERM.
///
/// Rooms are told to close and the sockets are given a moment to drain, which
/// turns "everybody's connection died" into "the room closed" on the way
/// through a restart.
async fn shutdown(hub: Arc<hub::Hub>) {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("interrupted"),
        _ = terminate => info!("terminated"),
    }
    info!(rooms = hub.room_count(), players = hub.player_count(), "closing rooms");
    hub.close_all().await;
    tokio::time::sleep(Duration::from_millis(250)).await;
}
