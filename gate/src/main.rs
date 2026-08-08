//! Esclusa gate: policy gate + tamper-evident ledger + live topology probes.
//! Binds 0.0.0.0:3000 immediately; db/cache attach in the background so
//! /ready never depends on anything but the process itself.

mod db;
mod demo;
mod http;
mod ledger;
mod policy;
mod probe;
mod rate_limit;
mod state;
mod topology;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};

use state::AppState;
use tokio::sync::RwLock;

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::main]
async fn main() {
    let gate_token = env_nonempty("GATE_TOKEN");
    let signing_key = env_nonempty("LEDGER_SIGNING_KEY")
        .unwrap_or_else(|| {
            println!("gate: LEDGER_SIGNING_KEY not set — using an insecure dev key");
            "insecure-dev-signing-key".to_string()
        })
        .into_bytes();
    let database_url = env_nonempty("DATABASE_URL");
    let cache_url = env_nonempty("CACHE_URL");

    // Presence only — values are never logged.
    println!(
        "gate: GATE_TOKEN {}",
        if gate_token.is_some() { "set" } else { "absent — sync disabled, evaluate always unauthenticated" }
    );

    let pool = database_url.as_deref().and_then(db::make_pool);
    if database_url.is_some() && pool.is_none() {
        eprintln!("gate: DATABASE_URL is set but could not be parsed as a postgres config");
    }

    let state = Arc::new(AppState {
        db: pool,
        db_ready: AtomicBool::new(false),
        cache: RwLock::new(None),
        mem_rl: Mutex::new(HashMap::new()),
        gate_token,
        signing_key,
        last_probe_cycle: AtomicU64::new(0),
    });

    tokio::spawn(db::init_with_retry(state.clone()));
    match cache_url {
        Some(url) => {
            tokio::spawn(db::cache_connect_with_retry(state.clone(), url));
        }
        None => println!("gate: CACHE_URL not set — in-memory rate limiting only"),
    }
    tokio::spawn(probe::run(state.clone()));

    let app = http::router(state);
    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind 0.0.0.0:3000");
    println!("gate: listening on {addr}");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
        .await
        .expect("http server");
}
