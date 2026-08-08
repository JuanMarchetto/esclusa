//! Pool construction, schema migration and seeding, cache connection.
//! Everything here retries in the background: the HTTP server never waits.

use std::sync::atomic::Ordering;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use tokio_postgres::NoTls;

use crate::policy::POLICIES;
use crate::state::SharedState;
use crate::topology;

/// One fixed key serializes ledger appends and migrations across all
/// containers of the gate service.
pub const ADVISORY_LOCK_KEY: i64 = 0x6573_636c_7573; // "esclus"

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS ledger (
    id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL,
    kind TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'anonymous',
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    policy TEXT NOT NULL DEFAULT '',
    params JSONB NOT NULL DEFAULT '{}'::jsonb,
    authenticated BOOLEAN NOT NULL DEFAULT FALSE,
    prev_hmac TEXT NOT NULL,
    hmac TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ledger_kind_id_idx ON ledger (kind, id DESC);
CREATE INDEX IF NOT EXISTS ledger_target_ts_idx ON ledger (target, ts DESC);
CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    ord INTEGER NOT NULL,
    description TEXT NOT NULL,
    effect TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE TABLE IF NOT EXISTS topology (
    hostname TEXT PRIMARY KEY,
    service_type TEXT NOT NULL,
    stateful BOOLEAN NOT NULL DEFAULT FALSE,
    probe_method TEXT NOT NULL DEFAULT 'none',
    tcp_port INTEGER,
    status TEXT NOT NULL DEFAULT 'present',
    probe_ok BOOLEAN NOT NULL DEFAULT FALSE,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    last_probe TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
";

pub fn make_pool(url: &str) -> Option<Pool> {
    let cfg: tokio_postgres::Config = url.parse().ok()?;
    let mgr = Manager::from_config(
        cfg,
        NoTls,
        ManagerConfig { recycling_method: RecyclingMethod::Fast },
    );
    Pool::builder(mgr)
        .max_size(8)
        .runtime(Runtime::Tokio1)
        .create_timeout(Some(Duration::from_secs(5)))
        .wait_timeout(Some(Duration::from_secs(5)))
        .recycle_timeout(Some(Duration::from_secs(5)))
        .build()
        .ok()
}

/// Background task: migrate + seed with backoff, then mark db_ready.
pub async fn init_with_retry(state: SharedState) {
    let Some(pool) = state.db.clone() else {
        println!("gate: DATABASE_URL not set — ledger disabled, /v1/evaluate answers 503");
        return;
    };
    let mut delay = 2u64;
    loop {
        match init_once(&pool).await {
            Ok(()) => {
                state.db_ready.store(true, Ordering::Relaxed);
                println!("gate: db ready — schema migrated, policies and topology seeded");
                return;
            }
            Err(e) => {
                eprintln!("gate: db init failed ({e}); retrying in {delay}s");
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(30);
            }
        }
    }
}

async fn init_once(pool: &Pool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_KEY]).await?;
    tx.batch_execute(SCHEMA).await?;

    for (ord, (id, effect, description)) in POLICIES.iter().enumerate() {
        tx.execute(
            "INSERT INTO policies (id, ord, description, effect, enabled) \
             VALUES ($1,$2,$3,$4,TRUE) ON CONFLICT (id) DO NOTHING",
            &[id, &(ord as i32), description, effect],
        )
        .await?;
    }

    let count: i64 = tx.query_one("SELECT count(*) FROM topology", &[]).await?.get(0);
    if count == 0 {
        for s in topology::seed() {
            tx.execute(
                "INSERT INTO topology (hostname, service_type, stateful, probe_method, tcp_port, status, probe_ok, consecutive_failures, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,'present',FALSE,0,now()) ON CONFLICT (hostname) DO NOTHING",
                &[&s.hostname, &s.service_type, &s.stateful, &s.probe_method, &s.tcp_port],
            )
            .await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// Background task: connect the valkey connection manager (auto-reconnecting
/// after first success). Until it exists, rate limiting uses the in-memory map.
pub async fn cache_connect_with_retry(state: SharedState, url: String) {
    let client = match redis::Client::open(url.as_str()) {
        Ok(c) => c,
        Err(_) => {
            // Deliberately not printing the parse error: it can echo the URL.
            eprintln!("gate: CACHE_URL is not a valid redis URL — in-memory rate limiting only");
            return;
        }
    };
    let mut delay = 2u64;
    loop {
        match client.get_connection_manager().await {
            Ok(mgr) => {
                *state.cache.write().await = Some(mgr);
                println!("gate: cache connected — shared rate limiting active");
                return;
            }
            Err(_) => {
                eprintln!("gate: cache connect failed; retrying in {delay}s");
                tokio::time::sleep(Duration::from_secs(delay)).await;
                delay = (delay * 2).min(30);
            }
        }
    }
}
