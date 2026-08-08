use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use deadpool_postgres::Pool;
use tokio::sync::RwLock;

pub struct AppState {
    pub db: Option<Pool>,
    /// Set once migrations + seeding have completed.
    pub db_ready: AtomicBool,
    pub cache: RwLock<Option<redis::aio::ConnectionManager>>,
    /// In-memory rate-limit fallback: ip -> (minute bucket, count).
    pub mem_rl: Mutex<HashMap<String, (u64, u32)>>,
    pub gate_token: Option<String>,
    pub signing_key: Vec<u8>,
    /// Unix seconds of the probe loop's last completed cycle.
    pub last_probe_cycle: AtomicU64,
}

pub type SharedState = Arc<AppState>;

impl AppState {
    /// A pooled client, only once the schema is ready. None = fail closed.
    pub async fn db_client(&self) -> Option<deadpool_postgres::Client> {
        if !self.db_ready.load(Ordering::Relaxed) {
            return None;
        }
        match &self.db {
            Some(pool) => pool.get().await.ok(),
            None => None,
        }
    }

    /// Constant-time check of a presented X-Gate-Token. False when GATE_TOKEN
    /// is not configured — auth fails closed.
    pub fn token_matches(&self, presented: Option<&str>) -> bool {
        match (&self.gate_token, presented) {
            (Some(expected), Some(got)) => ct_eq(expected.as_bytes(), got.as_bytes()),
            _ => false,
        }
    }
}

/// Constant-time byte comparison (only the length is allowed to leak).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_basics() {
        assert!(ct_eq(b"secret", b"secret"));
        assert!(!ct_eq(b"secret", b"secreT"));
        assert!(!ct_eq(b"secret", b"secret2"));
        assert!(!ct_eq(b"", b"x"));
        assert!(ct_eq(b"", b""));
    }
}
