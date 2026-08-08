//! 30 req/min per client IP. Valkey INCR+EXPIRE keyed `rl:{ip}:{minute}` so
//! the limit is shared across containers; if the cache is unreachable, an
//! in-process map takes over.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use redis::AsyncCommands;

use crate::state::AppState;

const LIMIT: i64 = 30;

/// true = request allowed.
pub async fn check(state: &AppState, ip: &str) -> bool {
    let minute = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60;

    let mgr = state.cache.read().await.clone();
    if let Some(mut conn) = mgr {
        let key = format!("rl:{ip}:{minute}");
        let incr = tokio::time::timeout(Duration::from_millis(800), async {
            let count: i64 = conn.incr(&key, 1i64).await?;
            if count == 1 {
                let _: bool = conn.expire(&key, 120).await?;
            }
            Ok::<i64, redis::RedisError>(count)
        })
        .await;
        if let Ok(Ok(count)) = incr {
            return count <= LIMIT;
        }
        // cache down or slow → fall through to the in-memory limiter
    }

    let mut map = state.mem_rl.lock().unwrap_or_else(|e| e.into_inner());
    if map.len() > 4096 {
        map.retain(|_, (m, _)| *m == minute);
    }
    let entry = map.entry(ip.to_string()).or_insert((minute, 0));
    if entry.0 != minute {
        *entry = (minute, 0);
    }
    entry.1 += 1;
    i64::from(entry.1) <= LIMIT
}
