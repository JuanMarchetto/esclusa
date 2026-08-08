//! Background probe loop: every 15 s (jittered) resolve/connect to every
//! probeable service and reconcile reality against the topology model.

use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::Utc;
use serde_json::json;

use crate::ledger::{self, NewEntry};
use crate::state::{AppState, SharedState};

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

pub async fn run(state: SharedState) {
    state.last_probe_cycle.store(unix_now(), Ordering::Relaxed);
    let mut db_ok_last = true;
    loop {
        // Sub-second clock noise stands in for a jitter source; not worth a
        // rand dependency.
        let jitter = Duration::from_millis(u64::from(Utc::now().timestamp_subsec_nanos() % 3000));
        tokio::time::sleep(Duration::from_secs(15) + jitter).await;
        cycle(&state, &mut db_ok_last).await;
        state.last_probe_cycle.store(unix_now(), Ordering::Relaxed);
    }
}

async fn cycle(state: &AppState, db_ok_last: &mut bool) {
    let Some(mut client) = state.db_client().await else {
        if *db_ok_last {
            println!("gate: probe loop idle — db unavailable");
            *db_ok_last = false;
        }
        return;
    };
    if !*db_ok_last {
        println!("gate: probe loop resumed — db available");
        *db_ok_last = true;
    }

    let rows = match client
        .query(
            // Keep probing removed services too: a hostname that answers again
            // must come back to 'present', otherwise one approved removal makes
            // that service invisible to the gate forever.
            "SELECT hostname, probe_method, tcp_port FROM topology \
             WHERE probe_method <> 'none'",
            &[],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gate: probe query failed: {e}");
            return;
        }
    };

    let mut set = tokio::task::JoinSet::new();
    for row in rows {
        let host: String = row.get(0);
        let method: String = row.get(1);
        let port: Option<i32> = row.get(2);
        set.spawn(async move {
            let ok = probe_one(&host, &method, port).await;
            (host, ok)
        });
    }

    while let Some(joined) = set.join_next().await {
        let Ok((host, ok)) = joined else { continue };
        if ok {
            handle_success(state, &mut client, &host).await;
        } else {
            handle_failure(state, &mut client, &host).await;
        }
    }
}

async fn probe_one(host: &str, method: &str, port: Option<i32>) -> bool {
    let attempt = async {
        match method {
            "dns" => tokio::net::lookup_host((host, 1u16)).await.is_ok(),
            "tcp" => match port {
                Some(p) => tokio::net::TcpStream::connect((host, p as u16)).await.is_ok(),
                None => false,
            },
            _ => true,
        }
    };
    tokio::time::timeout(Duration::from_secs(3), attempt).await.unwrap_or(false)
}

async fn handle_success(state: &AppState, client: &mut deadpool_postgres::Client, host: &str) {
    // The WHERE clause claims the missing→present transition exactly once
    // across containers.
    let reappeared = client
        .execute(
            "UPDATE topology SET status='present', probe_ok=TRUE, consecutive_failures=0, \
             last_probe=now(), updated_at=now() \
             WHERE hostname=$1 AND status IN ('missing-unaudited','removed-audited')",
            &[&host],
        )
        .await
        .unwrap_or(0)
        == 1;
    if reappeared {
        let entry = ledger::append(
            client,
            &state.signing_key,
            NewEntry {
                kind: "system",
                actor: "gate-probe",
                action: "probe.reappear",
                target: host,
                decision: "info",
                reason: "service answering again; status restored to present",
                policy: "",
                params: json!({}),
                authenticated: false,
            },
        )
        .await;
        match entry {
            Ok(_) => println!("gate: system: {host} reappeared -> present"),
            Err(e) => eprintln!("gate: ledger append failed for reappearance of {host}: {e}"),
        }
    } else {
        let _ = client
            .execute(
                "UPDATE topology SET probe_ok=TRUE, consecutive_failures=0, \
                 last_probe=now(), updated_at=now() WHERE hostname=$1",
                &[&host],
            )
            .await;
    }
}

async fn handle_failure(state: &AppState, client: &mut deadpool_postgres::Client, host: &str) {
    let row = match client
        .query_opt(
            "UPDATE topology SET probe_ok=FALSE, consecutive_failures=consecutive_failures+1, \
             last_probe=now(), updated_at=now() WHERE hostname=$1 \
             RETURNING consecutive_failures, status",
            &[&host],
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("gate: probe update failed for {host}: {e}");
            return;
        }
    };
    let Some(row) = row else { return };
    let failures: i32 = row.get(0);
    let status: String = row.get(1);
    // >= 3 (not == 3): with several containers probing, the counter can jump
    // past 3 between cycles; the claim below still fires exactly once.
    if failures < 3 || status != "present" {
        return;
    }

    let audited = ledger::recent_allow_exists(client, host).await.unwrap_or(false);
    let new_status = if audited { "removed-audited" } else { "missing-unaudited" };
    let claimed = client
        .execute(
            "UPDATE topology SET status=$2, updated_at=now() \
             WHERE hostname=$1 AND status='present'",
            &[&host, &new_status],
        )
        .await
        .unwrap_or(0)
        == 1;
    if !claimed {
        return; // another container already owned the transition
    }

    let (kind, decision, action, reason) = if audited {
        (
            "audit",
            "info",
            "probe.audit",
            format!("{host} stopped answering; matching allow found in the last 30 min — removal audited"),
        )
    } else {
        (
            "drift",
            "flag",
            "probe.drift",
            format!("{host} stopped answering after 3 consecutive probe failures with no matching allow — unaudited drift"),
        )
    };
    let entry = ledger::append(
        client,
        &state.signing_key,
        NewEntry {
            kind,
            actor: "gate-probe",
            action,
            target: host,
            decision,
            reason: &reason,
            policy: "",
            params: json!({ "consecutive_failures": failures }),
            authenticated: false,
        },
    )
    .await;
    match entry {
        Ok(_) => println!("gate: {kind}: {host} -> {new_status}"),
        Err(e) => eprintln!("gate: ledger append failed for {kind} on {host}: {e}"),
    }
}
