//! Router and handlers. Decisions are data (200 for allow AND refuse);
//! infrastructure trouble is status codes (503 fail-closed, 401, 429, 400).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::{header, HeaderMap, HeaderName, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use tower_http::cors::{Any, CorsLayer};

use crate::demo;
use crate::ledger::{self, NewEntry};
use crate::policy::{self, Effect};
use crate::rate_limit;
use crate::state::SharedState;
use crate::topology::{self, Snapshot};

pub fn router(state: SharedState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([header::CONTENT_TYPE, HeaderName::from_static("x-gate-token")]);

    Router::new()
        .route("/", get(root))
        .route("/ready", get(|| async { "ready" }))
        .route("/healthz", get(healthz))
        .route("/v1/evaluate", post(evaluate))
        .route("/v1/ledger", get(ledger_list))
        .route("/v1/ledger/verify", get(ledger_verify))
        .route("/v1/policies", get(policies))
        .route("/v1/topology", get(topology_get))
        .route("/v1/drift", get(drift))
        .route("/v1/topology/sync", post(topology_sync))
        .route("/v1/demo/decommission", post(demo_decommission))
        .layer(cors)
        .with_state(state)
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({ "error": msg }))).into_response()
}

fn unavailable() -> Response {
    err(
        StatusCode::SERVICE_UNAVAILABLE,
        "ledger unavailable — the gate fails closed",
    )
}

fn header_token(headers: &HeaderMap) -> Option<&str> {
    headers.get("x-gate-token").and_then(|v| v.to_str().ok())
}

/// First X-Forwarded-For value (set by the Zerops L7 balancer), else peer addr.
fn client_ip(headers: &HeaderMap, peer: SocketAddr) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| peer.ip().to_string())
}

// ---------------------------------------------------------------------------

async fn root() -> Json<Value> {
    Json(json!({
        "name": "esclusa-gate",
        "version": env!("CARGO_PKG_VERSION"),
        "description": "Esclusa — policy gate and tamper-evident audit ledger for agent-driven infrastructure on Zerops",
        "endpoints": [
            { "method": "GET",  "path": "/",                 "auth": "none",                    "purpose": "service info" },
            { "method": "GET",  "path": "/ready",            "auth": "none",                    "purpose": "process readiness (no db dependency)" },
            { "method": "GET",  "path": "/healthz",          "auth": "none",                    "purpose": "subsystem health booleans" },
            { "method": "POST", "path": "/v1/evaluate",      "auth": "optional X-Gate-Token",   "purpose": "evaluate a proposed action; decision is recorded in the ledger" },
            { "method": "GET",  "path": "/v1/ledger",        "auth": "none",                    "purpose": "ledger entries, newest first (?limit&offset)" },
            { "method": "GET",  "path": "/v1/ledger/verify", "auth": "none",                    "purpose": "recompute the full HMAC chain" },
            { "method": "GET",  "path": "/v1/policies",      "auth": "none",                    "purpose": "policy list" },
            { "method": "GET",  "path": "/v1/topology",      "auth": "none",                    "purpose": "topology model and live probe state" },
            { "method": "GET",  "path": "/v1/drift",         "auth": "none",                    "purpose": "drift/audit ledger entries, newest first" },
            { "method": "POST", "path": "/v1/topology/sync", "auth": "X-Gate-Token required",   "purpose": "replace probe set from a fresh snapshot; flag unexplained removals" },
            { "method": "POST", "path": "/v1/demo/decommission", "auth": "none",                "purpose": "drives the console scenarios: really takes the decommission target offline, with or without asking first" }
        ]
    }))
}

async fn healthz(State(st): State<SharedState>) -> Json<Value> {
    let db = match st.db_client().await {
        Some(client) => tokio::time::timeout(Duration::from_secs(2), client.query_one("SELECT 1", &[]))
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false),
        None => false,
    };
    let cache = {
        let mgr = st.cache.read().await.clone();
        match mgr {
            // A container that is still connecting its cache reports false here
            // and falls back to in-process rate limiting, which is why `ok`
            // below does not depend on the cache.
            Some(mut conn) => tokio::time::timeout(
                Duration::from_secs(3),
                redis::cmd("PING").query_async::<String>(&mut conn),
            )
            .await
            .map(|r| r.is_ok())
            .unwrap_or(false),
            None => false,
        }
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let probes = now.saturating_sub(st.last_probe_cycle.load(Ordering::Relaxed)) < 60;
    Json(json!({ "ok": db && probes, "db": db, "cache": cache, "probes": probes }))
}

// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct EvaluateReq {
    actor: Option<String>,
    action: Option<String>,
    target: Option<String>,
    params: Option<Value>,
}

async fn evaluate(
    State(st): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&headers, peer);
    if !rate_limit::check(&st, &ip).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded (30 req/min per client)");
    }

    let req: EvaluateReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return err(StatusCode::BAD_REQUEST, "malformed JSON body"),
    };
    let Some(action) = req.action.filter(|a| !a.trim().is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "missing required field: action");
    };
    let Some(target) = req.target.filter(|t| !t.trim().is_empty()) else {
        return err(StatusCode::BAD_REQUEST, "missing required field: target");
    };
    let actor = req.actor.filter(|a| !a.trim().is_empty()).unwrap_or_else(|| "anonymous".to_string());
    let params = req.params.unwrap_or_else(|| json!({}));
    let authenticated = st.token_matches(header_token(&headers));

    // Fail closed: no ledger, no decision.
    let Some(mut client) = st.db_client().await else { return unavailable() };
    let Ok(topo) = topology::views(&client).await else { return unavailable() };
    let Ok(enabled) = load_enabled(&client).await else { return unavailable() };

    let d = policy::evaluate(&action, &target, &params, &topo, &enabled);
    let decision = match d.effect {
        Effect::Allow => "allow",
        Effect::Refuse => "refuse",
    };
    let entry = match ledger::append(
        &mut client,
        &st.signing_key,
        NewEntry {
            kind: "decision",
            actor: &actor,
            action: &action,
            target: &target,
            decision,
            reason: &d.reason,
            policy: d.policy,
            params,
            authenticated,
        },
    )
    .await
    {
        Ok(e) => e,
        Err(_) => {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger write failed — decision not recorded, the gate fails closed",
            )
        }
    };

    Json(json!({
        "decision": decision,
        "reason": d.reason,
        "policy": d.policy,
        "entry": {
            "id": entry.id,
            "ts": entry.ts,
            "hmac": entry.hmac,
            "prev_hmac": entry.prev_hmac
        }
    }))
    .into_response()
}

async fn load_enabled(
    client: &deadpool_postgres::Client,
) -> Result<HashMap<String, bool>, tokio_postgres::Error> {
    let rows = client.query("SELECT id, enabled FROM policies", &[]).await?;
    Ok(rows.iter().map(|r| (r.get(0), r.get(1))).collect())
}

// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct Page {
    limit: Option<i64>,
    offset: Option<i64>,
}

async fn ledger_list(State(st): State<SharedState>, Query(page): Query<Page>) -> Response {
    let limit = page.limit.unwrap_or(100).clamp(1, 500);
    let offset = page.offset.unwrap_or(0).max(0);
    let Some(client) = st.db_client().await else { return unavailable() };
    match ledger::list(&client, limit, offset, None).await {
        Ok((entries, total)) => Json(json!({ "entries": entries, "total": total })).into_response(),
        Err(_) => unavailable(),
    }
}

async fn drift(State(st): State<SharedState>, Query(page): Query<Page>) -> Response {
    let limit = page.limit.unwrap_or(100).clamp(1, 500);
    let offset = page.offset.unwrap_or(0).max(0);
    let Some(client) = st.db_client().await else { return unavailable() };
    match ledger::list(&client, limit, offset, Some(&["drift", "audit"])).await {
        Ok((entries, total)) => Json(json!({ "entries": entries, "total": total })).into_response(),
        Err(_) => unavailable(),
    }
}

async fn ledger_verify(State(st): State<SharedState>) -> Response {
    let Some(client) = st.db_client().await else { return unavailable() };
    match ledger::all_ordered(&client).await {
        Ok(entries) => Json(ledger::verify_chain(&st.signing_key, &entries)).into_response(),
        Err(_) => unavailable(),
    }
}

async fn policies(State(st): State<SharedState>) -> Response {
    let Some(client) = st.db_client().await else { return unavailable() };
    let rows = match client
        .query("SELECT id, description, effect, enabled FROM policies ORDER BY ord", &[])
        .await
    {
        Ok(r) => r,
        Err(_) => return unavailable(),
    };
    let list: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<_, String>(0),
                "description": r.get::<_, String>(1),
                "effect": r.get::<_, String>(2),
                "enabled": r.get::<_, bool>(3)
            })
        })
        .collect();
    Json(json!({ "policies": list })).into_response()
}

async fn topology_get(State(st): State<SharedState>) -> Response {
    let Some(client) = st.db_client().await else { return unavailable() };
    match topology::all(&client).await {
        Ok(services) => Json(json!({ "services": services })).into_response(),
        Err(_) => unavailable(),
    }
}

// ---------------------------------------------------------------------------

/// Drives the console's guided scenarios. `approved: true` asks the gate for
/// permission first (a real evaluate, recorded like any other); `false` skips
/// straight to the removal, which is what makes it drift. Either way the target
/// is genuinely knocked offline — nothing here fakes a status.
#[derive(serde::Deserialize)]
struct DemoReq {
    approved: Option<bool>,
}

async fn demo_decommission(
    State(st): State<SharedState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let ip = client_ip(&headers, peer);
    if !rate_limit::check(&st, &ip).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded (30 req/min per client)");
    }
    let approved = serde_json::from_slice::<DemoReq>(&body)
        .ok()
        .and_then(|r| r.approved)
        .unwrap_or(false);

    let Some(mut client) = st.db_client().await else { return unavailable() };
    let Ok(topo) = topology::views(&client).await else { return unavailable() };

    // One demo at a time: if the target is already down, the previous run is
    // still playing out and a second trigger would muddle the story.
    let Ok(rows) = topology::all(&client).await else { return unavailable() };
    match rows.iter().find(|t| t.hostname == demo::target()) {
        None => return err(StatusCode::CONFLICT, "the decommission target is not in the topology model"),
        Some(t) if t.status != "present" => {
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "a decommission is already in progress",
                    "target": demo::target(),
                    "status": t.status
                })),
            )
                .into_response()
        }
        Some(_) => {}
    }

    let mut decision = None;
    if approved {
        let Ok(enabled) = load_enabled(&client).await else { return unavailable() };
        let params = json!({});
        let d = policy::evaluate("service.stop", demo::target(), &params, &topo, &enabled);
        let verdict = match d.effect {
            Effect::Allow => "allow",
            Effect::Refuse => "refuse",
        };
        let entry = ledger::append(
            &mut client,
            &st.signing_key,
            NewEntry {
                kind: "decision",
                actor: "console-demo",
                action: "service.stop",
                target: demo::target(),
                decision: verdict,
                reason: &d.reason,
                policy: d.policy,
                params,
                authenticated: st.token_matches(header_token(&headers)),
            },
        )
        .await;
        let Ok(entry) = entry else {
            return err(
                StatusCode::SERVICE_UNAVAILABLE,
                "ledger write failed — decision not recorded, the gate fails closed",
            );
        };
        // The gate refusing its own demo would be a policy change, not a bug —
        // honour it rather than knocking the service over anyway.
        if verdict == "refuse" {
            return Json(json!({
                "started": false,
                "approved": true,
                "decision": verdict,
                "reason": d.reason,
                "policy": d.policy,
                "entry": { "id": entry.id, "hmac": entry.hmac }
            }))
            .into_response();
        }
        decision = Some(json!({
            "decision": verdict,
            "reason": d.reason,
            "policy": d.policy,
            "entry": { "id": entry.id, "hmac": entry.hmac }
        }));
    }

    if let Err(e) = demo::play_dead(demo::PLAYDEAD_SECONDS).await {
        eprintln!("gate: demo decommission failed: {e}");
        return err(StatusCode::BAD_GATEWAY, "could not reach the decommission target");
    }

    Json(json!({
        "started": true,
        "approved": approved,
        "target": demo::target(),
        "offlineSeconds": demo::PLAYDEAD_SECONDS,
        "probeIntervalSeconds": 15,
        "failuresNeeded": 3,
        "expect": if approved { "removed-audited" } else { "missing-unaudited" },
        "expectKind": if approved { "audit" } else { "drift" },
        "authorization": decision
    }))
    .into_response()
}

async fn topology_sync(
    State(st): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !st.token_matches(header_token(&headers)) {
        return err(StatusCode::UNAUTHORIZED, "missing or invalid X-Gate-Token");
    }
    let snap: Snapshot = match serde_json::from_slice(&body) {
        Ok(s) => s,
        Err(_) => {
            return err(
                StatusCode::BAD_REQUEST,
                "malformed body: expected {\"services\": [{hostname, service_type, stateful, probe_method, tcp_port}]}",
            )
        }
    };
    for s in &snap.services {
        if let Err(msg) = topology::validate_service(s) {
            return err(StatusCode::BAD_REQUEST, &msg);
        }
    }

    let Some(mut client) = st.db_client().await else { return unavailable() };
    let Ok(current) = topology::all(&client).await else { return unavailable() };
    let existing: HashMap<String, String> =
        current.iter().map(|r| (r.hostname.clone(), r.status.clone())).collect();
    let snapshot_hosts: HashSet<&str> = snap.services.iter().map(|s| s.hostname.as_str()).collect();

    let mut added: Vec<String> = Vec::new();
    let mut updated: Vec<String> = Vec::new();
    let mut removed_audited: Vec<String> = Vec::new();
    let mut removed_unaudited: Vec<String> = Vec::new();

    for s in &snap.services {
        let is_new = !existing.contains_key(&s.hostname);
        // The snapshot is authoritative: whatever the row's previous status,
        // a service present in the snapshot is present again.
        let res = client
            .execute(
                "INSERT INTO topology (hostname, service_type, stateful, probe_method, tcp_port, status, probe_ok, consecutive_failures, updated_at) \
                 VALUES ($1,$2,$3,$4,$5,'present',FALSE,0,now()) \
                 ON CONFLICT (hostname) DO UPDATE SET \
                   service_type=EXCLUDED.service_type, stateful=EXCLUDED.stateful, \
                   probe_method=EXCLUDED.probe_method, tcp_port=EXCLUDED.tcp_port, \
                   status='present', consecutive_failures=0, updated_at=now()",
                &[&s.hostname, &s.service_type, &s.stateful, &s.probe_method, &s.tcp_port],
            )
            .await;
        if res.is_err() {
            return unavailable();
        }
        if is_new {
            added.push(s.hostname.clone());
        } else {
            updated.push(s.hostname.clone());
        }
    }

    for row in &current {
        if snapshot_hosts.contains(row.hostname.as_str()) || row.status != "present" {
            continue; // still present, or already flagged/resolved earlier
        }
        let audited = ledger::recent_allow_exists(&client, &row.hostname).await.unwrap_or(false);
        let new_status = if audited { "removed-audited" } else { "missing-unaudited" };
        if client
            .execute(
                "UPDATE topology SET status=$2, updated_at=now() WHERE hostname=$1 AND status='present'",
                &[&row.hostname, &new_status],
            )
            .await
            .is_err()
        {
            return unavailable();
        }
        let (kind, decision, action, reason) = if audited {
            ("audit", "info", "sync.audit",
             format!("{} absent from synced snapshot; matching allow found — removal audited", row.hostname))
        } else {
            ("drift", "flag", "sync.drift",
             format!("{} absent from synced snapshot with no matching allow — unaudited removal", row.hostname))
        };
        let appended = ledger::append(
            &mut client,
            &st.signing_key,
            NewEntry {
                kind,
                actor: "topology-sync",
                action,
                target: &row.hostname,
                decision,
                reason: &reason,
                policy: "",
                params: json!({}),
                authenticated: true,
            },
        )
        .await;
        if appended.is_err() {
            return unavailable();
        }
        if audited {
            removed_audited.push(row.hostname.clone());
        } else {
            removed_unaudited.push(row.hostname.clone());
        }
    }

    let summary = json!({
        "added": added,
        "updated": updated,
        "removed_audited": removed_audited,
        "removed_unaudited": removed_unaudited
    });
    let recorded = ledger::append(
        &mut client,
        &st.signing_key,
        NewEntry {
            kind: "system",
            actor: "topology-sync",
            action: "topology.sync",
            target: "",
            decision: "info",
            reason: "topology snapshot synced",
            policy: "",
            params: summary.clone(),
            authenticated: true,
        },
    )
    .await;
    if recorded.is_err() {
        return unavailable();
    }
    Json(summary).into_response()
}
