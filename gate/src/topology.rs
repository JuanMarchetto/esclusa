//! Topology model: embedded seed, row mapping, queries.

use chrono::{DateTime, Utc};

use crate::ledger::ts_string;
use crate::policy::TopoView;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SeedService {
    pub hostname: String,
    pub service_type: String,
    #[serde(default)]
    pub stateful: bool,
    #[serde(default = "default_probe_method")]
    pub probe_method: String,
    #[serde(default)]
    pub tcp_port: Option<i32>,
}

fn default_probe_method() -> String {
    "none".to_string()
}

#[derive(Debug, serde::Deserialize)]
pub struct Snapshot {
    pub services: Vec<SeedService>,
}

/// seed.json is compiled in: the deploy ships only the binary.
pub fn seed() -> Vec<SeedService> {
    let snap: Snapshot =
        serde_json::from_str(include_str!("../seed.json")).expect("seed.json is valid JSON");
    snap.services
}

/// Returns an error string when the snapshot row is unusable (→ HTTP 400).
pub fn validate_service(s: &SeedService) -> Result<(), String> {
    if s.hostname.trim().is_empty() {
        return Err("hostname must not be empty".to_string());
    }
    match s.probe_method.as_str() {
        "none" | "dns" => Ok(()),
        "tcp" => match s.tcp_port {
            Some(p) if (1..=65535).contains(&p) => Ok(()),
            _ => Err(format!("service '{}': probe_method tcp requires tcp_port 1-65535", s.hostname)),
        },
        other => Err(format!("service '{}': unknown probe_method '{other}'", s.hostname)),
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TopoRow {
    pub hostname: String,
    pub service_type: String,
    pub stateful: bool,
    pub probe_method: String,
    pub tcp_port: Option<i32>,
    pub status: String,
    pub probe_ok: bool,
    pub consecutive_failures: i32,
    pub last_probe: Option<String>,
    pub updated_at: String,
}

fn row_from_pg(row: &tokio_postgres::Row) -> TopoRow {
    let last_probe: Option<DateTime<Utc>> = row.get("last_probe");
    let updated_at: DateTime<Utc> = row.get("updated_at");
    TopoRow {
        hostname: row.get("hostname"),
        service_type: row.get("service_type"),
        stateful: row.get("stateful"),
        probe_method: row.get("probe_method"),
        tcp_port: row.get("tcp_port"),
        status: row.get("status"),
        probe_ok: row.get("probe_ok"),
        consecutive_failures: row.get("consecutive_failures"),
        last_probe: last_probe.as_ref().map(ts_string),
        updated_at: ts_string(&updated_at),
    }
}

pub async fn all(
    client: &deadpool_postgres::Client,
) -> Result<Vec<TopoRow>, tokio_postgres::Error> {
    let rows = client
        .query("SELECT * FROM topology ORDER BY hostname", &[])
        .await?;
    Ok(rows.iter().map(row_from_pg).collect())
}

/// The minimal view the policy engine needs. Every row counts as "in the
/// model", whatever its status: the gate still knows the service exists.
pub async fn views(
    client: &deadpool_postgres::Client,
) -> Result<Vec<TopoView>, tokio_postgres::Error> {
    let rows = client
        .query("SELECT hostname, stateful FROM topology", &[])
        .await?;
    Ok(rows
        .iter()
        .map(|r| TopoView { hostname: r.get(0), stateful: r.get(1) })
        .collect())
}
