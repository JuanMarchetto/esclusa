//! Tamper-evident ledger: canonical string + HMAC-SHA256 chain (pure), plus
//! the Postgres append/list/verify plumbing.

use chrono::{DateTime, SecondsFormat, Timelike, Utc};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;

use crate::db::ADVISORY_LOCK_KEY;

pub const GENESIS: &str = "genesis";

#[derive(Clone, Debug, serde::Serialize)]
pub struct Entry {
    pub id: i64,
    /// RFC3339 UTC with fixed microsecond precision — the exact string that
    /// entered the canonical form.
    pub ts: String,
    pub kind: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub decision: String,
    pub reason: String,
    pub policy: String,
    pub params: Value,
    pub authenticated: bool,
    pub prev_hmac: String,
    pub hmac: String,
}

/// Truncate to microseconds: Postgres timestamptz stores microseconds, and the
/// canonical string must survive a round-trip through the database.
pub fn now_micros() -> DateTime<Utc> {
    let now = Utc::now();
    now.with_nanosecond((now.nanosecond() / 1000) * 1000).unwrap_or(now)
}

pub fn ts_string(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

/// Append one field as `<byte-length>:<bytes>|`.
///
/// The length prefix is what makes the concatenation injective. A plain
/// `a|b|c` join is not: actor="x|service.delete" and action="y" would produce
/// the same bytes as actor="x" and action="service.delete|y", so a caller who
/// plants `|` in a free-form field could later rewrite the row's columns into
/// a different meaning that still recomputes to the stored HMAC.
fn push_field(out: &mut String, s: &str) {
    out.push_str(&s.len().to_string());
    out.push(':');
    out.push_str(s);
    out.push('|');
}

#[allow(clippy::too_many_arguments)]
pub fn canonical_string(
    id: i64,
    ts: &str,
    kind: &str,
    actor: &str,
    action: &str,
    target: &str,
    decision: &str,
    reason: &str,
    policy: &str,
    params: &Value,
    authenticated: bool,
    prev_hmac: &str,
) -> String {
    // serde_json's default map is ordered (BTreeMap), so compact serialization
    // is deterministic across the insert and verify paths.
    let params_json = serde_json::to_string(params).unwrap_or_else(|_| "null".to_string());
    let mut out = String::with_capacity(256);
    push_field(&mut out, &id.to_string());
    push_field(&mut out, ts);
    push_field(&mut out, kind);
    push_field(&mut out, actor);
    push_field(&mut out, action);
    push_field(&mut out, target);
    push_field(&mut out, decision);
    push_field(&mut out, reason);
    push_field(&mut out, policy);
    push_field(&mut out, &params_json);
    push_field(&mut out, if authenticated { "1" } else { "0" });
    push_field(&mut out, prev_hmac);
    out
}

pub fn entry_canonical(e: &Entry) -> String {
    canonical_string(
        e.id, &e.ts, &e.kind, &e.actor, &e.action, &e.target, &e.decision, &e.reason, &e.policy,
        &e.params, e.authenticated, &e.prev_hmac,
    )
}

/// Postgres `jsonb` normalizes numbers on the way in: `-0.0` comes back as
/// `0.0`, so a canonical string built from the client's value would not match
/// the one rebuilt at verify time. Canonicalize before signing instead.
pub fn normalize_params(v: &Value) -> Value {
    match v {
        // Only float negative zero is affected; integers round-trip unchanged.
        Value::Number(n) if n.is_f64() => match n.as_f64() {
            Some(f) if f == 0.0 && f.is_sign_negative() => serde_json::Number::from_f64(0.0)
                .map(Value::Number)
                .unwrap_or_else(|| v.clone()),
            _ => v.clone(),
        },
        Value::Array(a) => Value::Array(a.iter().map(normalize_params).collect()),
        Value::Object(o) => {
            Value::Object(o.iter().map(|(k, x)| (k.clone(), normalize_params(x))).collect())
        }
        _ => v.clone(),
    }
}

pub fn hmac_hex(key: &[u8], msg: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Debug, serde::Serialize)]
pub struct VerifyReport {
    pub valid: bool,
    pub checked: usize,
    pub head_hmac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<i64>,
}

/// Recompute the whole chain. `entries` must be ordered by id ascending.
pub fn verify_chain(key: &[u8], entries: &[Entry]) -> VerifyReport {
    let head_hmac = entries.last().map(|e| e.hmac.clone());
    let mut prev = GENESIS.to_string();
    for e in entries {
        let linked = e.prev_hmac == prev;
        let recomputed = hmac_hex(key, &entry_canonical(e));
        if !linked || recomputed != e.hmac {
            return VerifyReport {
                valid: false,
                checked: entries.len(),
                head_hmac,
                broken_at: Some(e.id),
            };
        }
        prev = e.hmac.clone();
    }
    VerifyReport { valid: true, checked: entries.len(), head_hmac, broken_at: None }
}

// ---------------------------------------------------------------------------
// Postgres plumbing
// ---------------------------------------------------------------------------

pub struct NewEntry<'a> {
    pub kind: &'a str,
    pub actor: &'a str,
    pub action: &'a str,
    pub target: &'a str,
    pub decision: &'a str,
    pub reason: &'a str,
    pub policy: &'a str,
    pub params: Value,
    pub authenticated: bool,
}

/// Append one entry. Serialized across all containers with a pg advisory
/// transaction lock: lock → read head → compute id/hmac → insert.
pub async fn append(
    client: &mut deadpool_postgres::Client,
    key: &[u8],
    new: NewEntry<'_>,
) -> Result<Entry, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    tx.execute("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_KEY]).await?;
    let head = tx
        .query_opt("SELECT id, hmac FROM ledger ORDER BY id DESC LIMIT 1", &[])
        .await?;
    let (prev_id, prev_hmac) = match head {
        Some(row) => (row.get::<_, i64>(0), row.get::<_, String>(1)),
        None => (0, GENESIS.to_string()),
    };
    let id = prev_id + 1;
    let ts_dt = now_micros();
    let ts = ts_string(&ts_dt);
    let params = normalize_params(&new.params);
    let canonical = canonical_string(
        id, &ts, new.kind, new.actor, new.action, new.target, new.decision, new.reason,
        new.policy, &params, new.authenticated, &prev_hmac,
    );
    let hmac = hmac_hex(key, &canonical);
    tx.execute(
        "INSERT INTO ledger (id, ts, kind, actor, action, target, decision, reason, policy, params, authenticated, prev_hmac, hmac) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        &[
            &id, &ts_dt, &new.kind, &new.actor, &new.action, &new.target, &new.decision,
            &new.reason, &new.policy, &params, &new.authenticated, &prev_hmac, &hmac,
        ],
    )
    .await?;
    tx.commit().await?;
    Ok(Entry {
        id,
        ts,
        kind: new.kind.to_string(),
        actor: new.actor.to_string(),
        action: new.action.to_string(),
        target: new.target.to_string(),
        decision: new.decision.to_string(),
        reason: new.reason.to_string(),
        policy: new.policy.to_string(),
        params,
        authenticated: new.authenticated,
        prev_hmac,
        hmac,
    })
}

pub fn entry_from_row(row: &tokio_postgres::Row) -> Entry {
    let ts: DateTime<Utc> = row.get("ts");
    Entry {
        id: row.get("id"),
        ts: ts_string(&ts),
        kind: row.get("kind"),
        actor: row.get("actor"),
        action: row.get("action"),
        target: row.get("target"),
        decision: row.get("decision"),
        reason: row.get("reason"),
        policy: row.get("policy"),
        params: row.get("params"),
        authenticated: row.get("authenticated"),
        prev_hmac: row.get("prev_hmac"),
        hmac: row.get("hmac"),
    }
}

/// Newest first. `kinds = None` lists everything.
pub async fn list(
    client: &deadpool_postgres::Client,
    limit: i64,
    offset: i64,
    kinds: Option<&[&str]>,
) -> Result<(Vec<Entry>, i64), tokio_postgres::Error> {
    let (rows, total) = match kinds {
        Some(ks) => {
            let rows = client
                .query(
                    "SELECT * FROM ledger WHERE kind = ANY($1) ORDER BY id DESC LIMIT $2 OFFSET $3",
                    &[&ks, &limit, &offset],
                )
                .await?;
            let total = client
                .query_one("SELECT count(*) FROM ledger WHERE kind = ANY($1)", &[&ks])
                .await?;
            (rows, total)
        }
        None => {
            let rows = client
                .query("SELECT * FROM ledger ORDER BY id DESC LIMIT $1 OFFSET $2", &[&limit, &offset])
                .await?;
            let total = client.query_one("SELECT count(*) FROM ledger", &[]).await?;
            (rows, total)
        }
    };
    Ok((rows.iter().map(entry_from_row).collect(), total.get(0)))
}

pub async fn all_ordered(
    client: &deadpool_postgres::Client,
) -> Result<Vec<Entry>, tokio_postgres::Error> {
    let rows = client.query("SELECT * FROM ledger ORDER BY id ASC", &[]).await?;
    Ok(rows.iter().map(entry_from_row).collect())
}

/// Is there an ALLOW for service.delete/service.stop of `target` in the last
/// 30 minutes that has not already been spent? Decides audited-removal vs
/// unaudited-drift.
///
/// An authorization covers exactly one removal: the allow must post-date the
/// last audit already recorded for this target. Without that clause, one
/// approved stop would launder every later stop of the same service for the
/// rest of the window.
pub async fn recent_allow_exists(
    client: &deadpool_postgres::Client,
    target: &str,
) -> Result<bool, tokio_postgres::Error> {
    let row = client
        .query_opt(
            "SELECT 1 FROM ledger WHERE kind='decision' AND decision='allow' \
             AND action IN ('service.delete','service.stop') AND target=$1 \
             AND ts > now() - interval '30 minutes' \
             AND ts > COALESCE( \
                 (SELECT max(ts) FROM ledger WHERE kind='audit' AND target=$1), \
                 to_timestamp(0)) \
             LIMIT 1",
            &[&target],
        )
        .await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const KEY: &[u8] = b"test-signing-key";

    fn build_entry(id: i64, prev_hmac: &str, reason: &str, params: Value) -> Entry {
        let ts = format!("2026-08-08T12:00:0{id}.000000Z");
        let mut e = Entry {
            id,
            ts,
            kind: "decision".to_string(),
            actor: "tester".to_string(),
            action: "service.stop".to_string(),
            target: "oldworker".to_string(),
            decision: "allow".to_string(),
            reason: reason.to_string(),
            policy: "default-record".to_string(),
            params,
            authenticated: false,
            prev_hmac: prev_hmac.to_string(),
            hmac: String::new(),
        };
        e.hmac = hmac_hex(KEY, &entry_canonical(&e));
        e
    }

    fn chain_of_three() -> Vec<Entry> {
        let e1 = build_entry(1, GENESIS, "first", json!({}));
        let e2 = build_entry(2, &e1.hmac, "second", json!({"minContainers": 2}));
        let e3 = build_entry(3, &e2.hmac, "third", json!({}));
        vec![e1, e2, e3]
    }

    #[test]
    fn canonical_string_format_is_pinned() {
        let c = canonical_string(
            7,
            "2026-08-08T12:00:00.000000Z",
            "decision",
            "a",
            "service.stop",
            "db",
            "refuse",
            "r",
            "p",
            &json!({"x": 1}),
            false,
            GENESIS,
        );
        assert_eq!(
            c,
            "1:7|27:2026-08-08T12:00:00.000000Z|8:decision|1:a|12:service.stop|2:db|6:refuse|1:r|1:p|7:{\"x\":1}|1:0|7:genesis|"
        );
    }

    /// A caller controls actor/action/target verbatim. Without length prefixes,
    /// planting a `|` lets one field absorb the next, so a row can later be
    /// rewritten into a different meaning that still recomputes to the stored
    /// HMAC — the exact attack the chain exists to detect.
    #[test]
    fn delimiter_in_a_field_cannot_forge_a_matching_canonical_string() {
        let planted = canonical_string(
            5,
            "2026-08-08T12:00:00.000000Z",
            "decision",
            "mallory|service.delete|db|allow|operator approved",
            "deploy.push",
            "noop",
            "allow",
            "recorded",
            "default-record",
            &json!({}),
            false,
            "prev",
        );
        let rewritten = canonical_string(
            5,
            "2026-08-08T12:00:00.000000Z",
            "decision",
            "mallory",
            "service.delete",
            "db",
            "allow",
            "operator approved|deploy.push|noop|allow|recorded",
            "default-record",
            &json!({}),
            false,
            "prev",
        );
        assert_ne!(planted, rewritten);
        assert_ne!(hmac_hex(KEY, &planted), hmac_hex(KEY, &rewritten));
    }

    /// `authenticated` is shown in the console and served by /v1/ledger, so it
    /// must be covered by the signature like every other displayed field.
    #[test]
    fn authenticated_flag_is_covered_by_the_signature() {
        let args = |auth: bool| {
            canonical_string(
                1,
                "2026-08-08T12:00:00.000000Z",
                "decision",
                "a",
                "service.stop",
                "db",
                "allow",
                "r",
                "p",
                &json!({}),
                auth,
                GENESIS,
            )
        };
        assert_ne!(hmac_hex(KEY, &args(false)), hmac_hex(KEY, &args(true)));
    }

    /// Postgres jsonb turns -0.0 into 0.0; normalizing before signing keeps the
    /// insert-time and verify-time canonical strings identical.
    #[test]
    fn negative_zero_is_normalized_before_signing() {
        let raw: Value = serde_json::from_str("{\"n\": -0.0}").unwrap();
        let normalized = normalize_params(&raw);
        assert_eq!(serde_json::to_string(&normalized).unwrap(), "{\"n\":0.0}");
        // integers must survive untouched
        let ints: Value = serde_json::from_str("{\"minContainers\": 0}").unwrap();
        assert_eq!(serde_json::to_string(&normalize_params(&ints)).unwrap(), "{\"minContainers\":0}");
    }

    #[test]
    fn params_serialization_is_key_ordered() {
        // insert path and verify path must produce the same compact JSON
        let v: Value = serde_json::from_str("{\"b\":2,\"a\":1}").unwrap();
        assert_eq!(serde_json::to_string(&v).unwrap(), "{\"a\":1,\"b\":2}");
    }

    #[test]
    fn chain_of_three_verifies() {
        let chain = chain_of_three();
        let report = verify_chain(KEY, &chain);
        assert!(report.valid);
        assert_eq!(report.checked, 3);
        assert_eq!(report.head_hmac.as_deref(), Some(chain[2].hmac.as_str()));
        assert!(report.broken_at.is_none());
    }

    #[test]
    fn empty_chain_is_valid() {
        let report = verify_chain(KEY, &[]);
        assert!(report.valid);
        assert_eq!(report.checked, 0);
        assert!(report.head_hmac.is_none());
    }

    #[test]
    fn tampered_field_breaks_at_that_id() {
        let mut chain = chain_of_three();
        chain[1].reason = "sEcond".to_string(); // one byte flipped
        let report = verify_chain(KEY, &chain);
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(2));
    }

    #[test]
    fn tampered_params_break_at_that_id() {
        let mut chain = chain_of_three();
        chain[1].params = json!({"minContainers": 0});
        let report = verify_chain(KEY, &chain);
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(2));
    }

    #[test]
    fn broken_linkage_breaks_at_the_link() {
        let mut chain = chain_of_three();
        chain[2].prev_hmac = format!("{}x", chain[1].hmac);
        let report = verify_chain(KEY, &chain);
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(3));
    }

    #[test]
    fn rewritten_history_cannot_relink_without_the_key() {
        // Attacker rewrites entry 2 and dutifully re-links entry 3's prev_hmac
        // — without the signing key entry 2's hmac cannot be recomputed.
        let mut chain = chain_of_three();
        chain[1].reason = "rewritten".to_string();
        chain[2].prev_hmac = chain[1].hmac.clone();
        let report = verify_chain(KEY, &chain);
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(2));
    }

    #[test]
    fn wrong_key_breaks_at_genesis() {
        let chain = chain_of_three();
        let report = verify_chain(b"other-key", &chain);
        assert!(!report.valid);
        assert_eq!(report.broken_at, Some(1));
    }
}
