//! Pure policy engine: ordered rules, first match wins. No I/O.

use serde_json::Value;
use std::collections::HashMap;

/// (id, effect, description) in engine order. Seeded into the `policies`
/// table on first boot; the engine order itself is fixed in `evaluate`.
pub const POLICIES: &[(&str, &str, &str)] = &[
    (
        "protect-stateful",
        "refuse",
        "Refuse service.delete/service.stop when the target is a stateful service (db, cache, storage).",
    ),
    (
        "protect-spine",
        "refuse",
        "Refuse service.delete/service.stop/env.delete against gate or console — the gate defends its own audit surface.",
    ),
    (
        "no-scale-to-zero",
        "refuse",
        "Refuse service.scale with params.minContainers == 0.",
    ),
    (
        "secret-shield",
        "refuse",
        "Refuse env.set/env.delete when params.key ends with _KEY, _TOKEN, _SECRET or PASSWORD (case-insensitive).",
    ),
    (
        "unknown-target",
        "refuse",
        "Refuse service.*/env.* actions whose target is not in the topology model; for service.create, refuse only on hostname collision.",
    ),
    (
        "default-record",
        "allow",
        "Allow everything else and record it in the ledger.",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Refuse,
}

#[derive(Debug, Clone)]
pub struct Decision {
    pub effect: Effect,
    pub policy: &'static str,
    pub reason: String,
}

/// The slice of the topology model the engine needs.
#[derive(Debug, Clone)]
pub struct TopoView {
    pub hostname: String,
    pub stateful: bool,
}

fn refuse(policy: &'static str, reason: String) -> Decision {
    Decision { effect: Effect::Refuse, policy, reason }
}

pub fn evaluate(
    action: &str,
    target: &str,
    params: &Value,
    topo: &[TopoView],
    enabled: &HashMap<String, bool>,
) -> Decision {
    let on = |id: &str| enabled.get(id).copied().unwrap_or(true);
    let known = topo.iter().any(|t| t.hostname == target);
    let stateful = topo.iter().any(|t| t.hostname == target && t.stateful);

    if on("protect-stateful")
        && matches!(action, "service.delete" | "service.stop")
        && stateful
    {
        return refuse(
            "protect-stateful",
            format!("'{target}' is a stateful service; {action} risks irreversible data loss"),
        );
    }

    if on("protect-spine")
        && matches!(target, "gate" | "console")
        && matches!(action, "service.delete" | "service.stop" | "env.delete")
    {
        return refuse(
            "protect-spine",
            format!("'{target}' is part of the audit spine; the gate refuses {action} against its own surface"),
        );
    }

    if on("no-scale-to-zero") && action == "service.scale" && min_containers_is_zero(params) {
        return refuse(
            "no-scale-to-zero",
            format!("scaling '{target}' to minContainers=0 silently removes the service; use an explicit stop"),
        );
    }

    if on("secret-shield") && matches!(action, "env.set" | "env.delete") {
        if let Some(key) = secret_key(params) {
            return refuse(
                "secret-shield",
                format!("env key '{key}' looks like a credential; the gate refuses to touch secrets"),
            );
        }
    }

    if on("unknown-target") {
        if action == "service.create" {
            if known {
                return refuse(
                    "unknown-target",
                    format!("hostname '{target}' already exists in the topology model"),
                );
            }
        } else if (action.starts_with("service.") || action.starts_with("env.")) && !known {
            return refuse(
                "unknown-target",
                format!("'{target}' is not in the topology model; the gate cannot evaluate what it cannot see"),
            );
        }
    }

    Decision {
        effect: Effect::Allow,
        policy: "default-record",
        reason: "no refusal policy matched; action allowed and recorded".to_string(),
    }
}

fn min_containers_is_zero(params: &Value) -> bool {
    match params.get("minContainers") {
        Some(v) => v.as_i64() == Some(0) || v.as_f64() == Some(0.0),
        None => false,
    }
}

/// Returns the offending key when it matches `(_KEY|_TOKEN|_SECRET|PASSWORD)$`
/// case-insensitively.
fn secret_key(params: &Value) -> Option<String> {
    let key = params.get("key")?.as_str()?;
    let up = key.to_ascii_uppercase();
    ["_KEY", "_TOKEN", "_SECRET", "PASSWORD"]
        .iter()
        .any(|s| up.ends_with(s))
        .then(|| key.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn topo() -> Vec<TopoView> {
        [
            ("gate", false),
            ("console", false),
            ("db", true),
            ("cache", true),
            ("storage", true),
            ("oldworker", false),
            ("zcp", false),
        ]
        .into_iter()
        .map(|(h, s)| TopoView { hostname: h.to_string(), stateful: s })
        .collect()
    }

    fn all_on() -> HashMap<String, bool> {
        HashMap::new() // absent = enabled
    }

    fn run(action: &str, target: &str, params: Value) -> Decision {
        evaluate(action, target, &params, &topo(), &all_on())
    }

    // --- protect-stateful ---

    #[test]
    fn protect_stateful_refuses_delete_and_stop_of_stateful() {
        for action in ["service.delete", "service.stop"] {
            for target in ["db", "cache", "storage"] {
                let d = run(action, target, json!({}));
                assert_eq!(d.effect, Effect::Refuse, "{action} {target}");
                assert_eq!(d.policy, "protect-stateful");
            }
        }
    }

    #[test]
    fn protect_stateful_passes_non_stateful_and_other_actions() {
        let d = run("service.delete", "oldworker", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");

        let d = run("service.start", "db", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");
    }

    #[test]
    fn protect_stateful_disabled_falls_through() {
        let mut enabled = all_on();
        enabled.insert("protect-stateful".to_string(), false);
        let d = evaluate("service.delete", "db", &json!({}), &topo(), &enabled);
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");
    }

    // --- protect-spine ---

    #[test]
    fn protect_spine_refuses_stop_delete_envdelete_on_spine() {
        for action in ["service.delete", "service.stop", "env.delete"] {
            for target in ["gate", "console"] {
                let d = run(action, target, json!({}));
                assert_eq!(d.effect, Effect::Refuse, "{action} {target}");
                assert_eq!(d.policy, "protect-spine");
            }
        }
    }

    #[test]
    fn protect_spine_passes_other_actions_and_targets() {
        let d = run("env.set", "gate", json!({"key": "LOG_LEVEL"}));
        assert_eq!(d.effect, Effect::Allow);

        let d = run("service.stop", "oldworker", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");
    }

    // --- no-scale-to-zero ---

    #[test]
    fn no_scale_to_zero_refuses_min_containers_zero() {
        let d = run("service.scale", "oldworker", json!({"minContainers": 0}));
        assert_eq!(d.effect, Effect::Refuse);
        assert_eq!(d.policy, "no-scale-to-zero");
    }

    #[test]
    fn no_scale_to_zero_passes_nonzero_or_absent() {
        let d = run("service.scale", "oldworker", json!({"minContainers": 1}));
        assert_eq!(d.effect, Effect::Allow);

        let d = run("service.scale", "oldworker", json!({}));
        assert_eq!(d.effect, Effect::Allow);
    }

    #[test]
    fn no_scale_to_zero_precedes_unknown_target() {
        // Spec order: rule 3 before rule 5.
        let d = run("service.scale", "ghost", json!({"minContainers": 0}));
        assert_eq!(d.effect, Effect::Refuse);
        assert_eq!(d.policy, "no-scale-to-zero");
    }

    // --- secret-shield ---

    #[test]
    fn secret_shield_refuses_credential_keys_case_insensitive() {
        for key in ["API_TOKEN", "api_token", "MASTER_KEY", "client_secret", "DB_PASSWORD", "ROOTPASSWORD"] {
            let d = run("env.set", "oldworker", json!({"key": key}));
            assert_eq!(d.effect, Effect::Refuse, "key {key}");
            assert_eq!(d.policy, "secret-shield");
        }
        let d = run("env.delete", "oldworker", json!({"key": "SOME_KEY"}));
        assert_eq!(d.effect, Effect::Refuse);
        assert_eq!(d.policy, "secret-shield");
    }

    #[test]
    fn secret_shield_passes_plain_keys_and_other_actions() {
        let d = run("env.set", "oldworker", json!({"key": "LOG_LEVEL"}));
        assert_eq!(d.effect, Effect::Allow);

        // suffix must anchor at the end
        let d = run("env.set", "oldworker", json!({"key": "PASSWORD_HINT"}));
        assert_eq!(d.effect, Effect::Allow);

        // non-env action with a scary param is not shielded
        let d = run("deploy.push", "oldworker", json!({"key": "API_TOKEN"}));
        assert_eq!(d.effect, Effect::Allow);
    }

    // --- unknown-target ---

    #[test]
    fn unknown_target_refuses_service_and_env_actions_on_ghosts() {
        let d = run("service.stop", "ghost", json!({}));
        assert_eq!(d.effect, Effect::Refuse);
        assert_eq!(d.policy, "unknown-target");

        let d = run("env.set", "ghost", json!({"key": "LOG_LEVEL"}));
        assert_eq!(d.effect, Effect::Refuse);
        assert_eq!(d.policy, "unknown-target");
    }

    #[test]
    fn unknown_target_service_create_refuses_only_collisions() {
        let d = run("service.create", "oldworker", json!({}));
        assert_eq!(d.effect, Effect::Refuse);
        assert_eq!(d.policy, "unknown-target");

        let d = run("service.create", "newsvc", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");
    }

    #[test]
    fn unknown_target_ignores_non_service_env_verbs() {
        let d = run("deploy.push", "ghost", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");
    }

    // --- default-record ---

    #[test]
    fn default_record_allows_everything_else() {
        let d = run("deploy.push", "gate", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");

        let d = run("database.vacuum", "db", json!({}));
        assert_eq!(d.effect, Effect::Allow);
        assert_eq!(d.policy, "default-record");
    }

    #[test]
    fn order_stateful_wins_over_spine_class_rules() {
        // db is stateful and known: rule 1 must answer, not rule 5.
        let d = run("service.stop", "db", json!({}));
        assert_eq!(d.policy, "protect-stateful");
        // gate is spine but not stateful: rule 2 answers.
        let d = run("service.stop", "gate", json!({}));
        assert_eq!(d.policy, "protect-spine");
    }
}
