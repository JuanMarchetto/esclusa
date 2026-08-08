# Esclusa

A safety gate for agent-driven infrastructure on Zerops. Every mutating call a coding agent sends to the platform is evaluated against the live service topology before it runs — refused when it violates policy, allowed and recorded when it doesn't, and checked against reality afterward so nothing slips through unaudited.

Built solo for the Zerops Challenge, August 8–9, 2026.

- Gate API: https://gate-2a56-3000.prg1.zerops.app
- Console: https://console-2a56.prg1.zerops.app

## How it works

The gate never executes a platform action. It authorizes actions, records every decision in a tamper-evident ledger, and probes the private network to catch what happened anyway. The whole mechanism works without a Zerops API token.

### Evaluate — before the action

Agents POST the action they intend to run to `/v1/evaluate`. The gate checks the action against its topology model and an ordered policy set. It answers `allow` or `refuse` and appends a signed entry to the ledger in Postgres. Each entry's HMAC-SHA256 covers the entry content plus the previous entry's HMAC. Any edit to a past row breaks the chain at that row, and `/v1/ledger/verify` reports where. If the database is down, the gate fails closed: 503, no recorded decision, no allow.

### Observe — after the action

The gate lives inside the project's private network. A background loop probes each service every 15 s with a DNS lookup or a TCP connect. When a service the model lists as `present` fails three probes in a row, the gate checks the ledger:

- A matching `allow` entry (`service.stop` or `service.delete`, same target, last 30 minutes) → audited: status `removed-audited`, plus an `audit` ledger entry.
- No matching entry → unaudited drift: status `missing-unaudited`, plus a `drift` ledger entry.
- A missing service that answers again returns to `present`, plus a `system` entry.

### Sync — admin reconciliation

An operator POSTs a fresh topology snapshot (from `zerops_discover` or `zcli`) to `/v1/topology/sync`. The gate diffs the snapshot against its model and flags removals that no ledger entry explains.

```bash
curl -X POST https://gate-2a56-3000.prg1.zerops.app/v1/topology/sync \
  -H "x-gate-token: $GATE_TOKEN" \
  -H "content-type: application/json" \
  -d @snapshot.json
```

Zerops injects `GATE_TOKEN` into the gate container at start. Reference it as an environment variable only — the value belongs in no command line, file, or README.

## Architecture

```
                              internet
                                 |
                Zerops L7 balancer (TLS terminates here)
                 |                              |
  https://console-2a56...          https://gate-2a56-3000...
                 |                              |
         +--------------+              +-----------------+
         |   console    |              |      gate       |
         | static HTML  |              | Rust/axum :3000 |
         +--------------+              | 1-3 containers  |
                                       +-----------------+
                                          |   |   |   |
       ------ private VXLAN, plain TCP; probes every 15 s ------
          |             |               |                |
       db:5432     cache:6379     oldworker:3000     console:80
       postgres    valkey         node beacon        (probe target)
       ledger,     shared         decommission
       topology    rate limit     target

       storage, zcp: in the topology model with probe "none"
       (no private endpoint to probe)
```

The console page runs in your browser and calls the gate's public URL directly; the gate's CORS allows any origin for GET and POST. The gate stores the ledger and the topology model in Postgres. It uses Valkey to share the rate limit across up to three gate containers. `oldworker` is a small HTTP beacon that exists to be decommissioned in the demo.

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | none | Service info: name, version, endpoint list |
| GET | `/ready` | none | Plain 200 `ready`; process-level, no database dependency |
| GET | `/healthz` | none | `{ok, db, cache, probes}` subsystem booleans |
| POST | `/v1/evaluate` | optional `x-gate-token` | Evaluate a proposed action |
| GET | `/v1/ledger?limit&offset` | none | Ledger entries, newest first: `{entries, total}` |
| GET | `/v1/ledger/verify` | none | Recompute the full HMAC chain: `{valid, checked, head_hmac, broken_at?}` |
| GET | `/v1/policies` | none | Policy list: `{id, description, effect, enabled}` |
| GET | `/v1/topology` | none | Topology model plus live probe state |
| GET | `/v1/drift` | none | Ledger entries of kind `drift` and `audit`, newest first |
| POST | `/v1/topology/sync` | required `x-gate-token` | Replace the probe set, diff, flag unexplained removals |

`POST /v1/evaluate` request:

```json
{"actor": "claude-code", "action": "service.delete", "target": "db", "params": {}}
```

`actor` defaults to `anonymous`. A request with a valid `x-gate-token` marks the entry as authenticated. Both decisions return HTTP 200 — the decision is data:

```json
{"decision": "refuse", "reason": "db is stateful", "policy": "protect-stateful",
 "entry": {"id": 42, "ts": "2026-08-08T12:00:00Z", "hmac": "...", "prev_hmac": "..."}}
```

Errors: 400 for a malformed body, 429 over the rate limit (30 requests per minute per client IP), 503 when the ledger database is down.

## Policies

First match wins; the gate records every decision, allows included.

| # | Policy | Effect | Matches |
|---|---|---|---|
| 1 | `protect-stateful` | refuse | `service.delete` or `service.stop` on a stateful service (db, cache, storage) |
| 2 | `protect-spine` | refuse | `service.delete`, `service.stop`, or `env.delete` on gate or console — the gate defends its own audit surface |
| 3 | `no-scale-to-zero` | refuse | `service.scale` with `params.minContainers == 0` |
| 4 | `secret-shield` | refuse | `env.set` or `env.delete` where the key ends in `_KEY`, `_TOKEN`, `_SECRET`, or `PASSWORD` |
| 5 | `unknown-target` | refuse | `service.*` or `env.*` on a hostname missing from the topology model; for `service.create`, refuse only on a hostname collision |
| 6 | `default-record` | allow | Everything else — allowed but recorded |

## Demo — seven steps

`scripts/demo.sh` runs the curl steps (1–4 and 7) and prints the operator steps. Or paste them yourself:

```bash
GATE=https://gate-2a56-3000.prg1.zerops.app

# 1. Service info.
curl -s "$GATE/"

# 2. Delete the database? Refused: protect-stateful.
curl -s -X POST "$GATE/v1/evaluate" -H "content-type: application/json" \
  -d '{"actor":"readme-demo","action":"service.delete","target":"db"}'

# 3. Scale oldworker to zero? Refused: no-scale-to-zero.
curl -s -X POST "$GATE/v1/evaluate" -H "content-type: application/json" \
  -d '{"actor":"readme-demo","action":"service.scale","target":"oldworker","params":{"minContainers":0}}'

# 4. Stop oldworker? Allowed and recorded: default-record.
curl -s -X POST "$GATE/v1/evaluate" -H "content-type: application/json" \
  -d '{"actor":"readme-demo","action":"service.stop","target":"oldworker"}'

# 5. Operator: stop it for real. Within ~45 s the gate matches the
#    allow from step 4 and marks oldworker removed-audited.
zcli service stop oldworker
curl -s "$GATE/v1/drift"

# 6. Unaudited drift: bring it back, wait for "present" in /v1/topology,
#    then stop it again WITHOUT asking the gate.
zcli service start oldworker
zcli service stop oldworker
curl -s "$GATE/v1/drift"        # now shows a kind=drift entry

# 7. Prove the history was not rewritten.
curl -s "$GATE/v1/ledger/verify"
```

The console shows the same story live: topology cards change color, a drift banner appears, and the ledger feed refreshes every 5 s.

## Local development

The gate is a standard cargo project:

```bash
cd gate
cargo test    # policy engine + HMAC chain; pure logic, no network
cargo run     # listens on 0.0.0.0:3000
```

All four environment variables (`GATE_TOKEN`, `LEDGER_SIGNING_KEY`, `DATABASE_URL`, `CACHE_URL`) are optional locally. Without a database, `/ready` still answers and `/v1/evaluate` returns 503 — the same fail-closed path as production. Point `DATABASE_URL` at any Postgres to get the full behavior.

The console is one file. Open `console/index.html` in a browser; from `file://` it targets the public gate by default, and `?gate=https://...` overrides that. The oldworker beacon is `node oldworker/server.js`.

## Deploy

`zerops.yaml` at the repo root defines all three pipelines; build and run are separate containers.

```bash
zcli push gate        # cargo build --release on rust@1, /ready readiness check
zcli push console     # console/ on a static runtime
zcli push oldworker   # node server.js on nodejs@22
```

Zerops injects `GATE_TOKEN` and `LEDGER_SIGNING_KEY` into the gate container. `zerops.yaml` maps `DATABASE_URL` and `CACHE_URL` from the managed db and cache connection strings; the values resolve inside the container, never on your machine.

## What a production version would add

- Topology from the source of truth: read the service list from the Zerops API with a project token, instead of a committed seed plus manual sync.
- Real enforcement: today the observe phase catches agents that skip the gate; nothing blocks them. A production gate would proxy the platform API itself, so a refuse stops the call.
- Identity: SSO and per-agent credentials instead of one shared `GATE_TOKEN`.
- Operations: alerting on drift entries, and rotation of the ledger signing key.
