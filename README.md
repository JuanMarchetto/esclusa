# Esclusa

A safety gate for agent-driven infrastructure on Zerops. Every mutating call a coding agent sends to the platform is evaluated against the live service topology before it runs — refused when it violates policy, allowed and recorded when it doesn't, and checked against reality afterward so nothing slips through unaudited.

Built solo for the Zerops Challenge, August 8–9, 2026.

- Console: https://console-2a56.prg1.zerops.app
- Gate API: https://gate-2a56-3000.prg1.zerops.app
- Demo video (97 s): https://youtu.be/-iKw1haZ34E

## How it works

The gate never executes a platform action. It authorizes actions, records every decision in a tamper-evident ledger, and probes the private network to catch what happened anyway. The whole mechanism works without a Zerops API token.

### Evaluate — before the action

Agents POST the action they intend to run to `/v1/evaluate`. The gate checks the action against its topology model and an ordered policy set. It answers `allow` or `refuse` and appends a signed entry to the ledger in Postgres. Each entry's HMAC-SHA256 covers the entry content plus the previous entry's HMAC. Any edit to a past row breaks the chain at that row, and `/v1/ledger/verify` reports where. If the database is down, the gate fails closed: 503, no recorded decision, no allow.

### Observe — after the action

The gate lives inside the project's private network. A background loop probes each service every 15 s (plus up to 3 s of jitter) with a TCP connect, or a DNS lookup for services without a known port. When a service the model lists as `present` fails three probes in a row, the gate checks the ledger:

- A matching `allow` entry (`service.stop` or `service.delete`, same target, last 30 minutes) → audited: status `removed-audited`, plus an `audit` ledger entry.
- No matching entry → unaudited drift: status `missing-unaudited`, plus a `drift` ledger entry.
- A service that answers again returns to `present`, plus a `system` entry. This holds for audited removals too, so a host that comes back is never invisible to the gate.

An authorization covers exactly one removal. The `allow` has to post-date the last `audit` recorded for that target, so approving one stop does not launder every later stop of the same service for the rest of the window. That is what makes step 6 of the demo produce drift rather than a second audit.

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
         +--------------+              | 1-2 containers  |
                                       +-----------------+
                                          |   |   |   |
       ------ private VXLAN, plain TCP; probes every 15 s ------
          |             |               |                |
       db:5432     cache:6379     oldworker:3000     console:80
       postgres    valkey         node beacon        (probe target)
       ledger,     shared         decommission
       topology    rate limit     target

       gate, storage, zcp: in the topology model with probe "none"
       (self, or no private endpoint to probe)
```

The console page runs in your browser and calls the gate's public URL directly; the gate's CORS allows any origin for GET and POST. The gate stores the ledger and the topology model in Postgres. It uses Valkey to share the rate limit across up to two gate containers. `oldworker` is a small HTTP beacon that exists to be decommissioned in the demo.

## How Zerops is used

The core idea only works because of one platform property: **every service in a Zerops project sits on a private VXLAN with internal DNS**, and the gate container is on it too. That is what lets the probe loop resolve `db`, `cache`, and `oldworker` by hostname and open real TCP connections to them every 15 s from inside the project — not through a public endpoint, not through an API poll, but the same way any other service on the network would see them. A gate built as an external SaaS product could only ever trust what an agent told it happened. This one watches. Take away the private network and the "observe" half of the product — the part that turns unaudited drift into something the gate can actually catch — has no way to exist.

Concretely, the project uses:

- **7 services, one project**: `gate` (rust@1), `console` (static), `oldworker` (nodejs@22), `db` (postgresql:single@17), `cache` (valkey:ha@7.2), `storage` (object-storage), `zcp` (zcp@1) — see `zerops-project-import.yml`.
- **Managed Postgres and Valkey, wired with cross-service env refs.** `zerops.yaml` sets `DATABASE_URL: ${db_connectionString}` and `CACHE_URL: ${cache_connectionString}` on the gate's `run.envVariables`; Zerops resolves both only inside the running container, so no connection string ever appears in this repo or on the developer's machine.
- **Generated secrets at import time.** `zerops-project-import.yml` provisions `GATE_TOKEN` and `LEDGER_SIGNING_KEY` with `<@generateRandomString(...)>` and injects them as env secrets — the gate never ships a default token.
- **Public subdomains** on `gate` and `console` (`enableSubdomainAccess: true`), so the demo runs from a browser with nothing installed and the TLS-terminating L7 balancer sits in front of both.
- **Split build/run pipelines per service** in `zerops.yaml`: the gate builds with `cargo build --release` on `rust@1` and runs the compiled binary; `oldworker` and `console` build and run separately. Deploy is `zcli push <service>` per pipeline.
- **A real readiness gate**: the gate's `deploy.readinessCheck` polls `GET /ready` before Zerops considers a deploy healthy, matching the `/ready` endpoint's job of answering before the database is even attached.
- **HA scaling from 1 to 2 containers** (`minContainers: 1, maxContainers: 2` on the live `gate` service) drives two concrete design decisions, not just a config knob: the ledger append uses a Postgres advisory lock (`pg_advisory_xact_lock`) so concurrent containers can't race the hash chain, and the rate limiter is backed by Valkey specifically so "30 requests per minute per client IP" means the same thing regardless of which container answers a given request.

Honestly, **`storage` (object-storage) and `zcp` are provisioned in `zerops-project-import.yml` but the app never calls either.** They exist in the topology model with `probe_method: none` — the gate lists them as known services but has no private endpoint to probe, and no code path in `gate/src` touches object storage or the zcp service. They were provisioned as part of the challenge's service surface and left unused rather than wired in for the sake of a checkbox.

## Architectural decisions

- **Length-prefixed canonical string for the HMAC chain.** Each ledger field is encoded as `<byte-length>:<bytes>|` before signing (`gate/src/ledger.rs::push_field`). A plain `|`-joined string is not injective — a value like `actor="x|service.delete"` could be rewritten later into `actor="x", action="service.delete"` and still hash to the same bytes. Length-prefixing makes the encoding injective, so a planted delimiter can't forge a colliding row. Covered by a dedicated test (`delimiter_in_a_field_cannot_forge_a_matching_canonical_string`).
- **Fail-closed `/v1/evaluate`.** If the gate can't get a database client, or the ledger append fails, the endpoint returns 503 and appends nothing (`gate/src/http.rs`). There is no code path that produces an `allow` or `refuse` without a durable, signed row behind it — an unreachable ledger means no decision, not a silent allow.
- **Single-use authorizations.** `recent_allow_exists` (`gate/src/ledger.rs`) requires the `allow` to post-date the most recent `audit` already recorded for that target. Without that clause, one approved stop would retroactively cover every later stop of the same service for the rest of the 30-minute window; with it, one authorization covers exactly one removal.
- **Probes keep watching removed-audited hosts, not just present ones.** The probe query is `WHERE probe_method <> 'none'` with no filter on status (`gate/src/probe.rs`), so a host that was audited-removed and later comes back still gets picked up and flipped to `present` with a `system`/`probe.reappear` entry. A resurrected hostname is never invisible to the gate.
- **A Postgres advisory transaction lock serializes ledger appends across containers.** `pg_advisory_xact_lock` in `ledger::append` means the lock → read-head → compute-id/hmac → insert sequence is atomic even with multiple gate containers running concurrently under HA scaling — no two containers can compute the same next id or fork the chain.
- **No HTTP client crate for internal calls.** `gate/src/demo.rs` hand-rolls a single fixed HTTP/1.1 POST over a raw `TcpStream` to call `oldworker`'s `/playdead`. It's the only outbound call the gate makes to another service, to one fixed host and port, so a full client dependency (reqwest is not in `Cargo.toml`) would be weight the codebase doesn't need.
- **The demo endpoint knocks a real service over instead of faking a status.** `POST /v1/demo/decommission` calls `oldworker`'s `/playdead`, which really closes its listener for 90 s (`oldworker` self-recovers). Scenarios 2 and 3 in the console produce genuine probe failures, not a scripted status flip — the wait while probes fail is the proof, not a UI animation.

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
| POST | `/v1/demo/decommission` | none | Drives the console scenarios: really takes the decommission target offline, with or without asking first |

`POST /v1/evaluate` request:

```json
{"actor": "claude-code", "action": "service.delete", "target": "db", "params": {}}
```

`actor` defaults to `anonymous`. A request with a valid `x-gate-token` marks the entry as authenticated. Both decisions return HTTP 200 — the decision is data:

```json
{"decision": "refuse", "policy": "protect-stateful",
 "reason": "'db' is a stateful service; service.delete risks irreversible data loss",
 "entry": {"id": 42, "ts": "2026-08-08T12:00:00Z", "hmac": "...", "prev_hmac": "..."}}
```

Errors: 400 for a malformed body, 401 for a missing or invalid token on `/v1/topology/sync`, 429 over the rate limit (30 requests per minute per client IP), 503 when the ledger database is down.

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

## Demo — open the console

https://console-2a56.prg1.zerops.app has three buttons. They need nothing installed.

| | Scenario | What happens |
|---|---|---|
| 1 | Delete the database | Refused on `protect-stateful`, and the refusal is signed into the ledger. Instant. |
| 2 | Retire a service, properly | Asks the gate first, then really takes `oldworker` offline. Three probes fail and the gate files an **audited** removal. About 45 s. |
| 3 | Go behind the gate's back | Takes `oldworker` offline with no approval on record. Same three probes, but this time the gate flags **unaudited drift** and the banner goes red. About 45 s. |

Scenarios 2 and 3 are not simulated. `oldworker` exposes `POST /playdead`, which
closes its listener for 90 s; the gate calls it through
`POST /v1/demo/decommission`. The service genuinely stops answering, so the
probe failures are real failures. It restarts itself, the gate refuses to start
a second run while one is in flight, and `oldworker` exists for no other purpose.

While it runs, each card counts the probes as they fail. That wait is the point:
it is the difference between claiming something watches the network and showing it.

## Demo — from a terminal

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

## AI disclosure

This project was built with Claude Code (Anthropic) driving implementation, review, and deployment, including multi-agent workflows used for parallel build work and adversarial code review. The author — solo, for this hackathon — directed the scope, the design decisions (the policy set, the ledger's fail-closed and single-use-authorization rules, the probe-keeps-watching behavior, what the demo would actually have to do to be honest), and the priorities for what got built versus deferred. The code, architecture, and this README reflect that direction; they were not accepted unreviewed.
