# Esclusa — Social Post (Zerops Challenge 2026)

## X / Twitter

### Main post (thread 1/4) — 265 chars

I built a gate that catches AI agents changing infra behind your back — trigger a real incident from the demo page. Esclusa signs every decision into a tamper-evident ledger, built on @zeropsio. Video attached. Live: https://console-2a56.prg1.zerops.app @WeMakeDevs

### Thread 2/4 — how it works (277 chars)

How it works: agents POST an intended action to /v1/evaluate. The gate checks it against live topology + ordered policies, answers allow/refuse, and HMAC-chains the entry to the one before it. A background loop probes every service every 15s to catch what an agent does anyway.

### Thread 3/4 — the drift demo (271 chars)

The console has 3 buttons, nothing to install. Ask first, get approved, service really goes offline → audited removal. Skip the gate, same removal → unaudited drift, red banner. Nothing simulated: a real Node beacon stops answering and the gate's probes catch it in ~45s.

### Thread 4/4 — the Zerops angle

Zerops angle: probes run inside the project's private network, no public exposure needed. Managed Postgres holds the ledger, managed Valkey shares rate limits across gate containers. The watcher lives inside the infra it guards. #ZeropsChallenge2026 @zeropsio

### Thread 5/5 — repo

Code, policies, and the full write-up: https://github.com/JuanMarchetto/esclusa — Rust gate, one-file console, 28 tests, honest notes on what a production version would add.

---

## LinkedIn

I built a gate that catches AI agents changing infrastructure behind your back — and you can trigger a real incident from the demo page.

Esclusa is a safety gate for agent-driven infrastructure on Zerops. Every mutating call a coding agent sends is checked against live topology before it runs: refused when it breaks policy, allowed and signed into a tamper-evident ledger when it doesn't, then checked against reality afterward so nothing slips through unaudited.

Built on Zerops: probes run inside the project's private network, managed Postgres holds the ledger, and managed Valkey shares rate limits across gate containers. The watcher lives inside the infrastructure it guards.

A short video of it running is attached.
Live demo: https://console-2a56.prg1.zerops.app
Code: https://github.com/JuanMarchetto/esclusa

Built solo for the Zerops Challenge. @WeMakeDevs @zeropsio
