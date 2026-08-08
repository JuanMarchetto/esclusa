# Esclusa — Demo Narration (~100s)

Voice: plain, declarative, concrete verbs. No hype words. Target ~1.7 words/sec TTS.

---

**[SCENE 1 — Title card: "Esclusa" + tagline, fades in over a dark network diagram]**

AI coding agents now deploy and mutate real infrastructure. Nothing stands between one bad decision and your database.

**[SCENE 2 — Console homepage: topology cards for gate, console, db, cache, oldworker]**

Esclusa is a safety gate. Agents ask before they act, and every answer is signed into a tamper-evident ledger — then the gate checks reality.

**[SCENE 3 — Click "Delete the database"; card flashes red, refusal reason appears]**

The agent asks to delete the database. The gate refuses instantly, citing policy protect-stateful, and signs the refusal into the ledger.

**[SCENE 4 — Click "Retire a service, properly"; approval badge, probe counter ticking down, card goes gray]**

This time the agent asks first and is approved. The service goes offline, three probes fail, and the gate files an audited removal.

**[SCENE 5 — Click "Go behind the gate's back"; probe counter ticking, banner turns red: UNAUDITED DRIFT]**

Same removal, no approval on record. The gate flags unaudited drift with a red banner — the service genuinely stops answering, nothing simulated.

**[SCENE 6 — Ledger feed with HMAC column, /v1/ledger/verify JSON response below]**

Every ledger entry is HMAC-chained to the one before it. Edit any row, and verification breaks exactly there.

**[SCENE 7 — Architecture diagram: gate inside private VXLAN, arrows to db, cache, oldworker]**

The probes run inside the project's private network on Zerops. Managed Postgres holds the ledger, managed Valkey shares rate limits, and the watcher lives inside the infrastructure it guards.

**[SCENE 8 — Outro card: both URLs on screen]**

Console and gate, live now. Esclusa asks first, signs everything, and checks reality.

---

- Console: https://console-2a56.prg1.zerops.app
- Gate: https://gate-2a56-3000.prg1.zerops.app
