#!/usr/bin/env bash
# Esclusa demo — the seven README steps as runnable curls.
#
# Steps 1-4 and 7 run directly against the public gate. Steps 5 and 6
# change live infrastructure, so this script prints the zcli commands
# instead of running them.
#
# Safe to run repeatedly: evaluate calls append ledger entries (that is
# the point) and every other call is read-only. No secrets are used or
# required.
#
# Usage: ./scripts/demo.sh                       (public gate)
#        GATE=http://localhost:3000 ./scripts/demo.sh

set -euo pipefail

GATE="${GATE:-https://gate-2a56-3000.prg1.zerops.app}"

step() { printf '\n=== %s\n' "$*"; }

evaluate() {
  # POST one intended action to the gate; allow and refuse both return 200.
  curl -sS -X POST "$GATE/v1/evaluate" \
    -H "content-type: application/json" \
    -d "$1"
  printf '\n'
}

step "1. Service info (GET /)"
curl -sS "$GATE/"
printf '\n'

step "2. Delete the database? Expect: refuse, policy protect-stateful"
evaluate '{"actor":"demo-script","action":"service.delete","target":"db"}'

step "3. Scale oldworker to zero? Expect: refuse, policy no-scale-to-zero"
evaluate '{"actor":"demo-script","action":"service.scale","target":"oldworker","params":{"minContainers":0}}'

step "4. Stop oldworker? Expect: allow, policy default-record"
evaluate '{"actor":"demo-script","action":"service.stop","target":"oldworker"}'

step "5 and 6. Taking the service offline for real"
cat <<EOF
The console does both from a browser, with no tooling:

    https://console-2a56.prg1.zerops.app

Or drive it from here. This asks the gate first, so the removal is
AUDITED — oldworker really stops answering for 90 s and restarts itself:

    curl -sS -X POST $GATE/v1/demo/decommission \\
      -H 'content-type: application/json' -d '{"approved":true}'

Wait for /v1/topology to show oldworker "present" again, then skip the
approval. Same removal, no authorisation on record, so it is DRIFT:

    curl -sS -X POST $GATE/v1/demo/decommission \\
      -H 'content-type: application/json' -d '{"approved":false}'

Either way the gate needs three failed probes, about 45 s. Watch it land:

    curl -sS $GATE/v1/drift

With zcli bound to the project, 'zcli service stop oldworker' does the
same thing the same way — the gate cannot tell the difference, which is
the point.
EOF

step "Current drift and audit entries (GET /v1/drift)"
curl -sS "$GATE/v1/drift"
printf '\n'

step "7. Verify the ledger HMAC chain (GET /v1/ledger/verify)"
curl -sS "$GATE/v1/ledger/verify"
printf '\n'

step "Done. Console: https://console-2a56.prg1.zerops.app"
