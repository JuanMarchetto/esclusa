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

step "5. Operator step (printed, not run)"
cat <<EOF
Run on a machine with zcli bound to this project:

    zcli service stop oldworker

The probe loop fails 3 times in ~45 s, finds the allow from step 4 in
the ledger, and marks oldworker removed-audited. Watch it land:

    curl -sS $GATE/v1/drift
EOF

step "6. Unaudited drift (printed, not run)"
cat <<EOF
Bring oldworker back, wait until /v1/topology shows it "present" again,
then stop it WITHOUT an evaluate call first:

    zcli service start oldworker
    zcli service stop oldworker

No matching allow this time, so /v1/drift gains a kind=drift entry.
EOF

step "Current drift and audit entries (GET /v1/drift)"
curl -sS "$GATE/v1/drift"
printf '\n'

step "7. Verify the ledger HMAC chain (GET /v1/ledger/verify)"
curl -sS "$GATE/v1/ledger/verify"
printf '\n'

step "Done. Console: https://console-2a56.prg1.zerops.app"
