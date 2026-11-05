#!/usr/bin/env bash
# Runs every suite once, in an order that avoids interference, then curates evidence/.
# The chaos test runs last and alone, so the resource figures are not distorted by the other suites.
set -uo pipefail
cd "$(dirname "$0")/.."
examiner="${1:-Lab team}"
# Measurements are worthless if the machine sleeps halfway, so sleep is blocked while this runs.
if [[ -z "${VAURORA_NO_SLEEP:-}" ]] && command -v systemd-inhibit >/dev/null; then
  exec env VAURORA_NO_SLEEP=1 systemd-inhibit --what=sleep:handle-lid-switch --who=vaurora --why="lab measurements" "$0" "$@"
fi
step() { echo "=== $(date '+%H:%M:%S') $*"; }

step "mail authentication"; scripts/run_mail_auth_test.sh | tail -3
step "incident and forensics"; DRAIN_WAIT=180 scripts/run_incident.sh "$examiner" | tail -40
step "security suite"; python3 tests/security/run_security_tests.py > evidence/raw/security_run.log 2>&1
grep -E '^\[FAIL\]' evidence/raw/security_run.log; tail -1 evidence/raw/security_run.log
step "phishing pipeline"; scripts/run_phishing_lab.sh --personas | tail -30
docker compose --profile phishing stop mailpit gophish phishing-runner >/dev/null
step "LLM evaluation"
scripts/pull_model.sh | tail -1
docker compose --profile llm up -d ollama llm-triage >/dev/null 2>&1
docker compose --profile llm build llm-triage >/dev/null 2>&1
docker compose --profile llm up -d llm-triage >/dev/null 2>&1
docker compose --profile llm exec -T llm-triage python -u evaluate.py | tail -14
docker compose --profile llm stop ollama llm-triage >/dev/null
step "accessibility"
docker build -q -t vaurora/a11y:1.0 tests/accessibility >/dev/null
docker run --rm --network vaurora_cloud -v "$PWD/secrets/lab/demo_users.json:/lab/demo_users.json:ro" \
  -v "$PWD/docs/results:/results" vaurora/a11y:1.0 | grep -E 'total_violations|overflow'
step "chaos test and resources"
python3 tests/resilience/measure_edge.py --minutes 36 > evidence/raw/resources_run.log 2>&1 &
python3 tests/resilience/chaos_test.py --minutes 35 | tail -3
wait
step "evidence"; python3 scripts/build_evidence.py
step "done"
