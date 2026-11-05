#!/usr/bin/env bash
# Runs the reproduction end to end: legacy stack up, attack chain, fiber cut, then forensic collection.
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p evidence/raw/attacker
chmod 777 evidence/raw/attacker
password="$(grep '^LEGACY_VPN_PASSWORD=' .env | cut -d= -f2)"
docker compose --profile legacy --profile tools up -d db-legacy panel-v1 legacy-vpn legacy-controller attacker
sleep 15
fiber_at=$(( ${DRAIN_WAIT:-180} / 2 ))
( sleep "$((fiber_at + 90))"; docker compose --profile legacy exec -T legacy-controller touch /tmp/fiber_down
  docker compose --profile tools exec -T attacker sh -c 'echo "$(date -Iseconds) STEP fiber_cut simulated" >> /out/incident_steps.log' ) &
docker compose --profile tools exec -T -e CAPTURED_PASSWORD="$password" -e DRAIN_WAIT="${DRAIN_WAIT:-180}" \
  attacker bash /attack/incident_chain.sh
wait
sleep 20
python3 forensics/collect_evidence.py "${1:-Lab team}"
python3 forensics/build_timeline.py
python3 forensics/analyze_memory.py
# The attacker's address is reused by the stolen-key scenario of the security suite.
docker compose --profile tools stop attacker >/dev/null
