#!/usr/bin/env bash
# RT-10: publishes SPF/DKIM/DMARC in the lab DNS and verifies a legitimate and a forged message.
set -euo pipefail
cd "$(dirname "$0")/.."
out=docs/results/mail_auth_results.txt
image=vaurora/mail-auth:1.0
docker compose --profile mail up -d --build lab-dns mail-receiver >/dev/null 2>&1
sleep 4
# The mailbox folders are created by the root-owned container, so they are cleared the same way.
docker run --rm -v "$PWD/evidence/raw:/raw" --entrypoint sh "$image" -c "rm -rf /raw/mail/inbox /raw/mail/quarantine"
{
  echo "# RT-10 mail authentication run, $(date -Iseconds)"
  for name in vilaaurora.example mail._domainkey.vilaaurora.example _dmarc.vilaaurora.example; do
    echo "\$ dig +short TXT $name"
    docker run --rm --network vaurora_mail --entrypoint dig "$image" +short TXT "$name" @172.27.0.53 | cut -c1-140
  done
  docker run --rm --network vaurora_mail --ip 172.27.0.10 -v "$PWD/secrets/mail:/keys:ro" "$image" python send_test_mail.py legit
  docker run --rm --network vaurora_mail --ip 172.27.0.66 -v "$PWD/secrets/mail:/keys:ro" "$image" python send_test_mail.py forged
  sleep 2
  echo "--- verdicts recorded by the receiving MTA"
  docker compose --profile mail logs --no-log-prefix mail-receiver | grep vilaaurora-mail | tail -2
  echo "--- mailbox folders"
  (cd evidence/raw/mail && find . -name '*.eml' | sort)
} | tee "$out"
