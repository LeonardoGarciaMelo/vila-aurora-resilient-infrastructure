#!/usr/bin/env bash
# Starts the isolated phishing lab and prints how to use it. Pass --personas to validate the pipeline.
set -euo pipefail
cd "$(dirname "$0")/.."
docker compose --profile phishing up -d mailpit gophish phishing-runner
sleep 12
tmp="$(mktemp -d)"
docker cp vaurora-gophish-1:/opt/gophish/gophish.db "$tmp/gophish.db"
key="$(python3 -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('select api_key from users limit 1').fetchone()[0])" "$tmp/gophish.db")"
rm -rf "$tmp"
runner=(docker compose --profile phishing exec -T phishing-runner python3 /phishing/run_campaign.py --key "$key")
case "${1:-}" in
  --personas) "${runner[@]}" --personas ;;
  --manual) "${runner[@]}" --manual "${2:?campaign name}" ;;
  --export) "${runner[@]}" --export "${2:?behaviour source}" ${3:+--exclude "$3"} ;;
  *) echo "usage: $0 --personas | --manual <name> | --export <behaviour source>"; exit 2 ;;
esac
