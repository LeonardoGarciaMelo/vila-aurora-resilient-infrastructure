#!/usr/bin/env bash
# Runs a one-off command inside a throwaway container on the cloud segment (tests only).
set -euo pipefail
docker run --rm --network vaurora_cloud --entrypoint sh vaurora/attacker:1.0 -c "$*"
