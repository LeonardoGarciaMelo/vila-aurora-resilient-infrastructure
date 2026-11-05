#!/usr/bin/env bash
# Downloads the LLM once into the lab volume. The running ollama service itself has no internet route.
set -euo pipefail
cd "$(dirname "$0")/.."
model="$(grep '^LLM_MODEL=' .env | cut -d= -f2)"
docker volume create vaurora_ollama_models >/dev/null
docker run --rm -v vaurora_ollama_models:/root/.ollama --entrypoint sh ollama/ollama:0.3.14 \
  -c "ollama serve >/dev/null 2>&1 & sleep 4; ollama pull $model; ollama list"
