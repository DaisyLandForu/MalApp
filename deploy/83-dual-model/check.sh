#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
else
  MODEL_A_PORT=8011
  MODEL_B_PORT=8012
  ENABLE_MODEL_A=0
fi

echo "== GPU =="
nvidia-smi || true

echo
echo "== Containers =="
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' || true

echo
echo "== Listening ports =="
if [[ "${ENABLE_MODEL_A:-0}" == "1" ]]; then
  ss -lntp | grep -E "${MODEL_A_PORT:-8011}|${MODEL_B_PORT:-8012}" || true
else
  ss -lntp | grep -E "${MODEL_B_PORT:-8012}" || true
fi

if [[ "${ENABLE_MODEL_A:-0}" == "1" ]]; then
  echo
  echo "== Model A =="
  curl -sS "http://127.0.0.1:${MODEL_A_PORT:-8011}/v1/models" || true
fi

echo
echo "== Model B =="
curl -sS "http://127.0.0.1:${MODEL_B_PORT:-8012}/v1/models" || true
echo
