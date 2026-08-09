#!/usr/bin/env bash
set -euo pipefail

# Run this script on server 82.
# It copies the offline vLLM image, local model directories, and deployment
# scripts to server 83, then prepares /opt/malapp-dual-model/.env on 83.

TARGET_HOST="${TARGET_HOST:-10.0.11.83}"
TARGET_USER="${TARGET_USER:-root}"
TARGET="${TARGET_USER}@${TARGET_HOST}"

SRC_ROOT="${SRC_ROOT:-/data/malapp_transfer}"
SRC_IMAGE="${SRC_IMAGE:-${SRC_ROOT}/vllm-openai.tar}"
SRC_MODEL_A="${SRC_MODEL_A:-${SRC_ROOT}/Qwen3-14B-Instruct-AWQ}"
SRC_MODEL_B="${SRC_MODEL_B:-${SRC_ROOT}/DeepSeek-R1-Distill-Qwen-7B}"

REMOTE_DEPLOY_DIR="${REMOTE_DEPLOY_DIR:-/opt/malapp-dual-model}"
REMOTE_MODEL_DIR="${REMOTE_MODEL_DIR:-/opt/models}"

echo "== Checking source assets on 82 =="
for path in "$SRC_IMAGE" "$SRC_MODEL_A" "$SRC_MODEL_B"; do
  if [[ ! -e "$path" ]]; then
    echo "Missing source asset: $path"
    exit 1
  fi
  du -sh "$path"
done

echo
echo "== Preparing directories on 83 =="
ssh "$TARGET" "mkdir -p '$REMOTE_DEPLOY_DIR' '$REMOTE_MODEL_DIR' && df -h / '$REMOTE_DEPLOY_DIR' '$REMOTE_MODEL_DIR' || true"

echo
echo "== Copying vLLM Docker image to 83 =="
scp "$SRC_IMAGE" "$TARGET:$REMOTE_DEPLOY_DIR/vllm-openai.tar"

echo
echo "== Copying model A to 83 =="
scp -r "$SRC_MODEL_A" "$TARGET:$REMOTE_MODEL_DIR/"

echo
echo "== Copying model B to 83 =="
scp -r "$SRC_MODEL_B" "$TARGET:$REMOTE_MODEL_DIR/"

echo
echo "== Copying deployment scripts to 83 =="
scp .env.example deploy-docker-run.sh check.sh "$TARGET:$REMOTE_DEPLOY_DIR/"

echo
echo "== Preparing .env on 83 =="
ssh "$TARGET" "cd '$REMOTE_DEPLOY_DIR' && cp .env .env.bak.\$(date +%Y%m%d%H%M%S) 2>/dev/null || true && cp .env.example .env && chmod +x deploy-docker-run.sh check.sh"

cat <<EOF

Transfer finished.

Next commands on 83:
  cd $REMOTE_DEPLOY_DIR
  ./deploy-docker-run.sh
  ./check.sh

APP server model settings:
  Model A URL: http://$TARGET_HOST:8011/v1
  Model A name: malapp-model-a
  Model B URL: http://$TARGET_HOST:8012/v1
  Model B name: malapp-model-b
EOF
