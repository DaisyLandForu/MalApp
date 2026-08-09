#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

if [[ ! -f .env ]]; then
  echo "Missing .env. Run: cp .env.example .env"
  exit 1
fi

set -a
# shellcheck disable=SC1091
source .env
set +a

command -v docker >/dev/null || { echo "Docker is not installed."; exit 1; }
command -v nvidia-smi >/dev/null || { echo "NVIDIA driver is not available."; exit 1; }

echo "== GPU =="
nvidia-smi --query-gpu=name,memory.total,memory.used,driver_version --format=csv,noheader
echo "== Disk =="
df -h "$ROOT_DIR"

total_mib="$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits | head -n 1 | tr -d ' ')"
if [[ "$total_mib" -lt 23000 ]]; then
  echo "This deployment requires a GPU with at least 23GB usable VRAM."
  exit 1
fi

mkdir -p "${HF_HOME:-/opt/malapp-models/huggingface}" "${MODEL_DIR:-/opt/models}"

if [[ -f vllm-openai.tar ]]; then
  echo "== Loading offline Docker image: vllm-openai.tar =="
  docker load -i vllm-openai.tar
fi

if ! docker image inspect "${VLLM_IMAGE}" >/dev/null 2>&1; then
  echo "== Docker image ${VLLM_IMAGE} is not available locally. Trying online pull... =="
  if ! docker compose --env-file .env -f compose.yaml pull; then
    cat <<EOF

Docker image cannot be pulled from this server.
83 currently cannot reach Docker Hub. Use one of these fixes:

1. Put an offline image tar here:
   /opt/malapp-dual-model/vllm-openai.tar
   then rerun ./deploy.sh

2. Or change VLLM_IMAGE in .env to your internal registry image.

3. Or temporarily enable internet access to Docker Hub.

EOF
    exit 1
  fi
else
  echo "== Docker image exists locally: ${VLLM_IMAGE} =="
fi

for model_path in "${MODEL_A_ID}" "${MODEL_B_ID}"; do
  if [[ "$model_path" == /* && ! -d "$model_path" ]]; then
    cat <<EOF

Local model path does not exist:
  $model_path

For offline deployment, put models under ${MODEL_DIR:-/opt/models}, for example:
  ${MODEL_DIR:-/opt/models}/Qwen2.5-14B-Instruct-AWQ
  ${MODEL_DIR:-/opt/models}/Qwen2.5-7B-Instruct-AWQ

Then set MODEL_A_ID and MODEL_B_ID in .env to those local paths.

EOF
    exit 1
  fi
done

docker compose --env-file .env -f compose.yaml up -d

cat <<EOF

Services are starting.

Check logs:
  docker compose --env-file .env -f compose.yaml logs -f

After both models are ready, test:
  curl http://127.0.0.1:${MODEL_A_PORT}/v1/models
  curl http://127.0.0.1:${MODEL_B_PORT}/v1/models

EOF
