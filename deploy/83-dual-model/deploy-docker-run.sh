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

MODEL_A_MAX_MODEL_LEN="${MODEL_A_MAX_MODEL_LEN:-${MAX_MODEL_LEN:-4096}}"
MODEL_B_MAX_MODEL_LEN="${MODEL_B_MAX_MODEL_LEN:-${MAX_MODEL_LEN:-4096}}"
MAX_NUM_SEQS="${MAX_NUM_SEQS:-1}"

command -v docker >/dev/null || { echo "Docker is not installed."; exit 1; }
command -v nvidia-smi >/dev/null || { echo "NVIDIA driver is not available."; exit 1; }

mkdir -p "${HF_HOME:-/opt/malapp-models/huggingface}" "${MODEL_DIR:-/opt/models}"

echo "== GPU =="
nvidia-smi --query-gpu=name,memory.total,memory.used,driver_version --format=csv,noheader || nvidia-smi

if [[ -f vllm-openai.tar ]]; then
  echo "== Loading offline Docker image: vllm-openai.tar =="
  docker load -i vllm-openai.tar
fi

if ! docker image inspect "${VLLM_IMAGE}" >/dev/null 2>&1; then
  cat <<EOF
Docker image is missing locally:
  ${VLLM_IMAGE}

This server cannot access Docker Hub. Put this file here first:
  /opt/malapp-dual-model/vllm-openai.tar

Then rerun:
  ./deploy-docker-run.sh
EOF
  exit 1
fi

host_model_path() {
  local model_path="$1"
  if [[ "$model_path" == /models/* ]]; then
    echo "${MODEL_DIR:-/opt/models}/${model_path#/models/}"
  else
    echo "$model_path"
  fi
}

required_models=("${MODEL_B_ID}")
if [[ "${ENABLE_MODEL_A:-0}" == "1" ]]; then
  required_models=("${MODEL_A_ID}" "${MODEL_B_ID}")
fi

for model_path in "${required_models[@]}"; do
  host_path="$(host_model_path "$model_path")"
  if [[ "$model_path" == /* && ! -d "$model_path" ]]; then
    if [[ -d "$host_path" ]]; then
      continue
    fi
    cat <<EOF
Local model path does not exist:
  container path: $model_path
  host path:      $host_path

If 83 is offline, put model directories under ${MODEL_DIR:-/opt/models}
and set MODEL_A_ID / MODEL_B_ID in .env to /models/xxx.
EOF
    exit 1
  fi
done

docker rm -f malapp-model-a malapp-model-b >/dev/null 2>&1 || true

if [[ "${ENABLE_MODEL_A:-0}" == "1" ]]; then
  docker run -d \
    --name malapp-model-a \
    --restart unless-stopped \
    --gpus all \
    --ipc=host \
    -e CUDA_VISIBLE_DEVICES=0 \
    -e NVIDIA_VISIBLE_DEVICES=0 \
    -e NVIDIA_DISABLE_REQUIRE=1 \
    -e HF_TOKEN="${HF_TOKEN:-}" \
    -e HF_HOME=/root/.cache/huggingface \
    -p "${MODEL_A_PORT}:8000" \
    -v "${HF_HOME}:/root/.cache/huggingface" \
    -v "${MODEL_DIR}:/models" \
    "${VLLM_IMAGE}" \
    --model "${MODEL_A_ID}" \
    --served-model-name "${MODEL_A_NAME}" \
    --host 0.0.0.0 \
    --port 8000 \
    --quantization bitsandbytes \
    --load-format bitsandbytes \
    --gpu-memory-utilization "${MODEL_A_GPU_MEMORY_UTILIZATION}" \
    --max-model-len "${MODEL_A_MAX_MODEL_LEN}" \
    --max-num-seqs "${MAX_NUM_SEQS}" \
    --enforce-eager
else
  echo "Model A is disabled on 83. APP should call the external Model A service."
fi

docker run -d \
  --name malapp-model-b \
  --restart unless-stopped \
  --gpus all \
  --ipc=host \
  -e CUDA_VISIBLE_DEVICES=0 \
  -e NVIDIA_VISIBLE_DEVICES=0 \
  -e NVIDIA_DISABLE_REQUIRE=1 \
  -e HF_TOKEN="${HF_TOKEN:-}" \
  -e HF_HOME=/root/.cache/huggingface \
  -p "${MODEL_B_PORT}:8000" \
  -v "${HF_HOME}:/root/.cache/huggingface" \
  -v "${MODEL_DIR}:/models" \
  "${VLLM_IMAGE}" \
  --model "${MODEL_B_ID}" \
  --served-model-name "${MODEL_B_NAME}" \
  --host 0.0.0.0 \
  --port 8000 \
  --quantization bitsandbytes \
  --load-format bitsandbytes \
  --gpu-memory-utilization "${MODEL_B_GPU_MEMORY_UTILIZATION}" \
  --max-model-len "${MODEL_B_MAX_MODEL_LEN}" \
  --max-num-seqs "${MAX_NUM_SEQS}" \
  --enforce-eager

cat <<EOF
Services are starting.

Check logs:
  docker logs -f malapp-model-b

Check APIs:
  curl http://127.0.0.1:${MODEL_B_PORT}/v1/models
EOF
