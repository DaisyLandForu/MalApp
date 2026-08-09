#!/usr/bin/env bash
set -euo pipefail

# Read-only collector. Run on the host that actually owns the model files.
# Usage: bash collect_model_b_remote_fingerprint.sh /models/Qwen3-14B > model_b_remote_fingerprint.json
MODEL_DIR="${1:-/models/Qwen3-14B}"

python3 - "$MODEL_DIR" <<'PY'
import hashlib
import json
import os
import platform
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


model_dir = Path(sys.argv[1]).expanduser().resolve()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def package_version(name):
    try:
        import pkg_resources
        return pkg_resources.get_distribution(name).version
    except Exception:
        module_name = {
            "huggingface-hub": "huggingface_hub",
        }.get(name, name.replace("-", "_"))
        try:
            module = __import__(module_name)
            return getattr(module, "__version__", None)
        except Exception:
            return None


def process_records():
    records = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes()
            command = raw.replace(b"\x00", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        lower = command.lower()
        if "vllm" not in lower and "openai.api_server" not in lower:
            continue
        environment = {}
        try:
            values = (entry / "environ").read_bytes().split(b"\x00")
            allowed = (
                "CUDA_VISIBLE_DEVICES",
                "NVIDIA_VISIBLE_DEVICES",
                "VLLM_",
                "HF_HOME",
                "HF_HUB_CACHE",
                "TRANSFORMERS_CACHE",
                "PYTORCH_CUDA_ALLOC_CONF",
            )
            for value in values:
                key, sep, item = value.partition(b"=")
                name = key.decode("utf-8", "replace")
                if sep and (name in allowed or any(name.startswith(prefix) for prefix in allowed if prefix.endswith("_"))):
                    environment[name] = item.decode("utf-8", "replace")
        except OSError:
            pass
        records.append({"pid": int(entry.name), "cmdline": command, "environment_allowlist": environment})
    return records


def run(command):
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=20,
            check=False,
        )
        return {"returncode": result.returncode, "stdout": result.stdout.strip(), "stderr": result.stderr.strip()}
    except Exception as exc:
        return {"error": f"{type(exc).__name__}: {exc}"}


metadata_names = {
    "config.json",
    "generation_config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "added_tokens.json",
    "chat_template.json",
    "merges.txt",
    "vocab.json",
    "vocab.txt",
    "model.safetensors.index.json",
}
metadata_files = []
weight_files = []
if model_dir.exists():
    for path in sorted(item for item in model_dir.rglob("*") if item.is_file()):
        relative = path.relative_to(model_dir).as_posix()
        if path.name in metadata_names or path.suffix in {".model", ".tiktoken"}:
            metadata_files.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
        if path.suffix in {".safetensors", ".bin", ".pt", ".pth"}:
            weight_files.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)})

combined_lines = "".join(f"{item['sha256']}  {item['path']}\n" for item in weight_files)
combined_hash = hashlib.sha256(combined_lines.encode("utf-8")).hexdigest() if weight_files else None
config = read_json(model_dir / "config.json") if model_dir.exists() else None
tokenizer_config = read_json(model_dir / "tokenizer_config.json") if model_dir.exists() else None
generation_config = read_json(model_dir / "generation_config.json") if model_dir.exists() else None

result = {
    "schema_version": "malapp.model_b_remote_fingerprint.v1",
    "created_at_utc": datetime.now(timezone.utc).isoformat(),
    "host": {"hostname": socket.gethostname(), "platform": platform.platform(), "python": sys.version},
    "model_directory": str(model_dir),
    "model_directory_exists": model_dir.exists(),
    "model_config": config,
    "generation_config": generation_config,
    "tokenizer_config": tokenizer_config,
    "metadata_files": metadata_files,
    "weight_files": weight_files,
    "weight_file_count": len(weight_files),
    "weight_bytes_total": sum(item["bytes"] for item in weight_files),
    "weight_manifest_sha256": combined_hash,
    "packages": {
        name: package_version(name)
        for name in ("vllm", "transformers", "tokenizers", "torch", "safetensors", "huggingface-hub")
    },
    "vllm_processes": process_records(),
    "gpu": run(["nvidia-smi", "--query-gpu=index,name,uuid,driver_version,memory.total", "--format=csv,noheader"]),
}
print(json.dumps(result, ensure_ascii=False, indent=2))
PY
