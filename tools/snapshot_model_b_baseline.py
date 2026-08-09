from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import sqlite3
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROMPT_FUNCTIONS = (
    "initial_report",
    "debate_turn",
    "closing_report",
    "invoke",
    "build_json_repair_prompt",
    "build_initial_retry_prompt",
    "build_turn_retry_prompt",
    "build_turn_repair_prompt",
    "build_closing_retry_prompt",
    "build_closing_repair_prompt",
    "model_max_tokens_for_phase",
    "bounded_completion_tokens",
    "fit_prompt_for_context",
)
MODEL_PROVIDER_METHODS = ("context_token_limit", "_http_generate")
SOURCE_FILES = (
    "app_version.py",
    "engine/model_settings.py",
    "engine/debate_flow.py",
    "engine/decision_engine.py",
    "engine/pipeline.py",
    "engine/rag/embedding.py",
    "engine/rag/store.py",
    "engine/rag/graph.py",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_json(path: Path, fallback: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError):
        return fallback


def json_get(url: str, api_key: str, timeout: float) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read().decode("utf-8", "replace")
        parsed = json.loads(payload)
        return {"ok": True, "status": response.status, "data": parsed}
    except urllib.error.HTTPError as exc:
        return {"ok": False, "status": exc.code, "error": f"HTTP {exc.code}"}
    except Exception as exc:  # a baseline must record failures rather than abort
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def secret_state(value: Any) -> dict[str, Any]:
    text = str(value or "")
    return {
        "configured": bool(text),
        "sha256_prefix": sha256_text(text)[:12] if text else None,
        "value": "<redacted>" if text else "",
    }


def source_fingerprint(project_root: Path, relative: str) -> dict[str, Any]:
    path = project_root / relative
    if not path.exists():
        return {"path": str(path), "exists": False}
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "exists": True,
        "bytes": stat.st_size,
        "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "sha256": sha256_file(path),
    }


def extract_prompt_sources(source_path: Path, output_dir: Path) -> list[dict[str, Any]]:
    # Some Windows source files carry an UTF-8 BOM.  utf-8-sig removes it so
    # the AST parser sees a normal leading ``from __future__`` statement.
    source = source_path.read_text(encoding="utf-8-sig")
    lines = source.splitlines(keepends=True)
    tree = ast.parse(source)
    selected: list[tuple[str, ast.AST]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in PROMPT_FUNCTIONS:
            selected.append((node.name, node))
        if isinstance(node, ast.ClassDef) and node.name == "ModelProvider":
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name in MODEL_PROVIDER_METHODS:
                    selected.append((f"ModelProvider.{child.name}", child))
    prompt_dir = output_dir / "prompt_sources"
    prompt_dir.mkdir(parents=True, exist_ok=True)
    result: list[dict[str, Any]] = []
    for qualified_name, node in selected:
        start = int(getattr(node, "lineno"))
        end = int(getattr(node, "end_lineno"))
        text = "".join(lines[start - 1 : end])
        filename = qualified_name.replace(".", "_") + ".py.txt"
        target = prompt_dir / filename
        target.write_text(text, encoding="utf-8")
        result.append(
            {
                "name": qualified_name,
                "source_path": str(source_path.resolve()),
                "line_start": start,
                "line_end": end,
                "snapshot_path": str(target.resolve()),
                "sha256": sha256_text(text),
            }
        )
    return result


def load_effective_decision_params(project_root: Path, data_dir: Path) -> dict[str, Any]:
    old_data_dir = os.environ.get("MALAPP_DATA_DIR")
    os.environ["MALAPP_DATA_DIR"] = str(data_dir)
    sys.path.insert(0, str(project_root))
    try:
        from engine.decision_engine import DEFAULT_PARAMS, load_decision_params

        return {
            "source_defaults": DEFAULT_PARAMS,
            "effective": load_decision_params(),
            "overrides": {
                "best_params": read_json(data_dir / "eval" / "best_params.json", {}),
                "decision_params": read_json(data_dir / "decision_params.json", {}),
            },
            "paths": {
                "best_params": str((data_dir / "eval" / "best_params.json").resolve()),
                "decision_params": str((data_dir / "decision_params.json").resolve()),
            },
        }
    finally:
        if sys.path and sys.path[0] == str(project_root):
            sys.path.pop(0)
        if old_data_dir is None:
            os.environ.pop("MALAPP_DATA_DIR", None)
        else:
            os.environ["MALAPP_DATA_DIR"] = old_data_dir


def sqlite_scalar(conn: sqlite3.Connection, query: str) -> Any:
    row = conn.execute(query).fetchone()
    return row[0] if row else None


def rag_snapshot(db_path: Path, project_root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "database": str(db_path.resolve()),
        "exists": db_path.exists(),
        "code_version": {
            relative: source_fingerprint(project_root, relative)
            for relative in ("engine/rag/embedding.py", "engine/rag/store.py", "engine/rag/graph.py")
        },
        "configuration": {
            "enabled": os.getenv("MALAPP_RAG_ENABLED", "1").lower() in {"1", "true", "yes", "y"},
            "mode": os.getenv("MALAPP_RAG_MODE", "hybrid"),
            "top_k": int(os.getenv("MALAPP_RAG_TOP_K", "6") or "6"),
            "graph_max_hops": int(os.getenv("MALAPP_KG_MAX_HOPS", "1") or "1"),
            "remote_base_url": os.getenv("MALAPP_RAG_REMOTE_BASE_URL", ""),
            "embedding_backend_requested": os.getenv("MALAPP_RAG_EMBED_BACKEND", "chinese_transformer"),
            "embedding_model_requested": os.getenv("MALAPP_RAG_EMBED_MODEL", "BAAI/bge-small-zh-v1.5"),
            "embedding_dim_fallback": int(os.getenv("MALAPP_RAG_EMBED_DIM", "384") or "384"),
            "embedding_local_files_only": os.getenv("MALAPP_RAG_EMBED_LOCAL_FILES_ONLY", "1"),
            "note": "实际写入向量的 backend/model 未持久化在旧库中；向量维度只能校验兼容性，不能证明模型身份。",
        },
        "query_policy": "流水线对每个研判样本调用 rag_context_for_sample；MALAPP_RAG_ENABLED=0 时跳过。默认先向量检索，再融合结构化知识图谱。",
    }
    if not db_path.exists():
        return result
    stat = db_path.stat()
    result.update(
        {
            "bytes": stat.st_size,
            "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "sha256": sha256_file(db_path),
        }
    )
    uri = f"file:{db_path.as_posix()}?mode=ro"
    try:
        with sqlite3.connect(uri, uri=True, timeout=10) as conn:
            tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
            schema_rows = list(
                conn.execute(
                    "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type,name"
                )
            )
            schema_text = json.dumps(schema_rows, ensure_ascii=False, separators=(",", ":"))
            result["sqlite_user_version"] = sqlite_scalar(conn, "PRAGMA user_version")
            result["schema_sha256"] = sha256_text(schema_text)
            result["tables"] = {}
            for table in tables:
                if not table.replace("_", "").isalnum():
                    continue
                result["tables"][table] = {"rows": int(sqlite_scalar(conn, f'SELECT COUNT(*) FROM "{table}"') or 0)}
            if "rag_documents" in tables:
                result["source_counts"] = {
                    str(row[0]): int(row[1])
                    for row in conn.execute(
                        "SELECT source_type,COUNT(*) FROM rag_documents GROUP BY source_type ORDER BY source_type"
                    )
                }
                row = conn.execute(
                    "SELECT MIN(updated_at),MAX(updated_at),MIN(LENGTH(embedding_json)),MAX(LENGTH(embedding_json)) FROM rag_documents"
                ).fetchone()
                result["document_update_range_unix"] = {"min": row[0], "max": row[1]}
                first = conn.execute("SELECT embedding_json FROM rag_documents LIMIT 1").fetchone()
                if first:
                    try:
                        result["stored_embedding_dimension_sample"] = len(json.loads(first[0]))
                    except Exception:
                        result["stored_embedding_dimension_sample"] = None
    except sqlite3.Error as exc:
        result["read_error"] = f"{type(exc).__name__}: {exc}"
    return result


def runtime_prompt_config() -> dict[str, Any]:
    def env_int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)) or str(default))
        except ValueError:
            return default

    return {
        "model_b_role": {
            "name": "风险优先模型",
            "strategy": "强调高危权限、IOC、仿冒、业务危害链和漏报风险。",
        },
        "temperature": 0,
        "json_mode": os.getenv("MALAPP_MODEL_JSON_MODE", "1").lower() in {"1", "true", "yes", "on"},
        "chat_template_enable_thinking": False,
        "no_think_guard": True,
        "context_tokens": env_int("MALAPP_MODEL_B_CONTEXT_TOKENS", 2048),
        "prompt_token_budget": env_int("MALAPP_MODEL_B_PROMPT_TOKEN_BUDGET", 700),
        "phase_max_tokens": {
            "initial_testimony": 720,
            "directed_attack": 620,
            "evidence_rebuttal": 680,
            "role_reversal_rebuttal": 680,
            "closing_statement": 620,
        },
        "api_timeout_seconds": float(os.getenv("MALAPP_MODEL_API_TIMEOUT", "600") or "600"),
        "transport_retries": env_int("MALAPP_MODEL_TRANSPORT_RETRIES", 1),
        "fast_retry": os.getenv("MALAPP_FAST_MODEL_RETRY", "1").lower() in {"1", "true", "yes", "on"},
        "schema_repair_max_attempts": min(max(env_int("MALAPP_SCHEMA_REPAIR_MAX_ATTEMPTS", 2), 0), 2),
        "note": "精确提示词文本已按函数冻结到 prompt_sources/；运行时还会拼接当前样本证据、RAG上下文和阶段记忆。",
    }


def validate_remote_manifest(remote: Any, expected_model_dir: str) -> dict[str, Any]:
    """Reject fingerprints collected on a jump host or outside the vLLM container."""
    payload = remote if isinstance(remote, dict) else {}
    metadata_files = payload.get("metadata_files") if isinstance(payload.get("metadata_files"), list) else []
    metadata_names = {str(item.get("path") or "") for item in metadata_files if isinstance(item, dict)}
    processes = payload.get("vllm_processes") if isinstance(payload.get("vllm_processes"), list) else []
    process_commands = [str(item.get("cmdline") or "") for item in processes if isinstance(item, dict)]
    packages = payload.get("packages") if isinstance(payload.get("packages"), dict) else {}
    checks = {
        "schema_version": payload.get("schema_version") == "malapp.model_b_remote_fingerprint.v1",
        "model_directory_exists": payload.get("model_directory_exists") is True,
        "model_directory_matches_api": str(payload.get("model_directory") or "").rstrip("/")
        == str(expected_model_dir or "").rstrip("/"),
        "model_config_present": isinstance(payload.get("model_config"), dict) and bool(payload.get("model_config")),
        "tokenizer_config_present": isinstance(payload.get("tokenizer_config"), dict)
        and bool(payload.get("tokenizer_config")),
        "tokenizer_files_hashed": any(
            Path(name).name
            in {"tokenizer.json", "tokenizer.model", "tokenizer_config.json", "vocab.json", "vocab.txt"}
            for name in metadata_names
        ),
        "weight_files_hashed": int(payload.get("weight_file_count") or 0) > 0
        and isinstance(payload.get("weight_files"), list),
        "weight_manifest_sha256_present": len(str(payload.get("weight_manifest_sha256") or "")) == 64,
        "vllm_process_found": bool(process_commands),
        "vllm_process_matches_model": any(
            str(expected_model_dir or "") in command or "malapp-model-b" in command for command in process_commands
        ),
        "vllm_package_version_present": bool(packages.get("vllm")),
    }
    failed = [name for name, passed in checks.items() if not passed]
    return {
        "complete": not failed,
        "checks": checks,
        "failed_checks": failed,
        "guidance": (
            "若vLLM运行在Docker中，请在vLLM容器内执行采集脚本；在跳板机或仅有端口转发的宿主机执行不会通过校验。"
            if failed
            else "远程模型身份、权重、Tokenizer和vLLM进程信息已完整。"
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Freeze the reproducibility baseline for MalApp model B.")
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--remote-manifest", type=Path, help="JSON emitted by collect_model_b_remote_fingerprint.sh")
    parser.add_argument("--api-timeout", type=float, default=5.0)
    args = parser.parse_args()

    project_root = args.project_root.expanduser().resolve()
    local_app_data = Path(os.getenv("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
    data_dir = (args.data_dir or local_app_data / "MalApp_AgentTrace_LearningLoop" / "data").expanduser().resolve()
    stamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S%z")
    output_dir = (args.output_dir or project_root / "model_baselines" / f"model_b_{stamp}").expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    settings_path = data_dir / "model_settings.json"
    settings = read_json(settings_path, {}) or {}
    api_url = str(settings.get("model_b_api_url") or "http://10.0.11.82:18012/v1").rstrip("/")
    api_key = str(settings.get("model_b_api_key") or "")
    configured_model = str(settings.get("model_b_model") or "malapp-model-b")
    models_response = json_get(f"{api_url}/models", api_key, args.api_timeout)
    version_response = json_get(api_url.removesuffix("/v1") + "/version", api_key, args.api_timeout)
    model_entry = None
    if models_response.get("ok"):
        for item in models_response.get("data", {}).get("data", []):
            if isinstance(item, dict) and str(item.get("id")) == configured_model:
                model_entry = item
                break

    remote = read_json(args.remote_manifest, None) if args.remote_manifest else None
    expected_model_dir = str((model_entry or {}).get("root") or "/models/Qwen3-14B")
    remote_validation = validate_remote_manifest(remote, expected_model_dir)
    model_identity = {
        "configured_alias": configured_model,
        "api_url": api_url,
        "api_key": secret_state(api_key),
        "openai_models_api": models_response,
        "selected_model_entry": model_entry,
        "vllm_version_api": version_response,
        "confirmed_from_api": {
            "served_model_name": (model_entry or {}).get("id"),
            "model_directory": (model_entry or {}).get("root"),
            "max_model_len": (model_entry or {}).get("max_model_len"),
            "owned_by": (model_entry or {}).get("owned_by"),
        },
        "vllm_start_arguments_inferred_from_api": {
            "--model": (model_entry or {}).get("root"),
            "--served-model-name": (model_entry or {}).get("id"),
            "--max-model-len": (model_entry or {}).get("max_model_len"),
            "provenance": "OpenAI /v1/models；这些值可确认服务行为，但不能替代 /proc/<pid>/cmdline 的完整启动参数。",
        },
        "exact_remote_fingerprint": remote,
        "remote_fingerprint_validation": remote_validation,
    }

    source_versions = {relative: source_fingerprint(project_root, relative) for relative in SOURCE_FILES}
    prompts = extract_prompt_sources(project_root / "engine" / "debate_flow.py", output_dir)
    decision = load_effective_decision_params(project_root, data_dir)
    rag = rag_snapshot(data_dir / "rag" / "rag_store.db", project_root)
    app_version = read_json(project_root / "app_version.py", None)
    version_text = (project_root / "app_version.py").read_text(encoding="utf-8") if (project_root / "app_version.py").exists() else ""

    pending = []
    if not remote_validation["complete"]:
        pending = [
            "Qwen3-14B权重分片逐文件SHA-256与组合哈希",
            "tokenizer文件版本、配置与SHA-256",
            "服务器config.json完整配置及SHA-256",
            "vLLM实际进程完整命令行、环境白名单、GPU与Python包版本",
        ]
        if remote:
            pending.append("远程清单校验失败：" + "、".join(remote_validation["failed_checks"]))
    manifest = {
        "schema_version": "malapp.model_b_baseline.v1",
        "created_at": datetime.now().astimezone().isoformat(),
        "status": "complete" if not pending else "partial_server_auth_required",
        "pending_server_fields": pending,
        "app": {
            "version_source": version_text.strip(),
            "project_root": str(project_root),
            "runtime_data_dir": str(data_dir),
            "settings_path": str(settings_path),
        },
        "model_b": model_identity,
        "prompt": {
            "runtime_configuration": runtime_prompt_config(),
            "frozen_sources": prompts,
        },
        "rag": rag,
        "fusion_and_thresholds": decision,
        "source_versions": source_versions,
        "reproduction_rule": (
            "只有模型权重/Tokenizer/配置、提示词、RAG快照、融合参数、vLLM启动参数全部相同，"
            "且输入样本与随机/并发设置受控时，才能称为同一可复现基线。"
        ),
    }
    manifest_path = output_dir / "model_b_baseline.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    effective = decision["effective"]
    confirmed = model_identity["confirmed_from_api"]
    report = f"""# MalApp 模型乙可复现基线

- 生成时间：{manifest['created_at']}
- 状态：`{manifest['status']}`
- 模型别名：`{configured_model}`
- API确认模型目录：`{confirmed.get('model_directory')}`
- API确认最大上下文：`{confirmed.get('max_model_len')}`
- vLLM版本：`{(version_response.get('data') or {}).get('version') if version_response.get('ok') else '未取得'}`
- 完整机器清单：`model_b_baseline.json`

## 当前生效配置

- 提示词：已冻结 {len(prompts)} 个关键函数源码；包含初判、攻防、反驳、终审、JSON修复和HTTP请求协议。
- RAG：`{rag.get('database')}`，SHA-256 `{rag.get('sha256', '库不存在')}`，文档数 `{(rag.get('tables') or {}).get('rag_documents', {}).get('rows', 0)}`。
- RAG模式：`{rag.get('configuration', {}).get('mode')}`，Top-K `{rag.get('configuration', {}).get('top_k')}`，图谱最大跳数 `{rag.get('configuration', {}).get('graph_max_hops')}`。
- 融合权重：XGBoost `{effective['xgb_fusion_weight']}`，完整流水线 `{effective['pipeline_fusion_weight']}`，证据 `{effective['evidence_fusion_weight']}`（乘证据置信度后再归一化）。
- 最终阈值：恶意 `{effective['malicious_threshold']}`，可疑 `{effective['suspicious_threshold']}`。

## 尚未取得的服务器字段

{chr(10).join(f'- {item}' for item in pending) if pending else '- 无；远程清单已合并。'}

这些字段无法从 OpenAI 兼容推理 API 可靠获得。请在真正承载 `/models/Qwen3-14B` 的服务器上运行：

```bash
bash collect_model_b_remote_fingerprint.sh /models/Qwen3-14B > model_b_remote_fingerprint.json
```

然后合并：

```powershell
python tools\\snapshot_model_b_baseline.py --remote-manifest model_b_remote_fingerprint.json
```

不要在聊天或清单中保存 SSH 密码/API Key 明文。
"""
    (output_dir / "README.md").write_text(report, encoding="utf-8")
    print(str(output_dir))
    print(str(manifest_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
