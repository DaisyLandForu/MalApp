from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from malapp.config.paths import PROJECT_ROOT, resolve_data_dir
from malapp.governance.artifacts import (
    canonical_json,
    now_iso,
    resolve_git_commit,
    sha256_file,
    sha256_text,
    xgboost_manifest_summary,
)

RUNTIME_SNAPSHOT_VERSION = 2
DECISION_PARAMS_VERSION = "decision-params-v2-business-alignment"
AGENT_VERSION = "1.0.0"


def capture_runtime_snapshot(
    *,
    debate_result: dict[str, Any] | None = None,
    xgb_result: dict[str, Any] | None = None,
    rag_context: dict[str, Any] | None = None,
    decision_params: dict[str, Any] | None = None,
    data_dir: Path | None = None,
    admission: dict[str, Any] | None = None,
    evidence_envelope: dict[str, Any] | None = None,
    expert_runtime: dict[str, Any] | None = None,
    debate_conformance: str | None = None,
    wec_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    code = code_identity()
    commit = resolve_git_commit(PROJECT_ROOT)
    commit_source = "git"
    if commit == "unknown":
        commit = f"source-{code['sha256'][:16]}"
        commit_source = "source_digest_fallback"
    identity = {
        "snapshot_version": RUNTIME_SNAPSHOT_VERSION,
        "code_commit": commit,
        "code_commit_source": commit_source,
        "code_sha256": code["sha256"],
        "models": model_versions(debate_result),
        "xgb_artifacts": xgb_artifacts(xgb_result),
        "rag_snapshot": active_rag_snapshot(rag_context),
        "prompt_version": active_prompt_version(debate_result),
        "decision_params_version": decision_params_manifest(decision_params),
        "agent_versions": agent_versions(),
        "engine_c_admission": dict(admission or {}),
        "evidence_contract": evidence_contract_manifest(evidence_envelope),
        "expert_runtime": dict(expert_runtime or {}),
        "debate_conformance": str(debate_conformance or "unknown"),
        "wec_policy": dict(wec_policy or {}),
    }
    snapshot_id = f"runtime-{sha256_text(canonical_json(identity))[:16]}"
    return {
        **identity,
        "snapshot_id": snapshot_id,
        "captured_at": now_iso(),
    }


def save_runtime_snapshot(
    snapshot: dict[str, Any] | None = None,
    *,
    debate_result: dict[str, Any] | None = None,
    xgb_result: dict[str, Any] | None = None,
    rag_context: dict[str, Any] | None = None,
    decision_params: dict[str, Any] | None = None,
    data_dir: Path | None = None,
    admission: dict[str, Any] | None = None,
    evidence_envelope: dict[str, Any] | None = None,
    expert_runtime: dict[str, Any] | None = None,
    debate_conformance: str | None = None,
    wec_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = snapshot or capture_runtime_snapshot(
        debate_result=debate_result,
        xgb_result=xgb_result,
        rag_context=rag_context,
        decision_params=decision_params,
        data_dir=data_dir,
        admission=admission,
        evidence_envelope=evidence_envelope,
        expert_runtime=expert_runtime,
        debate_conformance=debate_conformance,
        wec_policy=wec_policy,
    )
    snapshot_id = str(value.get("snapshot_id") or "")
    if not snapshot_id:
        raise ValueError("runtime snapshot does not contain snapshot_id")
    path = runtime_snapshot_dir(data_dir) / f"{snapshot_id}.json"
    existing = _read_json(path)
    if existing.get("snapshot_id") == snapshot_id:
        value = existing
    else:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return {**value, "path": str(path)}


def runtime_snapshot_dir(data_dir: Path | None = None) -> Path:
    path = (data_dir or resolve_data_dir()) / "evaluation" / "snapshots"
    path.mkdir(parents=True, exist_ok=True)
    return path


def decision_params_manifest(params: dict[str, Any] | None = None) -> dict[str, Any]:
    if params is None:
        from malapp.orchestration.decision import load_decision_params

        params = load_decision_params()
    digest = sha256_text(canonical_json(params))
    return {
        "params_id": f"decision-{digest[:16]}",
        "version": DECISION_PARAMS_VERSION,
        "sha256": digest,
    }


def evidence_contract_manifest(envelope: dict[str, Any] | None) -> dict[str, Any] | None:
    if not envelope:
        return None
    return {
        "schema_version": envelope.get("schema_version"),
        "evidence_snapshot_id": envelope.get("evidence_snapshot_id") or envelope.get("snapshot_id"),
        "sha256": envelope.get("sha256"),
        "evidence_ids": list(envelope.get("evidence_ids") or []),
    }


def model_versions(debate_result: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    providers = (debate_result or {}).get("providers") or {}
    if not providers:
        server_enabled = _enabled("MALAPP_USE_SERVER_MODELS")
        local_enabled = _enabled("MALAPP_USE_LOCAL_QWEN")
        fallback_model = os.getenv("MALAPP_QWEN_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
        backend = "openai_compatible" if server_enabled else "local_qwen" if local_enabled else "rule"
        providers = {
            "model_a": {
                "backend": backend,
                "model": os.getenv("MALAPP_MODEL_A_MODEL", "") or fallback_model,
                "api_url": os.getenv("MALAPP_MODEL_A_API_URL", "") if server_enabled else "",
            },
            "model_b": {
                "backend": backend,
                "model": os.getenv("MALAPP_MODEL_B_MODEL", "") or fallback_model,
                "api_url": os.getenv("MALAPP_MODEL_B_API_URL", "") if server_enabled else "",
            },
        }
    result: dict[str, dict[str, Any]] = {}
    for name in ("model_a", "model_b"):
        provider = providers.get(name) if isinstance(providers.get(name), dict) else {}
        value = {
            "provider": str(provider.get("backend") or "unknown"),
            "model_id": str(provider.get("model") or "unknown"),
            "endpoint": _safe_endpoint(str(provider.get("api_url") or "")),
        }
        value["identity"] = f"{value['provider']}:{value['model_id']}"
        value["sha256"] = sha256_text(canonical_json(value))
        result[name] = value
    return result


def xgb_artifacts(xgb_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    artifact = (xgb_result or {}).get("artifact")
    if isinstance(artifact, dict) and artifact.get("artifact_id"):
        return [dict(artifact)]
    runtime_dir = Path(
        os.getenv("MALAPP_XGB_DIR", str(PROJECT_ROOT / "training_artifacts" / "xgb"))
    ).expanduser()
    manifest = _read_json(runtime_dir / "models" / "runtime_manifest.json")
    if manifest.get("artifact_id"):
        return [{**xgboost_manifest_summary(manifest), "usage": "configured_not_used"}]
    return []


def active_rag_snapshot(rag_context: dict[str, Any] | None) -> dict[str, Any] | None:
    status = (rag_context or {}).get("status") or {}
    snapshot = status.get("snapshot") if isinstance(status, dict) else None
    if isinstance(snapshot, dict) and snapshot.get("snapshot_id"):
        return dict(snapshot)
    if rag_context is not None:
        return None
    try:
        from malapp.rag import rag_status

        current = rag_status().get("snapshot")
        return dict(current) if isinstance(current, dict) else None
    except (OSError, ValueError):
        return None


def active_prompt_version(debate_result: dict[str, Any] | None) -> dict[str, Any]:
    prompt = (debate_result or {}).get("prompt_version")
    if isinstance(prompt, dict) and prompt.get("prompt_id"):
        return dict(prompt)
    from malapp.orchestration.debate import debate_prompt_manifest

    return debate_prompt_manifest()


@lru_cache(maxsize=1)
def agent_versions() -> dict[str, dict[str, str]]:
    sources = {
        "static_analysis": ("agents/domain.py", "agents/static_features.py"),
        "threat_intel": ("agents/domain.py", "agents/threat_intelligence.py"),
        "impersonation": ("agents/domain.py", "agents/impersonation.py"),
        "business_label": ("agents/domain.py", "agents/business_label.py"),
    }
    result: dict[str, dict[str, str]] = {}
    for name, relative_paths in sources.items():
        files = [PROJECT_ROOT / "malapp" / relative for relative in relative_paths]
        digest = _file_bundle_digest(files)
        result[name] = {
            "agent_id": f"{name}-{digest[:12]}",
            "version": AGENT_VERSION,
            "sha256": digest,
        }
    return result


@lru_cache(maxsize=1)
def code_identity() -> dict[str, Any]:
    files = sorted((PROJECT_ROOT / "malapp").rglob("*.py"))
    return {"sha256": _file_bundle_digest(files), "file_count": len(files)}


def _file_bundle_digest(files: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in files:
        if not path.is_file():
            continue
        try:
            relative = path.relative_to(PROJECT_ROOT)
        except ValueError:
            relative = path
        digest.update(str(relative).replace("\\", "/").encode("utf-8"))
        digest.update(sha256_file(path).encode("ascii"))
    return digest.hexdigest()


def _safe_endpoint(value: str) -> str:
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port:
        host = f"{host}:{parsed.port}"
    return urlunsplit((parsed.scheme, host, "", "", ""))


def _enabled(name: str) -> bool:
    return str(os.getenv(name, "0")).strip().lower() in {"1", "true", "yes", "on"}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
