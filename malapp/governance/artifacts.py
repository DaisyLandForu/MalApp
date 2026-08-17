from __future__ import annotations

import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ARTIFACT_MANIFEST_VERSION = 1
XGB_FEATURE_SCHEMA_VERSION = "xgb-features-v1"
XGB_REQUIRED_MODELS = (
    "static_analysis",
    "threat_intel",
    "impersonation",
    "business_label",
    "fusion",
    "wec",
)


class ArtifactManifestError(ValueError):
    """Raised when an artifact manifest is missing or malformed."""


class ArtifactIntegrityError(ArtifactManifestError):
    """Raised when a governed artifact does not match its recorded digest."""


class ArtifactCompatibilityError(ArtifactManifestError):
    """Raised when an artifact cannot be consumed by this runtime."""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def resolve_git_commit(root: Path | None = None) -> str:
    configured = str(os.getenv("MALAPP_GIT_COMMIT", "")).strip()
    if configured and configured.lower() != "unknown":
        return configured
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        commit = result.stdout.strip()
        if commit:
            return commit
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def feature_schema(
    agents: dict[str, list[str]],
    fusion_features: list[str],
    wec_features: list[str],
) -> dict[str, Any]:
    return {
        "agents": {name: list(features) for name, features in sorted(agents.items())},
        "fusion_features": list(fusion_features),
        "wec_features": list(wec_features),
    }


def feature_schema_sha256(
    agents: dict[str, list[str]],
    fusion_features: list[str],
    wec_features: list[str],
) -> str:
    return sha256_text(canonical_json(feature_schema(agents, fusion_features, wec_features)))


def build_xgboost_manifest(
    *,
    model_dir: Path,
    database_path: Path,
    agents: dict[str, list[str]],
    fusion_features: list[str],
    wec_features: list[str],
    thresholds: dict[str, Any],
    metrics: dict[str, Any] | None = None,
    dataset_version: str = "",
    model_version: str = "xgb-runtime-v1",
    git_commit: str = "",
    created_at: str = "",
) -> dict[str, Any]:
    model_dir = model_dir.resolve()
    database_path = database_path.resolve()
    files: dict[str, dict[str, Any]] = {}
    for name in XGB_REQUIRED_MODELS:
        path = model_dir / f"{name}.json"
        if not path.is_file():
            raise FileNotFoundError(f"required XGBoost model does not exist: {path}")
        files[path.name] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    if not database_path.is_file():
        raise FileNotFoundError(f"XGBoost reference database does not exist: {database_path}")
    database_digest = sha256_file(database_path)
    schema = feature_schema(agents, fusion_features, wec_features)
    schema_digest = sha256_text(canonical_json(schema))
    dataset_id = dataset_version or f"dataset-{database_digest[:16]}"
    manifest: dict[str, Any] = {
        "manifest_version": ARTIFACT_MANIFEST_VERSION,
        "artifact_type": "xgboost",
        "model_type": "xgboost",
        "agent": "multi_agent_fusion",
        "version": model_version,
        "feature_schema_version": XGB_FEATURE_SCHEMA_VERSION,
        "feature_schema_sha256": schema_digest,
        **schema,
        "dataset_version": dataset_id,
        "git_commit": git_commit or resolve_git_commit(model_dir),
        "files": files,
        "database": {
            "path": os.path.relpath(database_path, model_dir),
            "sha256": database_digest,
            "size": database_path.stat().st_size,
        },
        "thresholds": dict(thresholds),
        "metrics": dict(metrics or {}),
        "created_at": created_at or now_iso(),
    }
    manifest["sha256"] = sha256_text(canonical_json(_xgboost_identity(manifest)))
    timestamp = "".join(character for character in manifest["created_at"][:10] if character.isdigit())
    manifest["artifact_id"] = f"xgb-runtime-{timestamp}-{manifest['sha256'][:12]}"
    return manifest


def validate_xgboost_manifest(
    manifest: dict[str, Any],
    *,
    model_dir: Path,
    expected_agents: dict[str, list[str]],
    expected_fusion_features: list[str],
    expected_wec_features: list[str],
    supported_feature_schema_versions: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ArtifactManifestError("XGBoost manifest must be a JSON object")
    required = {
        "manifest_version",
        "artifact_id",
        "artifact_type",
        "feature_schema_version",
        "feature_schema_sha256",
        "dataset_version",
        "git_commit",
        "sha256",
        "files",
        "database",
        "agents",
        "fusion_features",
        "wec_features",
        "thresholds",
        "created_at",
    }
    missing = sorted(required - set(manifest))
    if missing:
        raise ArtifactManifestError(f"XGBoost manifest is missing fields: {', '.join(missing)}")
    if int(manifest["manifest_version"]) != ARTIFACT_MANIFEST_VERSION:
        raise ArtifactCompatibilityError(
            f"unsupported XGBoost manifest version: {manifest['manifest_version']}"
        )
    if manifest["artifact_type"] != "xgboost":
        raise ArtifactCompatibilityError("artifact_type must be xgboost")
    supported = supported_feature_schema_versions or {XGB_FEATURE_SCHEMA_VERSION}
    if manifest["feature_schema_version"] not in supported:
        raise ArtifactCompatibilityError(
            f"unsupported XGBoost feature schema: {manifest['feature_schema_version']}"
        )

    expected_schema = feature_schema(
        expected_agents,
        expected_fusion_features,
        expected_wec_features,
    )
    actual_schema = feature_schema(
        manifest.get("agents") or {},
        manifest.get("fusion_features") or [],
        manifest.get("wec_features") or [],
    )
    if actual_schema != expected_schema:
        raise ArtifactCompatibilityError("XGBoost feature names do not match the runtime schema")
    actual_schema_digest = sha256_text(canonical_json(actual_schema))
    if manifest["feature_schema_sha256"] != actual_schema_digest:
        raise ArtifactIntegrityError("XGBoost feature schema digest mismatch")

    model_dir = model_dir.resolve()
    file_entries = manifest.get("files")
    if not isinstance(file_entries, dict):
        raise ArtifactManifestError("XGBoost files must be an object")
    for name in XGB_REQUIRED_MODELS:
        filename = f"{name}.json"
        entry = file_entries.get(filename)
        if not isinstance(entry, dict):
            raise ArtifactManifestError(f"XGBoost manifest does not declare {filename}")
        path = _safe_relative_path(model_dir, filename)
        _validate_file(path, entry, filename)

    database = manifest.get("database")
    if not isinstance(database, dict) or not database.get("path"):
        raise ArtifactManifestError("XGBoost manifest database entry is invalid")
    database_path = _safe_relative_path(model_dir, str(database["path"]))
    _validate_file(database_path, database, "reference database")

    manifest_digest = sha256_text(canonical_json(_xgboost_identity(manifest)))
    if manifest["sha256"] != manifest_digest:
        raise ArtifactIntegrityError("XGBoost artifact bundle digest mismatch")
    return {"manifest": manifest, "database_path": database_path}


def xgboost_manifest_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "artifact_id": manifest.get("artifact_id"),
        "artifact_type": manifest.get("artifact_type"),
        "version": manifest.get("version"),
        "feature_schema_version": manifest.get("feature_schema_version"),
        "dataset_version": manifest.get("dataset_version"),
        "git_commit": manifest.get("git_commit"),
        "sha256": manifest.get("sha256"),
        "created_at": manifest.get("created_at"),
    }


def _xgboost_identity(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "manifest_version": manifest.get("manifest_version"),
        "artifact_type": manifest.get("artifact_type"),
        "version": manifest.get("version"),
        "feature_schema_version": manifest.get("feature_schema_version"),
        "feature_schema_sha256": manifest.get("feature_schema_sha256"),
        "dataset_version": manifest.get("dataset_version"),
        "files": manifest.get("files"),
        "database": manifest.get("database"),
        "thresholds": manifest.get("thresholds"),
    }


def _safe_relative_path(parent: Path, relative: str) -> Path:
    path = (parent / relative).resolve()
    if path != parent and parent not in path.parents and parent.parent not in path.parents:
        raise ArtifactManifestError(f"artifact path escapes its runtime directory: {relative}")
    return path


def _validate_file(path: Path, entry: dict[str, Any], label: str) -> None:
    if not path.is_file():
        raise ArtifactIntegrityError(f"governed {label} does not exist: {path}")
    expected_size = int(entry.get("size", -1))
    if expected_size != path.stat().st_size:
        raise ArtifactIntegrityError(f"governed {label} size mismatch")
    expected_digest = str(entry.get("sha256") or "")
    if len(expected_digest) != 64 or sha256_file(path) != expected_digest:
        raise ArtifactIntegrityError(f"governed {label} SHA256 mismatch")
