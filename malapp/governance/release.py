"""Immutable MalApp release snapshots and startup integrity verification."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from malapp.evaluation.gates import evaluate_regression_gate, load_gate_policy, load_scorecard
from malapp.governance.artifacts import (
    canonical_json,
    now_iso,
    resolve_git_commit,
    sha256_file,
    sha256_text,
)
from malapp.governance.datasets import validate_dataset_manifest
from malapp.governance.promotion import load_registry
from malapp.governance.runtime import capture_runtime_snapshot

RELEASE_SNAPSHOT_VERSION = 1
DOCKER_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET_KEY_PATTERN = re.compile(r"(^|_)(api_key|access_token|password|secret|private_key)($|_)", re.IGNORECASE)


class ReleaseError(ValueError):
    """Raised when a release is incomplete, mutable or unsafe."""


def build_release_snapshot(
    *,
    version: str,
    component: str,
    registry_path: Path,
    dataset_manifest_path: Path,
    baseline_scorecard_path: Path,
    candidate_scorecard_path: Path,
    docker_image_digest: str,
    output_dir: Path,
    runtime_snapshot_path: Path | None = None,
    gate_policy_path: Path | None = None,
    git_commit: str = "",
) -> dict[str, Any]:
    _validate_version(version)
    if not DOCKER_DIGEST_PATTERN.fullmatch(docker_image_digest):
        raise ReleaseError("docker_image_digest must be sha256:<64 lowercase hex characters>")

    registry_source = registry_path.expanduser().resolve()
    registry = load_registry(registry_source)
    champion_id = str(registry.get("champions", {}).get(component) or "")
    if not champion_id:
        raise ReleaseError(f"component has no approved Champion: {component}")
    champion = registry["candidates"][champion_id]
    if champion.get("status") != "champion":
        raise ReleaseError(f"registry Champion has invalid state: {champion.get('status')}")
    _verify_candidate_artifacts(champion)

    dataset_validated = validate_dataset_manifest(dataset_manifest_path)
    dataset = dataset_validated["manifest"]
    if champion.get("dataset", {}).get("sha256") != dataset.get("sha256"):
        raise ReleaseError("release dataset does not match the promoted candidate dataset")

    baseline = load_scorecard(baseline_scorecard_path)
    candidate_scorecard = load_scorecard(candidate_scorecard_path)
    gate_policy = load_gate_policy(gate_policy_path) if gate_policy_path else load_gate_policy()
    gate = evaluate_regression_gate(baseline, candidate_scorecard, gate_policy)
    if gate["status"] != "pass":
        raise ReleaseError(f"release regression gate is {gate['status']}; only pass can be released")
    governed_scorecard = champion.get("gate", {}).get("candidate_scorecard") or {}
    if governed_scorecard.get("sha256") != sha256_file(candidate_scorecard_path.expanduser().resolve()):
        raise ReleaseError("release scorecard does not match the scorecard approved during promotion")

    runtime_snapshot = (
        _read_json(runtime_snapshot_path.expanduser().resolve())
        if runtime_snapshot_path
        else capture_runtime_snapshot()
    )
    if not runtime_snapshot.get("snapshot_id"):
        raise ReleaseError("runtime snapshot does not contain snapshot_id")

    previous_champion = _previous_champion(registry, component, champion_id)
    identity = {
        "snapshot_version": RELEASE_SNAPSHOT_VERSION,
        "release_version": version,
        "git_commit": git_commit or resolve_git_commit(),
        "docker_image_digest": docker_image_digest,
        "component": component,
        "champion": _release_candidate(champion),
        "previous_champion": previous_champion,
        "runtime": {
            "snapshot_id": runtime_snapshot.get("snapshot_id"),
            "code_sha256": runtime_snapshot.get("code_sha256"),
            "agent_versions": runtime_snapshot.get("agent_versions") or {},
            "prompt_version": runtime_snapshot.get("prompt_version") or {},
            "models": runtime_snapshot.get("models") or {},
            "xgb_artifacts": runtime_snapshot.get("xgb_artifacts") or [],
            "rag_snapshot": runtime_snapshot.get("rag_snapshot"),
            "decision_params_version": runtime_snapshot.get("decision_params_version") or {},
        },
        "dataset": {
            "dataset_id": dataset["dataset_id"],
            "manifest_sha256": dataset["sha256"],
            "lineage_sha256": dataset["lineage_sha256"],
            "manifest": _file_reference(dataset_manifest_path),
        },
        "evaluation": {
            "dataset_sha256": candidate_scorecard.get("validation_sha256"),
            "baseline_scorecard": _file_reference(baseline_scorecard_path),
            "candidate_scorecard": _file_reference(candidate_scorecard_path),
            "gate_policy": _file_reference(Path(gate_policy["source"])),
            "gate": gate,
        },
        "registry": {
            "sha256": registry["sha256"],
            "path": str(registry_source),
        },
    }
    secret_paths = find_secret_paths(identity)
    if secret_paths:
        raise ReleaseError(f"release snapshot contains secret-like fields: {', '.join(secret_paths)}")
    digest = sha256_text(canonical_json(identity))
    release = {
        **identity,
        "release_id": f"malapp-{version}-{digest[:12]}",
        "created_at": now_iso(),
        "sha256": digest,
    }
    target_dir = output_dir.expanduser().resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    safe_version = re.sub(r"[^A-Za-z0-9._-]", "-", version)
    manifest_path = target_dir / f"release-{safe_version}.json"
    _write_json_atomic(manifest_path, release)
    checksum_path = manifest_path.with_suffix(manifest_path.suffix + ".sha256")
    checksum_path.write_text(f"{sha256_file(manifest_path)}  {manifest_path.name}\n", encoding="ascii")
    return {**release, "path": str(manifest_path), "checksum_path": str(checksum_path)}


def validate_release_snapshot(path: Path, *, verify_references: bool = True) -> dict[str, Any]:
    source = path.expanduser().resolve()
    release = _read_json(source)
    required = {
        "snapshot_version",
        "release_id",
        "release_version",
        "git_commit",
        "docker_image_digest",
        "component",
        "champion",
        "runtime",
        "dataset",
        "evaluation",
        "registry",
        "sha256",
    }
    missing = sorted(required - set(release))
    if missing:
        raise ReleaseError(f"release snapshot is missing fields: {', '.join(missing)}")
    if release["snapshot_version"] != RELEASE_SNAPSHOT_VERSION:
        raise ReleaseError(f"unsupported release snapshot version: {release['snapshot_version']}")
    if not DOCKER_DIGEST_PATTERN.fullmatch(str(release["docker_image_digest"])):
        raise ReleaseError("release Docker image digest is invalid")
    identity = {key: value for key, value in release.items() if key not in {"release_id", "created_at", "sha256", "path", "checksum_path"}}
    digest = sha256_text(canonical_json(identity))
    if digest != release["sha256"]:
        raise ReleaseError("release snapshot digest mismatch")
    if release["release_id"] != f"malapp-{release['release_version']}-{digest[:12]}":
        raise ReleaseError("release_id does not match release snapshot digest")
    secret_paths = find_secret_paths(release)
    if secret_paths:
        raise ReleaseError(f"release snapshot contains secret-like fields: {', '.join(secret_paths)}")
    if release.get("evaluation", {}).get("gate", {}).get("status") != "pass":
        raise ReleaseError("release snapshot does not contain a passing regression gate")
    if verify_references:
        _verify_reference(release["dataset"]["manifest"], "dataset manifest")
        _verify_reference(release["evaluation"]["baseline_scorecard"], "baseline scorecard")
        _verify_reference(release["evaluation"]["candidate_scorecard"], "candidate scorecard")
        _verify_reference(release["evaluation"]["gate_policy"], "regression gate policy")
        validate_dataset_manifest(Path(release["dataset"]["manifest"]["path"]))
        baseline = load_scorecard(Path(release["evaluation"]["baseline_scorecard"]["path"]))
        candidate = load_scorecard(Path(release["evaluation"]["candidate_scorecard"]["path"]))
        policy = load_gate_policy(Path(release["evaluation"]["gate_policy"]["path"]))
        current_gate = evaluate_regression_gate(baseline, candidate, policy)
        recorded_gate = release["evaluation"]["gate"]
        if current_gate["status"] != "pass" or current_gate["gate_report_sha256"] != recorded_gate.get("gate_report_sha256"):
            raise ReleaseError("release regression gate cannot be reproduced from referenced scorecards")
        for artifact in release.get("champion", {}).get("artifacts") or []:
            _verify_reference(
                {
                    "path": artifact.get("manifest_path"),
                    "sha256": artifact.get("manifest_sha256"),
                    "size": artifact.get("manifest_size", -1),
                },
                f"artifact manifest {artifact.get('artifact_id')}",
            )
    return release


def verify_configured_release() -> dict[str, Any] | None:
    configured = str(os.getenv("MALAPP_RELEASE_MANIFEST", "")).strip()
    if not configured:
        return None
    return validate_release_snapshot(Path(configured), verify_references=True)


def find_secret_paths(value: Any, prefix: str = "") -> list[str]:
    matches: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if SECRET_KEY_PATTERN.search(str(key)) and child is not None and child != "" and child is not False:
                matches.append(path)
            matches.extend(find_secret_paths(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            matches.extend(find_secret_paths(child, f"{prefix}[{index}]"))
    elif isinstance(value, str) and "://" in value:
        parsed = urlsplit(value)
        if parsed.username or parsed.password:
            matches.append(prefix)
    return matches


def _release_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": candidate.get("candidate_id"),
        "component": candidate.get("component"),
        "candidate_sha256": candidate.get("sha256"),
        "artifacts": candidate.get("artifacts") or [],
        "dataset": candidate.get("dataset") or {},
        "gate": candidate.get("gate") or {},
        "shadow": candidate.get("shadow") or {},
        "approval": candidate.get("approval") or {},
    }


def _verify_candidate_artifacts(candidate: dict[str, Any]) -> None:
    artifacts = candidate.get("artifacts") or []
    if not artifacts:
        raise ReleaseError("Champion does not declare any artifact manifests")
    for artifact in artifacts:
        path = Path(str(artifact.get("manifest_path") or "")).expanduser().resolve()
        if (
            not path.is_file()
            or path.stat().st_size != int(artifact.get("manifest_size", -1))
            or sha256_file(path) != artifact.get("manifest_sha256")
        ):
            raise ReleaseError(f"Champion artifact manifest changed or is missing: {path}")


def _previous_champion(registry: dict[str, Any], component: str, champion_id: str) -> str | None:
    for event in reversed(registry.get("history") or []):
        if event.get("action") == "candidate_promoted" and event.get("component") == component and event.get("candidate_id") == champion_id:
            return (event.get("details") or {}).get("previous_champion")
    return None


def _file_reference(path: Path) -> dict[str, Any]:
    source = path.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    return {"path": str(source), "sha256": sha256_file(source), "size": source.stat().st_size}


def _verify_reference(reference: dict[str, Any], label: str) -> None:
    path = Path(str(reference.get("path") or "")).expanduser().resolve()
    if not path.is_file():
        raise ReleaseError(f"{label} is missing: {path}")
    if int(reference.get("size", -1)) != path.stat().st_size or reference.get("sha256") != sha256_file(path):
        raise ReleaseError(f"{label} changed after release")


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"cannot read release dependency: {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ReleaseError(f"release dependency must be a JSON object: {path}")
    return value


def _validate_version(version: str) -> None:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", version):
        raise ReleaseError("release version must be semantic, for example 2.1.0")


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)
