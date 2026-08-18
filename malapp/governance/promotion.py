"""Transactional Champion/Challenger governance for model artifacts."""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from malapp.evaluation.gates import evaluate_regression_gate, load_gate_policy, load_scorecard
from malapp.governance.artifacts import canonical_json, now_iso, sha256_file, sha256_text
from malapp.governance.datasets import read_json, validate_dataset_manifest

MODEL_REGISTRY_VERSION = 1
VALID_CANDIDATE_STATES = frozenset(
    {"candidate", "gate_passed", "shadow_passed", "approved", "champion", "superseded", "rolled_back", "rejected", "blocked"}
)


class PromotionError(ValueError):
    """Raised when a candidate attempts an invalid promotion transition."""


def load_registry(path: Path) -> dict[str, Any]:
    source = path.expanduser().resolve()
    if not source.exists():
        return _empty_registry()
    value = read_json(source)
    validate_registry(value)
    return value


def validate_registry(registry: dict[str, Any]) -> None:
    if registry.get("registry_version") != MODEL_REGISTRY_VERSION:
        raise PromotionError(f"unsupported model registry version: {registry.get('registry_version')}")
    for field in ("candidates", "champions", "history", "sha256"):
        if field not in registry:
            raise PromotionError(f"model registry is missing {field}")
    if not isinstance(registry["candidates"], dict) or not isinstance(registry["champions"], dict):
        raise PromotionError("model registry candidates and champions must be objects")
    for candidate_id, candidate in registry["candidates"].items():
        if candidate.get("candidate_id") != candidate_id:
            raise PromotionError(f"candidate identity mismatch: {candidate_id}")
        if candidate.get("status") not in VALID_CANDIDATE_STATES:
            raise PromotionError(f"invalid candidate status: {candidate.get('status')}")
        if candidate.get("sha256") != sha256_text(canonical_json(_candidate_identity(candidate))):
            raise PromotionError(f"candidate digest mismatch: {candidate_id}")
    expected = sha256_text(canonical_json(_registry_identity(registry)))
    if registry.get("sha256") != expected:
        raise PromotionError("model registry digest mismatch")


def register_candidate(
    registry_path: Path,
    *,
    candidate_id: str,
    component: str,
    artifact_manifests: list[Path],
    dataset_manifest_path: Path,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    _validate_identifier(candidate_id, "candidate_id")
    _validate_identifier(component, "component")
    if not artifact_manifests:
        raise PromotionError("at least one artifact manifest is required")
    dataset = validate_dataset_manifest(dataset_manifest_path)["manifest"]
    artifacts = [_artifact_reference(path) for path in artifact_manifests]

    def mutate(registry: dict[str, Any]) -> dict[str, Any]:
        if candidate_id in registry["candidates"]:
            raise PromotionError(f"candidate already exists: {candidate_id}")
        registered_at = now_iso()
        candidate = {
            "candidate_id": candidate_id,
            "component": component,
            "status": "candidate",
            "registered_at": registered_at,
            "updated_at": registered_at,
            "artifacts": artifacts,
            "dataset": {
                "dataset_id": dataset["dataset_id"],
                "sha256": dataset["sha256"],
                "manifest_path": str(dataset_manifest_path.expanduser().resolve()),
            },
            "metadata": dict(metadata or {}),
            "gate": None,
            "shadow": None,
            "approval": None,
        }
        candidate["sha256"] = sha256_text(canonical_json(_candidate_identity(candidate)))
        registry["candidates"][candidate_id] = candidate
        _history(registry, "candidate_registered", candidate_id, component)
        return candidate

    return _locked_mutation(registry_path, mutate)


def evaluate_candidate(
    registry_path: Path,
    *,
    candidate_id: str,
    baseline_scorecard: Path,
    candidate_scorecard: Path,
    policy_path: Path | None = None,
) -> dict[str, Any]:
    baseline = load_scorecard(baseline_scorecard)
    scorecard = load_scorecard(candidate_scorecard)
    policy = load_gate_policy(policy_path) if policy_path else load_gate_policy()
    gate = evaluate_regression_gate(baseline, scorecard, policy)
    gate_dir = registry_path.expanduser().resolve().parent / "gates"
    gate_dir.mkdir(parents=True, exist_ok=True)
    gate_path = gate_dir / f"{candidate_id}.json"
    _write_json_atomic(gate_path, gate)

    def mutate(registry: dict[str, Any]) -> dict[str, Any]:
        candidate = _candidate(registry, candidate_id)
        if candidate["status"] not in {"candidate", "gate_passed", "rejected", "blocked"}:
            raise PromotionError(f"candidate cannot be evaluated from state {candidate['status']}")
        candidate["gate"] = {
            "status": gate["status"],
            "gate_report_sha256": gate["gate_report_sha256"],
            "report_path": str(gate_path),
            "baseline_scorecard": _file_reference(baseline_scorecard),
            "candidate_scorecard": _file_reference(candidate_scorecard),
            "policy": gate["policy"],
        }
        candidate["status"] = {
            "pass": "gate_passed",
            "fail": "rejected",
            "blocked": "blocked",
        }[gate["status"]]
        candidate["updated_at"] = now_iso()
        candidate["sha256"] = sha256_text(canonical_json(_candidate_identity(candidate)))
        _history(registry, f"regression_gate_{gate['status']}", candidate_id, candidate["component"])
        return {"candidate": candidate, "gate": gate}

    return _locked_mutation(registry_path, mutate)


def record_shadow_result(
    registry_path: Path,
    *,
    candidate_id: str,
    shadow_report_path: Path,
) -> dict[str, Any]:
    report = read_json(shadow_report_path.expanduser().resolve())
    status = str(report.get("status") or "").lower()
    sample_count = int(report.get("sample_count") or 0)
    critical_regressions = int(report.get("critical_regressions") or 0)
    if status != "pass" or sample_count <= 0 or critical_regressions != 0:
        raise PromotionError("shadow report must pass with samples and zero critical regressions")
    declared_candidate = str(report.get("candidate_id") or candidate_id)
    if declared_candidate != candidate_id:
        raise PromotionError("shadow report candidate_id does not match requested candidate")

    def mutate(registry: dict[str, Any]) -> dict[str, Any]:
        candidate = _candidate(registry, candidate_id)
        if candidate["status"] != "gate_passed":
            raise PromotionError("candidate must pass the regression gate before shadow evaluation")
        candidate["shadow"] = {
            "status": status,
            "sample_count": sample_count,
            "critical_regressions": critical_regressions,
            "report": _file_reference(shadow_report_path),
        }
        candidate["status"] = "shadow_passed"
        candidate["updated_at"] = now_iso()
        candidate["sha256"] = sha256_text(canonical_json(_candidate_identity(candidate)))
        _history(registry, "shadow_passed", candidate_id, candidate["component"])
        return candidate

    return _locked_mutation(registry_path, mutate)


def approve_candidate(
    registry_path: Path,
    *,
    candidate_id: str,
    approver: str,
    note: str = "",
) -> dict[str, Any]:
    if not approver.strip():
        raise PromotionError("a non-empty human approver is required")

    def mutate(registry: dict[str, Any]) -> dict[str, Any]:
        candidate = _candidate(registry, candidate_id)
        if candidate["status"] != "shadow_passed":
            raise PromotionError("candidate must pass shadow evaluation before approval")
        candidate["approval"] = {"approver": approver.strip(), "note": note.strip(), "approved_at": now_iso()}
        candidate["status"] = "approved"
        candidate["updated_at"] = now_iso()
        candidate["sha256"] = sha256_text(canonical_json(_candidate_identity(candidate)))
        _history(registry, "candidate_approved", candidate_id, candidate["component"], actor=approver.strip())
        return candidate

    return _locked_mutation(registry_path, mutate)


def promote_candidate(registry_path: Path, *, candidate_id: str) -> dict[str, Any]:
    def mutate(registry: dict[str, Any]) -> dict[str, Any]:
        candidate = _candidate(registry, candidate_id)
        if candidate["status"] != "approved":
            raise PromotionError("only an approved candidate can become Champion")
        component = candidate["component"]
        previous_id = registry["champions"].get(component)
        if previous_id and previous_id in registry["candidates"]:
            previous = registry["candidates"][previous_id]
            previous["status"] = "superseded"
            previous["updated_at"] = now_iso()
            previous["sha256"] = sha256_text(canonical_json(_candidate_identity(previous)))
        candidate["status"] = "champion"
        candidate["updated_at"] = now_iso()
        candidate["sha256"] = sha256_text(canonical_json(_candidate_identity(candidate)))
        registry["champions"][component] = candidate_id
        _history(
            registry,
            "candidate_promoted",
            candidate_id,
            component,
            details={"previous_champion": previous_id},
        )
        return {"champion": candidate, "previous_champion": previous_id}

    return _locked_mutation(registry_path, mutate)


def rollback_champion(
    registry_path: Path,
    *,
    component: str,
    actor: str,
    target_candidate_id: str = "",
) -> dict[str, Any]:
    if not actor.strip():
        raise PromotionError("a non-empty rollback actor is required")

    def mutate(registry: dict[str, Any]) -> dict[str, Any]:
        current_id = registry["champions"].get(component)
        if not current_id:
            raise PromotionError(f"component has no Champion: {component}")
        target_id = target_candidate_id or _previous_champion(registry, component, current_id)
        if not target_id or target_id not in registry["candidates"]:
            raise PromotionError(f"no rollback target is available for component: {component}")
        if target_id == current_id:
            raise PromotionError("rollback target is already the active Champion")
        target = registry["candidates"][target_id]
        if target["component"] != component or target["status"] not in {"superseded", "rolled_back"}:
            raise PromotionError("rollback target is not a previously governed Champion")
        current = registry["candidates"][current_id]
        current["status"] = "rolled_back"
        current["updated_at"] = now_iso()
        current["sha256"] = sha256_text(canonical_json(_candidate_identity(current)))
        target["status"] = "champion"
        target["updated_at"] = now_iso()
        target["sha256"] = sha256_text(canonical_json(_candidate_identity(target)))
        registry["champions"][component] = target_id
        _history(
            registry,
            "champion_rolled_back",
            target_id,
            component,
            actor=actor.strip(),
            details={"rolled_back_candidate": current_id},
        )
        return {"champion": target, "rolled_back_candidate": current_id}

    return _locked_mutation(registry_path, mutate)


def _artifact_reference(path: Path) -> dict[str, Any]:
    source = path.expanduser().resolve()
    manifest = read_json(source)
    return {
        "artifact_id": str(manifest.get("artifact_id") or manifest.get("model_id") or source.stem),
        "artifact_type": str(manifest.get("artifact_type") or manifest.get("model_type") or "generic"),
        "manifest_path": str(source),
        "manifest_sha256": sha256_file(source),
        "manifest_size": source.stat().st_size,
        "declared_sha256": str(manifest.get("sha256") or ""),
    }


def _file_reference(path: Path) -> dict[str, Any]:
    source = path.expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    return {"path": str(source), "sha256": sha256_file(source), "size": source.stat().st_size}


def _candidate(registry: dict[str, Any], candidate_id: str) -> dict[str, Any]:
    try:
        return registry["candidates"][candidate_id]
    except KeyError as exc:
        raise PromotionError(f"unknown candidate: {candidate_id}") from exc


def _candidate_identity(candidate: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in candidate.items() if key not in {"sha256", "updated_at"}}


def _registry_identity(registry: dict[str, Any]) -> dict[str, Any]:
    return {
        "registry_version": registry.get("registry_version"),
        "candidates": registry.get("candidates"),
        "champions": registry.get("champions"),
        "history": registry.get("history"),
    }


def _empty_registry() -> dict[str, Any]:
    registry = {
        "registry_version": MODEL_REGISTRY_VERSION,
        "candidates": {},
        "champions": {},
        "history": [],
        "updated_at": now_iso(),
    }
    registry["sha256"] = sha256_text(canonical_json(_registry_identity(registry)))
    return registry


def _history(
    registry: dict[str, Any],
    action: str,
    candidate_id: str,
    component: str,
    *,
    actor: str = "system",
    details: dict[str, Any] | None = None,
) -> None:
    registry["history"].append(
        {
            "action": action,
            "candidate_id": candidate_id,
            "component": component,
            "actor": actor,
            "at": now_iso(),
            "details": dict(details or {}),
        }
    )


def _previous_champion(registry: dict[str, Any], component: str, current_id: str) -> str:
    for event in reversed(registry["history"]):
        if event.get("action") != "candidate_promoted" or event.get("component") != component:
            continue
        if event.get("candidate_id") != current_id:
            continue
        previous = str((event.get("details") or {}).get("previous_champion") or "")
        if previous:
            return previous
    return ""


def _validate_identifier(value: str, label: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise PromotionError(f"invalid {label}: {value!r}")


def _locked_mutation(path: Path, mutate: Any) -> Any:
    target = path.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with _registry_lock(target):
        registry = load_registry(target)
        result = mutate(registry)
        registry["updated_at"] = now_iso()
        registry["sha256"] = sha256_text(canonical_json(_registry_identity(registry)))
        _write_json_atomic(target, registry)
        return result


@contextmanager
def _registry_lock(path: Path, timeout: float = 5.0) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    deadline = time.monotonic() + timeout
    descriptor: int | None = None
    while descriptor is None:
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            if time.monotonic() >= deadline:
                raise PromotionError(f"timed out waiting for model registry lock: {lock_path}") from exc
            time.sleep(0.05)
    try:
        os.write(descriptor, str(os.getpid()).encode("ascii"))
        yield
    finally:
        os.close(descriptor)
        lock_path.unlink(missing_ok=True)


def _write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(temporary, path)
