from __future__ import annotations

import json
from pathlib import Path

import pytest

from malapp.governance.datasets import build_dataset_manifest
from malapp.governance.promotion import (
    PromotionError,
    approve_candidate,
    evaluate_candidate,
    load_registry,
    promote_candidate,
    record_shadow_result,
    register_candidate,
    rollback_champion,
)
from malapp.governance.release import ReleaseError, build_release_snapshot, validate_release_snapshot

ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "tests" / "fixtures" / "evaluation" / "approved-baseline-scorecard.json"
CANDIDATE_SCORECARD = ROOT / "tests" / "fixtures" / "evaluation" / "candidate-scorecard.json"


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def governed_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    train = tmp_path / "train.jsonl"
    test = tmp_path / "test.jsonl"
    train.write_text(
        json.dumps(
            {
                "sample_id": "train-release",
                "label": "malicious",
                "label_tier": "silver",
                "source": "unit",
                "source_version": "v1",
                "group_key": "group-train",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    test.write_text(
        json.dumps(
            {
                "sample_id": "test-release",
                "label": "benign",
                "label_tier": "gold",
                "reviewed_label": "benign",
                "reviewer": "analyst",
                "source": "unit-holdout",
                "source_version": "v1",
                "group_key": "group-test",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    dataset_dir = tmp_path / "dataset"
    build_dataset_manifest(
        dataset_name="release-data",
        inputs={"train": train, "test": test},
        output_dir=dataset_dir,
        git_commit="unit-test",
    )
    artifact = tmp_path / "artifact-manifest.json"
    write_json(
        artifact,
        {
            "artifact_id": "model-unit-v1",
            "artifact_type": "sft-adapter",
            "sha256": "a" * 64,
        },
    )
    runtime = tmp_path / "runtime.json"
    write_json(
        runtime,
        {
            "snapshot_id": "runtime-unit-v1",
            "code_sha256": "b" * 64,
            "agent_versions": {"static_analysis": {"version": "1.0.0", "sha256": "c" * 64}},
            "prompt_version": {"prompt_id": "debate-unit", "version": "1.0.0", "sha256": "d" * 64},
            "models": {
                "model_a": {"provider": "openai_compatible", "model_id": "model-a"},
                "model_b": {"provider": "openai_compatible", "model_id": "model-b"},
            },
            "xgb_artifacts": [{"artifact_id": "xgb-unit", "sha256": "e" * 64}],
            "rag_snapshot": {"snapshot_id": "rag-unit", "sha256": "f" * 64},
            "decision_params_version": {"version": "decision-v1", "sha256": "1" * 64},
        },
    )
    return dataset_dir / "dataset-manifest.json", artifact, runtime


def promote(
    tmp_path: Path,
    registry: Path,
    dataset: Path,
    artifact: Path,
    candidate_id: str,
) -> None:
    register_candidate(
        registry,
        candidate_id=candidate_id,
        component="judgement-runtime",
        artifact_manifests=[artifact],
        dataset_manifest_path=dataset,
    )
    with pytest.raises(PromotionError, match="approved"):
        promote_candidate(registry, candidate_id=candidate_id)
    gate = evaluate_candidate(
        registry,
        candidate_id=candidate_id,
        baseline_scorecard=BASELINE,
        candidate_scorecard=CANDIDATE_SCORECARD,
    )
    assert gate["gate"]["status"] == "pass"
    shadow = tmp_path / f"shadow-{candidate_id}.json"
    write_json(
        shadow,
        {"candidate_id": candidate_id, "status": "pass", "sample_count": 50, "critical_regressions": 0},
    )
    record_shadow_result(registry, candidate_id=candidate_id, shadow_report_path=shadow)
    approve_candidate(registry, candidate_id=candidate_id, approver="release-owner", note="reviewed")
    promote_candidate(registry, candidate_id=candidate_id)


def test_challenger_requires_gate_shadow_and_human_approval(tmp_path: Path) -> None:
    dataset, artifact, _ = governed_inputs(tmp_path)
    registry = tmp_path / "registry.json"
    promote(tmp_path, registry, dataset, artifact, "candidate-v1")

    value = load_registry(registry)
    assert value["champions"]["judgement-runtime"] == "candidate-v1"
    assert value["candidates"]["candidate-v1"]["status"] == "champion"
    assert value["candidates"]["candidate-v1"]["approval"]["approver"] == "release-owner"


def test_release_snapshot_binds_governed_runtime_and_detects_tampering(tmp_path: Path) -> None:
    dataset, artifact, runtime = governed_inputs(tmp_path)
    registry = tmp_path / "registry.json"
    promote(tmp_path, registry, dataset, artifact, "candidate-v1")

    release = build_release_snapshot(
        version="2.1.0",
        component="judgement-runtime",
        registry_path=registry,
        dataset_manifest_path=dataset,
        baseline_scorecard_path=BASELINE,
        candidate_scorecard_path=CANDIDATE_SCORECARD,
        docker_image_digest="sha256:" + "9" * 64,
        output_dir=tmp_path / "releases",
        runtime_snapshot_path=runtime,
        git_commit="deadbeef",
    )
    validated = validate_release_snapshot(Path(release["path"]))
    assert validated["release_id"].startswith("malapp-2.1.0-")
    assert validated["champion"]["candidate_id"] == "candidate-v1"
    assert validated["evaluation"]["gate"]["status"] == "pass"
    assert validated["runtime"]["models"]["model_a"]["model_id"] == "model-a"

    write_json(artifact, {"artifact_id": "tampered"})
    with pytest.raises(ReleaseError, match="artifact manifest"):
        validate_release_snapshot(Path(release["path"]))


def test_previous_champion_can_be_rolled_back(tmp_path: Path) -> None:
    dataset, artifact, _ = governed_inputs(tmp_path)
    registry = tmp_path / "registry.json"
    promote(tmp_path, registry, dataset, artifact, "candidate-v1")
    promote(tmp_path, registry, dataset, artifact, "candidate-v2")

    result = rollback_champion(
        registry,
        component="judgement-runtime",
        actor="incident-commander",
    )
    assert result["champion"]["candidate_id"] == "candidate-v1"
    value = load_registry(registry)
    assert value["candidates"]["candidate-v2"]["status"] == "rolled_back"


@pytest.mark.parametrize(
    ("candidate_id", "mutation", "expected"),
    [
        ("candidate-fail", lambda value: value["metrics"].update({"malicious_recall": 0.5}), "rejected"),
        ("candidate-blocked", lambda value: value.pop("validation_sha256"), "blocked"),
    ],
)
def test_failed_or_blocked_gate_cannot_reach_approval(
    tmp_path: Path,
    candidate_id: str,
    mutation,
    expected: str,
) -> None:
    dataset, artifact, _ = governed_inputs(tmp_path)
    registry = tmp_path / "registry.json"
    register_candidate(
        registry,
        candidate_id=candidate_id,
        component="judgement-runtime",
        artifact_manifests=[artifact],
        dataset_manifest_path=dataset,
    )
    scorecard = json.loads(CANDIDATE_SCORECARD.read_text(encoding="utf-8"))
    mutation(scorecard)
    scorecard_path = tmp_path / f"{candidate_id}-scorecard.json"
    write_json(scorecard_path, scorecard)
    result = evaluate_candidate(
        registry,
        candidate_id=candidate_id,
        baseline_scorecard=BASELINE,
        candidate_scorecard=scorecard_path,
    )
    assert result["candidate"]["status"] == expected
    with pytest.raises(PromotionError, match="shadow"):
        approve_candidate(registry, candidate_id=candidate_id, approver="release-owner")


def test_release_snapshot_rejects_secret_material(tmp_path: Path) -> None:
    dataset, artifact, runtime = governed_inputs(tmp_path)
    registry = tmp_path / "registry.json"
    promote(tmp_path, registry, dataset, artifact, "candidate-v1")
    runtime_value = json.loads(runtime.read_text(encoding="utf-8"))
    runtime_value["models"]["model_a"]["api_key"] = "must-not-leak"
    write_json(runtime, runtime_value)

    with pytest.raises(ReleaseError, match="secret-like"):
        build_release_snapshot(
            version="2.1.0",
            component="judgement-runtime",
            registry_path=registry,
            dataset_manifest_path=dataset,
            baseline_scorecard_path=BASELINE,
            candidate_scorecard_path=CANDIDATE_SCORECARD,
            docker_image_digest="sha256:" + "9" * 64,
            output_dir=tmp_path / "releases",
            runtime_snapshot_path=runtime,
        )
