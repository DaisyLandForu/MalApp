from __future__ import annotations

import json
from pathlib import Path

import pytest

from malapp.governance.datasets import (
    DatasetIntegrityError,
    build_dataset_manifest,
    validate_dataset_manifest,
)
from malapp.governance.leakage import (
    TrainingLeakageError,
    audit_dataset_manifest,
    audit_lineage_records,
    require_training_clearance,
)
from scripts.governance.manage import cmd_leakage


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def safe_rows() -> tuple[list[dict], list[dict]]:
    train = [
        {
            "sample_id": "train-1",
            "md5": "1" * 32,
            "sha256": "a" * 64,
            "label": "malicious",
            "label_tier": "silver_rule_generated",
            "label_source": "engine-consensus",
            "group_id": "family:train-one",
            "features": {"permission_count": 4, "signed": True},
            "evidence_refs": ["engine-a:1"],
        }
    ]
    test = [
        {
            "sample_id": "test-1",
            "md5": "2" * 32,
            "sha256": "b" * 64,
            "label": "benign",
            "label_tier": "gold",
            "reviewer": "analyst-a",
            "reviewed_label": "benign",
            "source": "expert-holdout",
            "source_version": "holdout-v1",
            "group_key": "family:test-one",
            "features": {"permission_count": 1, "signed": True},
        }
    ]
    return train, test


def build_safe_dataset(tmp_path: Path) -> tuple[Path, dict]:
    train, test = safe_rows()
    train_path = tmp_path / "train.jsonl"
    test_path = tmp_path / "test.jsonl"
    write_jsonl(train_path, train)
    write_jsonl(test_path, test)
    output = tmp_path / "governed"
    manifest = build_dataset_manifest(
        dataset_name="unit-dataset",
        inputs={"train": train_path, "test": test_path},
        output_dir=output,
        git_commit="unit-test",
        created_at="2026-08-18T00:00:00+00:00",
    )
    return output / "dataset-manifest.json", manifest


def test_dataset_manifest_preserves_lineage_and_is_content_addressed(tmp_path: Path) -> None:
    manifest_path, manifest = build_safe_dataset(tmp_path)
    validated = validate_dataset_manifest(manifest_path, verify_sources=True)

    assert manifest["dataset_id"].startswith("dataset-")
    assert manifest["sample_count"] == 2
    assert manifest["partitions"] == {"train": 1, "test": 1}
    assert manifest["label_tiers"] == {"silver": 1, "gold": 1}
    gold = next(row for row in validated["records"] if row["label_tier"] == "gold")
    assert gold["reviewer"] == "analyst-a"
    assert gold["reviewed_label"] == "benign"
    assert gold["source_version"] == "holdout-v1"


def test_dataset_manifest_detects_lineage_tampering(tmp_path: Path) -> None:
    manifest_path, _ = build_safe_dataset(tmp_path)
    lineage = manifest_path.parent / "dataset-lineage.jsonl"
    lineage.write_text(lineage.read_text(encoding="utf-8") + "{}\n", encoding="utf-8")
    with pytest.raises(DatasetIntegrityError, match="size mismatch"):
        validate_dataset_manifest(manifest_path)


def test_leakage_audit_pass_fail_and_blocked(tmp_path: Path) -> None:
    manifest_path, _ = build_safe_dataset(tmp_path)
    passed = audit_dataset_manifest(manifest_path)
    assert passed["status"] == "pass"

    validated = validate_dataset_manifest(manifest_path)
    leaking = [dict(row) for row in validated["records"]]
    leaking[1] = {
        **leaking[1],
        "group_key": leaking[0]["group_key"],
        "feature_names": ["permission_count", "fraud_category_big"],
    }
    failed = audit_lineage_records(leaking, required_partitions={"train", "test"})
    assert failed["status"] == "fail"
    failures = {item["id"] for item in failed["checks"] if item["status"] == "fail"}
    assert "group_key_overlap" in failures
    assert "label_derived_features" in failures

    blocked = audit_lineage_records(leaking[:1], required_partitions={"train", "test"})
    assert blocked["status"] == "blocked"
    assert blocked["summary"]["blocked"] == 1


def test_reserved_frozen_sample_cannot_enter_training(tmp_path: Path) -> None:
    manifest_path, _ = build_safe_dataset(tmp_path)
    result = audit_dataset_manifest(manifest_path, reserved_sample_ids={"train-1"})
    assert result["status"] == "fail"
    check = next(item for item in result["checks"] if item["id"] == "reserved_evaluation_boundary")
    assert check["violation_count"] == 1


def test_training_clearance_is_recomputed_and_fail_closed(tmp_path: Path) -> None:
    manifest_path, _ = build_safe_dataset(tmp_path)
    report_path = tmp_path / "audit.json"
    report = require_training_clearance(manifest_path, report_path=report_path)
    assert report["status"] == "pass"
    assert json.loads(report_path.read_text(encoding="utf-8"))["audit_sha256"] == report["audit_sha256"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["partitions"] = {"train": 2}
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises((DatasetIntegrityError, TrainingLeakageError)):
        require_training_clearance(manifest_path)


def test_leakage_cli_exit_codes_are_stable(tmp_path: Path) -> None:
    manifest_path, _ = build_safe_dataset(tmp_path)

    class Args:
        manifest = str(manifest_path)
        output = None
        reserved: list[str] = []
        require_partition = ["train", "test"]

    cmd_leakage(Args())

    reserved = tmp_path / "reserved.txt"
    reserved.write_text("train-1\n", encoding="utf-8")
    Args.reserved = [str(reserved)]
    with pytest.raises(SystemExit) as failed:
        cmd_leakage(Args())
    assert failed.value.code == 1

    Args.reserved = []
    Args.require_partition = ["train", "test", "challenge"]
    with pytest.raises(SystemExit) as blocked:
        cmd_leakage(Args())
    assert blocked.value.code == 2
