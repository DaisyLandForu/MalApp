from __future__ import annotations

import json
from pathlib import Path

import pytest

from malapp.governance.artifacts import (
    XGB_REQUIRED_MODELS,
    ArtifactCompatibilityError,
    ArtifactIntegrityError,
    build_xgboost_manifest,
    validate_xgboost_manifest,
)

AGENTS = {
    "static_analysis": ["signature"],
    "threat_intel": ["ioc"],
    "impersonation": ["brand"],
    "business_label": ["fraud"],
}
FUSION = [f"{name}_prob" for name in AGENTS]
WEC = [
    "engine_a_prob",
    "engine_b_prob",
    "engine_c_prob",
    "engine_score_gap",
    "engine_disagreement",
]


def create_manifest(tmp_path: Path) -> tuple[Path, Path, dict]:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    for name in XGB_REQUIRED_MODELS:
        (model_dir / f"{name}.json").write_text(
            json.dumps({"model": name}),
            encoding="utf-8",
        )
    database = tmp_path / "xgb_training.db"
    database.write_bytes(b"governed reference database")
    manifest = build_xgboost_manifest(
        model_dir=model_dir,
        database_path=database,
        agents=AGENTS,
        fusion_features=FUSION,
        wec_features=WEC,
        thresholds={"benign_threshold": 0.2, "malicious_threshold": 0.8},
        metrics={"macro_f1": 0.91},
        dataset_version="dataset-test-v1",
        git_commit="a" * 40,
        created_at="2026-08-17T00:00:00+00:00",
    )
    return model_dir, database, manifest


def validate(model_dir: Path, manifest: dict) -> dict:
    return validate_xgboost_manifest(
        manifest,
        model_dir=model_dir,
        expected_agents=AGENTS,
        expected_fusion_features=FUSION,
        expected_wec_features=WEC,
    )


def test_xgboost_manifest_binds_files_database_schema_and_lineage(tmp_path: Path) -> None:
    model_dir, database, manifest = create_manifest(tmp_path)

    result = validate(model_dir, manifest)

    assert result["database_path"] == database
    assert manifest["artifact_id"].startswith("xgb-runtime-20260817-")
    assert manifest["dataset_version"] == "dataset-test-v1"
    assert manifest["git_commit"] == "a" * 40
    assert len(manifest["sha256"]) == 64
    assert set(manifest["files"]) == {f"{name}.json" for name in XGB_REQUIRED_MODELS}


def test_xgboost_manifest_rejects_tampered_model(tmp_path: Path) -> None:
    model_dir, _, manifest = create_manifest(tmp_path)
    (model_dir / "fusion.json").write_text("tampered", encoding="utf-8")

    with pytest.raises(ArtifactIntegrityError, match="fusion.json"):
        validate(model_dir, manifest)


def test_xgboost_manifest_rejects_incompatible_feature_schema(tmp_path: Path) -> None:
    model_dir, _, manifest = create_manifest(tmp_path)
    manifest["feature_schema_version"] = "xgb-features-v999"

    with pytest.raises(ArtifactCompatibilityError, match="feature schema"):
        validate(model_dir, manifest)
