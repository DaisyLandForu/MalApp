from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

from malapp.governance.artifacts import (
    XGB_FEATURE_SCHEMA_VERSION,
    validate_xgboost_manifest,
    xgboost_manifest_summary,
)

XGB_IMPORT_ERROR = ""
TRAINING_IMPORT_ERROR = ""
try:
    import xgboost as xgb
except Exception as exc:  # optional runtime dependency for rule/model fallback mode
    xgb = None
    XGB_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"

try:
    from training.xgboost import pipeline as training
except Exception as exc:
    training = None
    TRAINING_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


ROOT = Path(__file__).resolve().parents[2]
RUNTIME_DIR = Path(
    os.getenv("MALAPP_XGB_DIR", str(ROOT / "training_artifacts" / "xgb"))
).expanduser().resolve()
MODEL_DIR = RUNTIME_DIR / "models"
DEFAULT_DB_PATH = RUNTIME_DIR / "xgb_training.db"


@lru_cache(maxsize=1)
def load_runtime() -> dict[str, Any]:
    if xgb is None or training is None:
        details = []
        if xgb is None:
            details.append(f"xgboost={XGB_IMPORT_ERROR or 'not imported'}")
        if training is None:
            details.append(f"training.xgboost.pipeline={TRAINING_IMPORT_ERROR or 'not imported'}")
        raise ImportError("xgboost runtime dependencies are not installed: " + "; ".join(details))
    manifest_path = MODEL_DIR / "runtime_manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError("XGBoost runtime manifest does not exist")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validation = validate_xgboost_manifest(
        manifest,
        model_dir=MODEL_DIR,
        expected_agents={agent: training.FEATURES[agent] for agent in training.AGENTS},
        expected_fusion_features=[f"{agent}_prob" for agent in training.AGENTS],
        expected_wec_features=[
            "engine_a_prob",
            "engine_b_prob",
            "engine_c_prob",
            "engine_score_gap",
            "engine_disagreement",
        ],
        supported_feature_schema_versions={XGB_FEATURE_SCHEMA_VERSION},
    )
    models = {}
    for name in (*training.AGENTS, "fusion", "wec"):
        model = xgb.Booster()
        model.load_model(MODEL_DIR / f"{name}.json")
        models[name] = model
    database_path = validation["database_path"]
    with closing(sqlite3.connect(database_path)) as conn:
        references = training.load_reference_sets(conn)
    return {
        "manifest": manifest,
        "models": models,
        "references": references,
        "database_path": database_path,
    }


def enrich_sample(sample: dict[str, Any], database_path: Path = DEFAULT_DB_PATH) -> dict[str, Any]:
    result = dict(sample)
    if training is None:
        return result
    md5 = training.base.md5_value(result.get("md5") or result.get("sample_id"))
    if not md5 or not database_path.exists():
        return result
    with closing(sqlite3.connect(database_path)) as conn:
        row = conn.execute(
            "SELECT payload_json FROM xgb_samples WHERE md5=?", (md5,)
        ).fetchone()
    if row:
        stored = json.loads(row[0])
        stored.update({key: value for key, value in result.items() if value not in ("", None, [])})
        return stored
    return result


def predict(sample: dict[str, Any]) -> dict[str, Any] | None:
    if str(os.getenv("MALAPP_USE_XGB", "1")).lower() not in {"1", "true", "yes", "y"}:
        return None
    if training is None:
        return None
    try:
        runtime = load_runtime()
    except (ImportError, OSError, ValueError, json.JSONDecodeError):
        return None
    sample = enrich_sample(sample, runtime["database_path"])
    md5 = training.base.md5_value(sample.get("md5") or sample.get("sample_id"))
    features = training.feature_vector(md5, sample, runtime["references"])
    agent_scores = {}
    for agent in training.AGENTS:
        names = runtime["manifest"]["agents"][agent]
        values = np.asarray([[features.get(name, 0.0) for name in names]], dtype=np.float32)
        agent_scores[agent] = booster_probability(runtime["models"][agent], values)
    fusion_names = runtime["manifest"]["fusion_features"]
    fusion_values = np.asarray(
        [[agent_scores.get(name.removesuffix("_prob"), 0.0) for name in fusion_names]],
        dtype=np.float32,
    )
    engine_c = booster_probability(runtime["models"]["fusion"], fusion_values)
    wec_values_map = {
        "engine_a_prob": features["engine_a_prob"],
        "engine_b_prob": features["engine_b_prob"],
        "engine_c_prob": engine_c,
        "engine_score_gap": features["engine_score_gap"],
        "engine_disagreement": features["engine_disagreement"],
    }
    wec_names = runtime["manifest"]["wec_features"]
    wec_values = np.asarray(
        [[wec_values_map[name] for name in wec_names]], dtype=np.float32
    )
    probability = booster_probability(runtime["models"]["wec"], wec_values)
    thresholds = runtime["manifest"]["thresholds"]
    if probability < thresholds["benign_threshold"]:
        verdict = "benign"
    elif probability >= thresholds["malicious_threshold"]:
        verdict = "malicious"
    else:
        verdict = "suspicious"
    return {
        "enabled": True,
        "version": runtime["manifest"]["version"],
        "artifact": xgboost_manifest_summary(runtime["manifest"]),
        "probability": round(probability, 6),
        "verdict": verdict,
        "agent_scores": {key: round(value, 6) for key, value in agent_scores.items()},
        "engine_scores": {
            "engine_a": round(features["engine_a_prob"], 6),
            "engine_b": round(features["engine_b_prob"], 6),
            "engine_c": round(engine_c, 6),
        },
        "thresholds": thresholds,
    }


def runtime_status() -> dict[str, Any]:
    status = {
        "runtime_dir": str(RUNTIME_DIR),
        "model_dir": str(MODEL_DIR),
        "database": str(DEFAULT_DB_PATH),
        "manifest_exists": (MODEL_DIR / "runtime_manifest.json").exists(),
        "database_exists": DEFAULT_DB_PATH.exists(),
        "xgboost_imported": xgb is not None,
        "training_imported": training is not None,
        "xgboost_import_error": XGB_IMPORT_ERROR,
        "training_import_error": TRAINING_IMPORT_ERROR,
        "ready": False,
        "error": "",
    }
    try:
        runtime = load_runtime()
        status["ready"] = True
        status["version"] = runtime["manifest"].get("version", "")
        status["artifact"] = xgboost_manifest_summary(runtime["manifest"])
        status["database"] = str(runtime["database_path"])
        status["database_exists"] = runtime["database_path"].exists()
        status["models"] = sorted(runtime["models"])
    except Exception as exc:
        status["error"] = f"{type(exc).__name__}: {exc}"
    return status


def booster_probability(model: xgb.Booster, values: np.ndarray) -> float:
    best_iteration = model.attr("best_iteration")
    iteration_range = (
        (0, int(best_iteration) + 1)
        if best_iteration is not None
        else (0, 0)
    )
    prediction = model.predict(
        xgb.DMatrix(values),
        iteration_range=iteration_range,
    )
    return float(prediction[0])
