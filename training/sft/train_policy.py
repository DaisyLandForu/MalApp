from __future__ import annotations

import argparse
import json
import pickle
from pathlib import Path
from typing import Any


def flatten_features(row: dict[str, Any]) -> dict[str, float]:
    features = row.get("features") or {}
    agent_scores = features.get("agent_scores") or {}
    flat = {
        "final_score": float(features.get("final_score") or 0.0),
        "final_confidence": float(features.get("final_confidence") or 0.0),
        "xgb_probability": float(features.get("xgb_probability") or 0.0),
        "llm_probability": float(features.get("llm_probability") or 0.0),
        "llm_confidence": float(features.get("llm_confidence") or 0.0),
        "evidence_block_count": float(features.get("evidence_block_count") or 0.0),
        "evidence_item_count": float(features.get("evidence_item_count") or 0.0),
        "missing_field_count": float(features.get("missing_field_count") or 0.0),
        "reward": float(features.get("reward") or 0.0),
    }
    for name in ("static_analysis", "threat_intel", "impersonation", "business_label"):
        flat[f"agent_{name}_score"] = float(agent_scores.get(name) or 0.0)
    return flat


def load_rows(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description="Train a baseline policy model for RAG/debate/review routing.")
    parser.add_argument("dataset", help="Path to policy_training.jsonl exported by dataset_export.")
    parser.add_argument("--output-dir", default="training_artifacts/policy_model", help="Directory for trained artifacts.")
    args = parser.parse_args()

    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import classification_report
        from sklearn.model_selection import train_test_split
    except Exception as exc:
        raise SystemExit(f"Missing dependency scikit-learn: {exc}") from exc

    rows = load_rows(Path(args.dataset))
    if len(rows) < 10:
        raise SystemExit("Need at least 10 policy rows to train a useful baseline.")
    feature_rows = [flatten_features(row) for row in rows]
    feature_names = list(feature_rows[0].keys())
    x = [[item[name] for name in feature_names] for item in feature_rows]
    labels = {
        "use_rag": [int((row.get("label") or {}).get("use_rag") or 0) for row in rows],
        "full_debate": [int((row.get("label") or {}).get("full_debate") or 0) for row in rows],
        "human_review": [int((row.get("label") or {}).get("human_review") or 0) for row in rows],
    }
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"row_count": len(rows), "feature_names": feature_names, "tasks": {}}
    models = {}
    for task, y in labels.items():
        x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.25, random_state=42, stratify=y if len(set(y)) > 1 else None)
        model = RandomForestClassifier(n_estimators=120, max_depth=5, random_state=42, class_weight="balanced")
        model.fit(x_train, y_train)
        pred = model.predict(x_test)
        report["tasks"][task] = classification_report(y_test, pred, output_dict=True, zero_division=0)
        models[task] = model
    artifact = {"feature_names": feature_names, "models": models}
    with (out_dir / "policy_model.pkl").open("wb") as f:
        pickle.dump(artifact, f)
    (out_dir / "policy_training_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"output_dir": str(out_dir), "report": report}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
