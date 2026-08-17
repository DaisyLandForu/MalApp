from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from malapp.application.judgement import DATA_DIR

LABELS = ("benign", "suspicious", "malicious")


@dataclass(frozen=True)
class Params:
    """Tunable WEC-like parameters for fast offline evaluation."""

    malicious_threshold: float
    suspicious_threshold: float
    engine_c_weight: float
    conflict_boost: float


def load_jsonl(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
            if limit and len(rows) >= limit:
                break
    return rows


def as_float(value: Any, default: float = 50.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def has_text(sample: dict[str, Any], *keys: str) -> bool:
    return any(str(sample.get(key, "")).strip() for key in keys)


def feature_score(sample: dict[str, Any], conflict_boost: float) -> float:
    """Fast Engine-C-like score for parameter search.

    This avoids running local Qwen across 10k+ validation rows. It approximates
    the agent evidence strength using structured fields.
    """
    score = 0.25
    engine_a = as_float(sample.get("engine_a_score")) / 100
    engine_b = as_float(sample.get("engine_b_score")) / 100
    descriptions = " ".join(sample.get("engine_descriptions", []) or [])
    descriptions += " " + " ".join(str(r.get("description", "")) for r in sample.get("engine_records", []))

    if abs(engine_a - engine_b) >= 0.35:
        score += conflict_boost
    if sample.get("fake_app"):
        score += 0.25
    if has_text(sample, "fraud_family", "fraud_category_big", "fraud_category_small"):
        score += 0.25
    if has_text(sample, "control_url", "download_url", "control_mailbox", "control_phone"):
        score += 0.12
    if sample.get("packer"):
        score += 0.08
    if any(term in descriptions for term in ("高风险", "恶意", "涉诈", "扣费", "窃取", "病毒", "风险")):
        score += 0.18
    if max(engine_a, engine_b) >= 0.85:
        score += 0.12

    return max(0.0, min(1.0, round(score, 4)))


def verdict_from_score(score: float, params: Params) -> str:
    if score >= params.malicious_threshold:
        return "malicious"
    if score >= params.suspicious_threshold:
        return "suspicious"
    return "benign"


def predict(sample: dict[str, Any], params: Params) -> tuple[str, float, dict[str, float]]:
    engine_a = as_float(sample.get("engine_a_score")) / 100
    engine_b = as_float(sample.get("engine_b_score")) / 100
    engine_c = feature_score(sample, params.conflict_boost)
    final_score = (engine_a + engine_b + engine_c * params.engine_c_weight) / (2 + params.engine_c_weight)
    final_score = max(0.0, min(1.0, round(final_score, 4)))
    return verdict_from_score(final_score, params), final_score, {
        "engine_a": engine_a,
        "engine_b": engine_b,
        "engine_c": engine_c,
    }


def score_result(rows: list[dict[str, Any]], params: Params) -> dict[str, Any]:
    confusion = {gold: {pred: 0 for pred in LABELS} for gold in LABELS}
    exact = 0
    malicious_tp = malicious_fp = malicious_fn = 0
    suspicious_or_malicious_tp = suspicious_or_malicious_fp = suspicious_or_malicious_fn = 0

    for row in rows:
        gold = row["weak_label"]
        pred, _, _ = predict(row["input"], params)
        confusion[gold][pred] += 1
        exact += int(pred == gold)

        gold_mal = gold == "malicious"
        pred_mal = pred == "malicious"
        malicious_tp += int(gold_mal and pred_mal)
        malicious_fp += int(not gold_mal and pred_mal)
        malicious_fn += int(gold_mal and not pred_mal)

        gold_risk = gold in {"suspicious", "malicious"}
        pred_risk = pred in {"suspicious", "malicious"}
        suspicious_or_malicious_tp += int(gold_risk and pred_risk)
        suspicious_or_malicious_fp += int(not gold_risk and pred_risk)
        suspicious_or_malicious_fn += int(gold_risk and not pred_risk)

    total = max(1, len(rows))
    return {
        "params": params.__dict__,
        "total": len(rows),
        "accuracy": round(exact / total, 4),
        "malicious_precision": safe_div(malicious_tp, malicious_tp + malicious_fp),
        "malicious_recall": safe_div(malicious_tp, malicious_tp + malicious_fn),
        "risk_precision": safe_div(suspicious_or_malicious_tp, suspicious_or_malicious_tp + suspicious_or_malicious_fp),
        "risk_recall": safe_div(suspicious_or_malicious_tp, suspicious_or_malicious_tp + suspicious_or_malicious_fn),
        "confusion": confusion,
    }


def safe_div(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def param_grid() -> list[Params]:
    """Parameter combinations to try on val/test jsonl files."""
    items = []
    for malicious_threshold in (0.80, 0.85, 0.90):
        for suspicious_threshold in (0.50, 0.55, 0.60, 0.65):
            if suspicious_threshold >= malicious_threshold:
                continue
            for engine_c_weight in (0.6, 0.8, 1.0, 1.2):
                for conflict_boost in (0.0, 0.1, 0.2, 0.3):
                    items.append(Params(malicious_threshold, suspicious_threshold, engine_c_weight, conflict_boost))
    return items


def write_summary(path: Path, results: list[dict[str, Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "rank",
                "accuracy",
                "malicious_precision",
                "malicious_recall",
                "risk_precision",
                "risk_recall",
                "malicious_threshold",
                "suspicious_threshold",
                "engine_c_weight",
                "conflict_boost",
            ],
        )
        writer.writeheader()
        for index, result in enumerate(results, start=1):
            row = {
                "rank": index,
                "accuracy": result["accuracy"],
                "malicious_precision": result["malicious_precision"],
                "malicious_recall": result["malicious_recall"],
                "risk_precision": result["risk_precision"],
                "risk_recall": result["risk_recall"],
                **result["params"],
            }
            writer.writerow(row)


def write_review_candidates(path: Path, rows: list[dict[str, Any]], params: Params, limit: int = 300) -> None:
    """Export samples that are worth manual review.

    Priority is given to prediction/weak-label mismatches, engine conflicts,
    high-risk samples, and boundary-score samples.
    """
    candidates = []
    for row in rows:
        sample = row["input"]
        pred, score, engine_scores = predict(sample, params)
        gold = row["weak_label"]
        conflict = abs(engine_scores["engine_a"] - engine_scores["engine_b"]) >= 0.35
        mismatch = pred != gold
        high_risk = score >= params.malicious_threshold or sample.get("fake_app") or sample.get("fraud_family")
        boundary = params.suspicious_threshold - 0.05 <= score <= params.malicious_threshold + 0.05
        if conflict or mismatch or high_risk or boundary:
            priority = int(mismatch) * 4 + int(conflict) * 3 + int(high_risk) * 2 + int(boundary)
            candidates.append((priority, {
                "md5": row["id"],
                "weak_label": gold,
                "pred": pred,
                "final_score": score,
                "engine_a_score": engine_scores["engine_a"],
                "engine_b_score": engine_scores["engine_b"],
                "engine_c_score": engine_scores["engine_c"],
                "app_name": sample.get("app_name", ""),
                "package_name": sample.get("package_name", ""),
                "fake_app": sample.get("fake_app", ""),
                "fraud_family": sample.get("fraud_family", ""),
                "reason": ",".join(
                    name for name, yes in {
                        "mismatch": mismatch,
                        "engine_conflict": conflict,
                        "high_risk": high_risk,
                        "boundary": boundary,
                    }.items() if yes
                ),
            }))
    candidates.sort(key=lambda item: item[0], reverse=True)
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(candidates[0][1].keys()) if candidates else ["md5"])
        writer.writeheader()
        for _, row in candidates[:limit]:
            writer.writerow(row)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default=str(DATA_DIR / "datasets" / "val.jsonl"))
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--out-dir", default=str(DATA_DIR / "eval"))
    args = parser.parse_args()

    dataset_path = Path(args.dataset)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = load_jsonl(dataset_path, limit=args.limit)
    results = [score_result(rows, params) for params in param_grid()]
    results.sort(key=lambda item: (item["risk_recall"], item["malicious_recall"], item["accuracy"]), reverse=True)
    best = results[0]

    write_summary(out_dir / "param_grid_summary.csv", results)
    (out_dir / "best_params.json").write_text(json.dumps(best, ensure_ascii=False, indent=2), encoding="utf-8")
    write_review_candidates(out_dir / "review_candidates.csv", rows, Params(**best["params"]))

    print(json.dumps({
        "dataset": str(dataset_path),
        "rows": len(rows),
        "best": best,
        "summary_csv": str(out_dir / "param_grid_summary.csv"),
        "review_candidates_csv": str(out_dir / "review_candidates.csv"),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
