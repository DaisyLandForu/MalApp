from __future__ import annotations

import csv
import hashlib
import json
import math
import sqlite3
import statistics
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from malapp.config.paths import resolve_data_dir

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_VALIDATION_CSV = (
    ROOT / "training_artifacts" / "xgb_selected_20260616" / "test_set_for_app.csv"
)
LABELS = ("malicious", "suspicious", "benign")
ERROR_TYPES = {
    "false_negative",
    "false_positive",
    "unnecessary_review",
    "wrong_evidence",
    "missing_evidence",
    "hallucination",
    "retrieval_miss",
    "retrieval_noise",
    "agent_tool_error",
    "agent_timeout",
    "model_timeout",
    "model_unavailable",
    "schema_error",
    "calibration_error",
    "threshold_error",
    "data_quality",
    "other",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def evaluation_dir(data_dir: Path | None = None) -> Path:
    path = (data_dir or resolve_data_dir()) / "evaluation"
    path.mkdir(parents=True, exist_ok=True)
    return path


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return default


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def _clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _as_float(value: Any, default: float | None = None) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def validation_gold_label(row: dict[str, Any]) -> str:
    for key in ("gold_label", "source_malicious"):
        text = _clean(row.get(key)).lower()
        if text in {"1", "true", "yes", "y", "malicious", "恶意", "100"}:
            return "malicious"
        if text in {"0", "false", "no", "n", "benign", "良性", "white", "白样本"}:
            return "benign"
    return "malicious" if _clean(row.get("label_source")) == "manual_conflict" else "benign"


def load_validation_rows(path: Path = DEFAULT_VALIDATION_CSV) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"validation CSV not found: {path}")
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for raw in csv.DictReader(handle):
            row = {_clean(key): _clean(value) for key, value in raw.items()}
            row["_gold_label"] = validation_gold_label(row)
            row["_row_id"] = _clean(row.get("md5") or row.get("sample_id")).upper()
            rows.append(row)
    return rows


def load_reports(data_dir: Path | None = None) -> list[dict[str, Any]]:
    db_path = (data_dir or resolve_data_dir()) / "mvp.db"
    if not db_path.exists():
        return []
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT payload_json FROM judgements ORDER BY created_at DESC"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        if conn is not None:
            conn.close()
    reports: list[dict[str, Any]] = []
    for (payload,) in rows:
        try:
            reports.append(json.loads(payload))
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
    return reports


def load_human_reviews(data_dir: Path | None = None) -> list[dict[str, Any]]:
    db_path = (data_dir or resolve_data_dir()) / "mvp.db"
    if not db_path.exists():
        return []
    conn: sqlite3.Connection | None = None
    try:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT payload_json FROM human_reviews ORDER BY created_at DESC"
        ).fetchall()
    except sqlite3.Error:
        return []
    finally:
        if conn is not None:
            conn.close()
    reviews: list[dict[str, Any]] = []
    for (payload,) in rows:
        try:
            value = json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            reviews.append(value)
    return reviews


def latest_human_review_index(
    reviews: Iterable[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_report: dict[str, dict[str, Any]] = {}
    by_sample: dict[str, dict[str, Any]] = {}
    for review in reviews:
        report_id = _clean(review.get("report_id"))
        sample_id = _clean(review.get("md5") or review.get("sample_id")).upper()
        if report_id and report_id not in by_report:
            by_report[report_id] = review
        if sample_id and sample_id not in by_sample:
            by_sample[sample_id] = review
    return by_report, by_sample


def latest_report_index(reports: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for report in reports:
        sample = report.get("sample") or {}
        key = _clean(sample.get("md5") or sample.get("sample_id")).upper()
        if key and key not in index:
            index[key] = report
    return index


def _percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    position = (len(ordered) - 1) * q
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    weight = position - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


def _safe_div(numerator: float, denominator: float) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _report_latency_ms(report: dict[str, Any]) -> float | None:
    debate = report.get("debate") or {}
    metrics = debate.get("metrics") or debate.get("timings") or {}
    value = _as_float(metrics.get("latency_ms"))
    if value is not None:
        return value
    execution = report.get("execution") or {}
    return _as_float(execution.get("latency_ms"))


def _report_structure_valid(report: dict[str, Any]) -> bool:
    decision = report.get("decision") or {}
    verdict = _clean(decision.get("verdict")).lower()
    return bool(
        report.get("report_id")
        and report.get("sample")
        and verdict in LABELS
        and len(report.get("evidence_blocks") or []) >= 4
        and (report.get("debate") or {}).get("arbiter")
    )


def _contains_invalid_fallback(report: dict[str, Any]) -> bool:
    debate = report.get("debate") or {}
    for stage in debate.get("stages") or []:
        for key in ("model_a", "model_b", "result", "response"):
            value = stage.get(key)
            if isinstance(value, dict) and "invalid_fallback" in _clean(value.get("backend")):
                return True
    return "invalid_fallback" in json.dumps(debate, ensure_ascii=False)


def _macro_f1(tp: int, fn: int, fp: int, tn: int) -> float | None:
    malicious_precision = _safe_div(tp, tp + fp)
    malicious_recall = _safe_div(tp, tp + fn)
    benign_precision = _safe_div(tn, tn + fn)
    benign_recall = _safe_div(tn, tn + fp)

    def f1(precision: float | None, recall: float | None) -> float | None:
        if precision is None or recall is None or precision + recall == 0:
            return None
        return 2 * precision * recall / (precision + recall)

    values = [
        value
        for value in (
            f1(malicious_precision, malicious_recall),
            f1(benign_precision, benign_recall),
        )
        if value is not None
    ]
    return round(statistics.mean(values), 6) if values else None


def _calibration_metrics(items: list[tuple[int, float]], bins: int = 10) -> dict[str, Any]:
    if not items:
        return {"count": 0, "brier_score": None, "ece": None, "bins": []}
    brier = statistics.mean((probability - gold) ** 2 for gold, probability in items)
    bin_rows = []
    weighted_error = 0.0
    for index in range(bins):
        low = index / bins
        high = (index + 1) / bins
        selected = [
            (gold, probability)
            for gold, probability in items
            if low <= probability < high or (index == bins - 1 and probability == 1.0)
        ]
        if not selected:
            continue
        accuracy = statistics.mean(gold for gold, _ in selected)
        confidence = statistics.mean(probability for _, probability in selected)
        weighted_error += len(selected) / len(items) * abs(accuracy - confidence)
        bin_rows.append(
            {
                "low": low,
                "high": high,
                "count": len(selected),
                "accuracy": round(accuracy, 6),
                "confidence": round(confidence, 6),
            }
        )
    return {
        "count": len(items),
        "brier_score": round(brier, 6),
        "ece": round(weighted_error, 6),
        "bins": bin_rows,
    }


def infer_error_types(
    gold_label: str,
    report: dict[str, Any] | None,
) -> list[str]:
    if not report:
        return []
    decision = report.get("decision") or {}
    verdict = _clean(decision.get("verdict")).lower()
    errors: list[str] = []
    if gold_label == "malicious" and verdict == "benign":
        errors.append("false_negative")
    if gold_label == "benign" and verdict == "malicious":
        errors.append("false_positive")
    if verdict == "suspicious":
        errors.append("unnecessary_review")
    if not _report_structure_valid(report):
        errors.append("schema_error")
    if _contains_invalid_fallback(report):
        errors.append("schema_error")
    rag_context = (report.get("evidence_layers") or {}).get("rag_context") or {}
    if rag_context.get("enabled") and not rag_context.get("items"):
        errors.append("retrieval_miss")
    runtime = ((report.get("preprocess") or {}).get("agent_runtime") or {}).get("agents") or {}
    if any(_clean(value.get("status")) in {"timeout", "degraded"} for value in runtime.values()):
        errors.append("agent_timeout")
    error_text = json.dumps(report.get("execution") or {}, ensure_ascii=False).lower()
    if "timeout" in error_text:
        errors.append("model_timeout")
    if any(token in error_text for token in ("unavailable", "connection", "refused")):
        errors.append("model_unavailable")
    return sorted(set(errors))


def build_scorecard(
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    rows = load_validation_rows(validation_csv)
    reports = load_reports(data_dir)
    index = latest_report_index(reports)
    reviews_by_report, reviews_by_sample = latest_human_review_index(
        load_human_reviews(data_dir)
    )
    confusion = {
        gold: {predicted: 0 for predicted in LABELS}
        for gold in ("malicious", "benign")
    }
    correct = incorrect = review = 0
    structure_valid = invalid_fallback = 0
    latencies: list[float] = []
    calibration: list[tuple[int, float]] = []
    error_counts: Counter[str] = Counter()
    reviewed_reports = 0
    review_quality: dict[str, list[bool]] = {
        "evidence_supported": [],
        "json_valid": [],
        "concise": [],
        "punctuation_valid": [],
        "hallucination": [],
    }
    evaluated = 0
    for row in rows:
        report = index.get(row["_row_id"])
        if not report:
            continue
        verdict = _clean((report.get("decision") or {}).get("verdict")).lower()
        if verdict not in LABELS:
            continue
        gold = row["_gold_label"]
        evaluated += 1
        confusion[gold][verdict] += 1
        if verdict == "suspicious":
            review += 1
        elif verdict == gold:
            correct += 1
        else:
            incorrect += 1
        structure_valid += int(_report_structure_valid(report))
        invalid_fallback += int(_contains_invalid_fallback(report))
        latency = _report_latency_ms(report)
        if latency is not None:
            latencies.append(latency)
        probability = _as_float((report.get("decision") or {}).get("final_score"))
        if probability is not None:
            calibration.append((1 if gold == "malicious" else 0, min(1.0, max(0.0, probability))))
        error_counts.update(infer_error_types(gold, report))
        review_payload = reviews_by_report.get(_clean(report.get("report_id")))
        if not review_payload:
            review_payload = reviews_by_sample.get(row["_row_id"])
        if review_payload:
            reviewed_reports += 1
            for field in review_quality:
                value = review_payload.get(field)
                if isinstance(value, bool):
                    review_quality[field].append(value)

    tp = confusion["malicious"]["malicious"]
    fn = confusion["malicious"]["benign"]
    fp = confusion["benign"]["malicious"]
    tn = confusion["benign"]["benign"]
    malicious_total = sum(confusion["malicious"].values())
    benign_total = sum(confusion["benign"].values())
    decided = correct + incorrect
    metrics = {
        "validation_total": len(rows),
        "evaluated_total": evaluated,
        "pending_total": len(rows) - evaluated,
        "coverage": _safe_div(evaluated, len(rows)),
        "correct": correct,
        "incorrect": incorrect,
        "review": review,
        "decided_accuracy": _safe_div(correct, decided),
        # A suspicious/manual-review output has not automatically recalled an
        # actual malicious sample, so it remains in the recall denominator.
        "malicious_recall": _safe_div(tp, malicious_total),
        "malicious_precision": _safe_div(tp, tp + fp),
        "benign_false_positive_rate": _safe_div(fp, benign_total),
        "macro_f1": _macro_f1(tp, fn, fp, tn),
        "review_rate": _safe_div(review, evaluated),
        "structure_success_rate": _safe_div(structure_valid, evaluated),
        "invalid_fallback_rate": _safe_div(invalid_fallback, evaluated),
        "human_review": {
            "reviewed_reports": reviewed_reports,
            "evidence_supported_count": len(review_quality["evidence_supported"]),
            "evidence_faithfulness_rate": _safe_div(
                sum(review_quality["evidence_supported"]),
                len(review_quality["evidence_supported"]),
            ),
            "json_valid_rate": _safe_div(
                sum(review_quality["json_valid"]), len(review_quality["json_valid"])
            ),
            "concise_rate": _safe_div(
                sum(review_quality["concise"]), len(review_quality["concise"])
            ),
            "punctuation_valid_rate": _safe_div(
                sum(review_quality["punctuation_valid"]),
                len(review_quality["punctuation_valid"]),
            ),
            "hallucination_rate": _safe_div(
                sum(review_quality["hallucination"]),
                len(review_quality["hallucination"]),
            ),
        },
        "latency_ms": {
            "count": len(latencies),
            "p50": _percentile(latencies, 0.50),
            "p90": _percentile(latencies, 0.90),
            "p95": _percentile(latencies, 0.95),
            "p99": _percentile(latencies, 0.99),
        },
        "calibration": _calibration_metrics(calibration),
        "confusion": confusion,
        "error_counts": dict(error_counts),
    }
    return {
        "generated_at": now_iso(),
        "validation_csv": str(validation_csv),
        "validation_sha256": sha256_file(validation_csv),
        "data_dir": str(data_dir or resolve_data_dir()),
        "metrics": metrics,
        "limitations": [
            "Evidence faithfulness is reported only for samples with an explicit human evidence_supported label.",
            "Metrics cover only saved reports matched to the validation set by MD5/sample_id.",
            "A frozen expert-labelled set is still required before production release decisions.",
        ],
    }


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
            if isinstance(value, dict):
                rows.append(value)
    return rows


def build_rag_retrieval_scorecard(dataset_jsonl: Path) -> dict[str, Any]:
    dataset_jsonl = dataset_jsonl.expanduser().resolve()
    rows = _read_jsonl(dataset_jsonl)
    annotated = [
        row
        for row in rows
        if _clean(row.get("annotation_status")).lower() in {"approved", "adjudicated"}
    ]
    def mean(values: list[float]) -> float | None:
        return round(statistics.fmean(values), 6) if values else None

    def score(selected: list[dict[str, Any]], relevant_field: str) -> dict[str, Any]:
        with_relevant = 0
        recall_5: list[float] = []
        recall_10: list[float] = []
        reciprocal_ranks: list[float] = []
        ndcg_10: list[float] = []
        context_precision: list[float] = []
        no_relevant = 0
        no_relevant_correct = 0
        for row in selected:
            retrieved = [
                _clean(value)
                for value in row.get("retrieved_doc_ids") or []
                if _clean(value)
            ]
            relevant = {
                _clean(value)
                for value in row.get(relevant_field) or []
                if _clean(value)
            }
            if not relevant:
                no_relevant += 1
                no_relevant_correct += int(not retrieved)
                continue
            with_relevant += 1
            recall_5.append(len(relevant.intersection(retrieved[:5])) / len(relevant))
            recall_10.append(len(relevant.intersection(retrieved[:10])) / len(relevant))
            first_rank = next(
                (
                    rank
                    for rank, doc_id in enumerate(retrieved, start=1)
                    if doc_id in relevant
                ),
                None,
            )
            reciprocal_ranks.append(1.0 / first_rank if first_rank else 0.0)
            dcg = sum(
                1.0 / math.log2(rank + 1)
                for rank, doc_id in enumerate(retrieved[:10], start=1)
                if doc_id in relevant
            )
            ideal_hits = min(len(relevant), 10)
            ideal_dcg = sum(
                1.0 / math.log2(rank + 1) for rank in range(1, ideal_hits + 1)
            )
            ndcg_10.append(dcg / ideal_dcg if ideal_dcg else 0.0)
            context_precision.append(
                sum(1 for doc_id in retrieved if doc_id in relevant) / len(retrieved)
                if retrieved
                else 0.0
            )
        return {
            "queries_with_relevant_documents": with_relevant,
            "queries_without_relevant_documents": no_relevant,
            "recall_at_5": mean(recall_5),
            "recall_at_10": mean(recall_10),
            "mrr": mean(reciprocal_ranks),
            "ndcg_at_10": mean(ndcg_10),
            "context_precision": mean(context_precision),
            "no_relevant_accuracy": _safe_div(no_relevant_correct, no_relevant),
        }

    official = score(annotated, "relevant_doc_ids")
    silver_rows = [row for row in rows if row.get("weak_relevant_doc_ids")]
    silver = score(silver_rows, "weak_relevant_doc_ids")
    evidence_values = [
        row.get("evidence_supported")
        for row in annotated
        if isinstance(row.get("evidence_supported"), bool)
    ]
    hallucination_values = [
        row.get("hallucination")
        for row in annotated
        if isinstance(row.get("hallucination"), bool)
    ]
    official_metrics = {
        key: value
        for key, value in official.items()
        if key not in {"queries_with_relevant_documents", "queries_without_relevant_documents"}
    }
    official_metrics["evidence_faithfulness_rate"] = _safe_div(
        sum(evidence_values), len(evidence_values)
    )
    official_metrics["hallucination_rate"] = _safe_div(
        sum(hallucination_values), len(hallucination_values)
    )
    return {
        "generated_at": now_iso(),
        "dataset_jsonl": str(dataset_jsonl),
        "dataset_sha256": sha256_file(dataset_jsonl),
        "total_rows": len(rows),
        "approved_rows": len(annotated),
        "queries_with_relevant_documents": official[
            "queries_with_relevant_documents"
        ],
        "queries_without_relevant_documents": official[
            "queries_without_relevant_documents"
        ],
        "evidence_review_count": len(evidence_values),
        "hallucination_review_count": len(hallucination_values),
        "metrics": official_metrics,
        "silver_prelabel_rows": len(silver_rows),
        "silver_metrics": {
            key: value
            for key, value in silver.items()
            if key not in {
                "queries_with_relevant_documents",
                "queries_without_relevant_documents",
            }
        },
        "valid": bool(annotated),
        "limitations": (
            [
                "Weak-label metrics are diagnostic silver metrics and are not valid release-gate evidence."
            ]
            if annotated
            else [
                "No approved/adjudicated annotations; official retrieval metrics are not valid yet.",
                "Weak-label metrics are diagnostic silver metrics and are not valid release-gate evidence.",
            ]
        ),
    }


def capture_runtime_snapshot(data_dir: Path | None = None) -> dict[str, Any]:
    from malapp.governance.runtime import capture_runtime_snapshot as capture_governed_snapshot

    return capture_governed_snapshot(data_dir=data_dir)


def save_runtime_snapshot(
    snapshot: dict[str, Any] | None = None,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    from malapp.governance.runtime import save_runtime_snapshot as save_governed_snapshot

    return save_governed_snapshot(snapshot, data_dir=data_dir)


def _group_key(row: dict[str, Any]) -> str:
    values = [
        _clean(row.get("certificate_sha256") or row.get("certificate_md5")),
        _clean(row.get("developer") or row.get("developer_name")),
        _clean(row.get("package_name")),
        _clean(row.get("fraud_family") or row.get("virus_name")),
        _clean(row.get("control_url") or row.get("download_url")),
    ]
    values = [value.lower() for value in values if value]
    return "|".join(values) if values else row["_row_id"].lower()


def freeze_evaluation_manifest(
    name: str = "v1",
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    rows = load_validation_rows(validation_csv)
    report_index = latest_report_index(load_reports(data_dir))
    snapshot = save_runtime_snapshot(data_dir=data_dir)
    items = []
    for row in rows:
        report = report_index.get(row["_row_id"])
        items.append(
            {
                "id": row["_row_id"],
                "gold_label": row["_gold_label"],
                "label_source": row.get("label_source", ""),
                "app_name": row.get("app_name", ""),
                "package_name": row.get("package_name", ""),
                "virus_name": row.get("virus_name", ""),
                "group_key": _group_key(row),
                "report_id": (report or {}).get("report_id"),
                "judged": bool(report),
                "verdict": ((report or {}).get("decision") or {}).get("verdict"),
                "error_types": infer_error_types(row["_gold_label"], report),
            }
        )
    created_at = now_iso()
    manifest = {
        "manifest_version": 1,
        "plan_version": name,
        "created_at": created_at,
        "status": "frozen",
        "validation_source": {
            "path": str(validation_csv),
            "sha256": sha256_file(validation_csv),
            "rows": len(rows),
        },
        "runtime_snapshot_id": snapshot["snapshot_id"],
        "runtime_snapshot_path": snapshot["path"],
        "counts": {
            "total": len(items),
            "judged": sum(int(item["judged"]) for item in items),
            "pending": sum(int(not item["judged"]) for item in items),
            "malicious": sum(int(item["gold_label"] == "malicious") for item in items),
            "benign": sum(int(item["gold_label"] == "benign") for item in items),
            "known_errors": sum(int(bool(item["error_types"])) for item in items),
        },
        "items": items,
    }
    manifest_id = f"{name}-{created_at[:10]}-{_stable_hash(json.dumps(items, sort_keys=True))[:10]}"
    manifest["manifest_id"] = manifest_id
    path = evaluation_dir(data_dir) / "manifests" / f"{manifest_id}.json"
    _write_json(path, manifest)
    latest_path = evaluation_dir(data_dir) / "manifests" / "latest.json"
    _write_json(latest_path, {"manifest_id": manifest_id, "path": str(path), "created_at": created_at})
    return {**manifest, "path": str(path)}


def _candidate_row(
    row: dict[str, Any],
    report: dict[str, Any] | None,
    dataset_type: str,
) -> dict[str, Any]:
    decision = (report or {}).get("decision") or {}
    return {
        "id": row["_row_id"],
        "dataset_type": dataset_type,
        "annotation_status": "pending",
        "gold_label_seed": row["_gold_label"],
        "gold_label": None,
        "label_source": row.get("label_source", ""),
        "app_name": row.get("app_name", ""),
        "package_name": row.get("package_name", ""),
        "virus_name": row.get("virus_name", ""),
        "group_key": _group_key(row),
        "current_report_id": (report or {}).get("report_id"),
        "current_verdict": decision.get("verdict"),
        "current_score": _as_float(decision.get("final_score")),
        "error_types": infer_error_types(row["_gold_label"], report),
        "review": {
            "reviewer_1": None,
            "reviewer_2": None,
            "adjudicator": None,
            "evidence_supported": None,
            "hallucination": None,
            "notes": "",
        },
    }


def _deterministic_take(
    rows: list[dict[str, Any]],
    size: int,
    *,
    seed: str,
) -> list[dict[str, Any]]:
    selected = []
    seen_groups = set()
    for row in sorted(rows, key=lambda row: _stable_hash(seed + "|" + row["_row_id"])):
        group = _group_key(row)
        if group in seen_groups:
            continue
        seen_groups.add(group)
        selected.append(row)
        if len(selected) >= max(0, size):
            break
    return selected


def _balanced_core_rows(rows: list[dict[str, Any]], size: int) -> list[dict[str, Any]]:
    malicious = [row for row in rows if row["_gold_label"] == "malicious"]
    benign = [row for row in rows if row["_gold_label"] == "benign"]
    benign_target = min(len(benign), size // 2)
    malicious_target = min(len(malicious), size - benign_target)
    selected = _deterministic_take(benign, benign_target, seed="core-benign")
    selected += _deterministic_take(malicious, malicious_target, seed="core-malicious")
    remaining = size - len(selected)
    if remaining > 0:
        chosen = {row["_row_id"] for row in selected}
        selected += _deterministic_take(
            [row for row in rows if row["_row_id"] not in chosen],
            remaining,
            seed="core-fill",
        )
    return selected


def _challenge_priority(row: dict[str, Any], report: dict[str, Any] | None) -> tuple[int, str]:
    priority = 0
    errors = infer_error_types(row["_gold_label"], report)
    priority += 100 * int(bool(errors))
    probability = _as_float(row.get("xgb_probability"))
    if probability is not None and 0.25 <= probability <= 0.75:
        priority += 30
    score_360 = _as_float(row.get("engine_360_score"))
    score_cm = _as_float(row.get("engine_cm_score"))
    if score_360 is not None and score_cm is not None and abs(score_360 - score_cm) >= 30:
        priority += 25
    if "conflict" in _clean(row.get("label_source")).lower():
        priority += 30
    if row.get("virus_name"):
        priority += 5
    return priority, _stable_hash("challenge|" + row["_row_id"])


def generate_evaluation_datasets(
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
    *,
    core_size: int = 500,
    challenge_size: int = 300,
    rag_size: int = 200,
) -> dict[str, Any]:
    rows = load_validation_rows(validation_csv)
    reports = load_reports(data_dir)
    index = latest_report_index(reports)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = evaluation_dir(data_dir) / "datasets" / timestamp

    core_rows = _balanced_core_rows(rows, min(core_size, len(rows)))
    core_ids = {row["_row_id"] for row in core_rows}
    core_groups = {_group_key(row) for row in core_rows}
    challenge_rows = sorted(
        [
            row
            for row in rows
            if row["_row_id"] not in core_ids and _group_key(row) not in core_groups
        ],
        key=lambda row: _challenge_priority(row, index.get(row["_row_id"])),
        reverse=True,
    )[: min(challenge_size, max(0, len(rows) - len(core_rows)))]

    rag_candidates = []
    for row in rows:
        report = index.get(row["_row_id"])
        rag = ((report or {}).get("evidence_layers") or {}).get("rag_context") or {}
        query = _clean(rag.get("query"))
        items = rag.get("items") or []
        if not query:
            continue
        candidate = _candidate_row(row, report, "rag_retrieval")
        candidate.update(
            {
                "query": query,
                "retrieved_doc_ids": [
                    item.get("doc_id") for item in items if isinstance(item, dict) and item.get("doc_id")
                ],
                "relevant_doc_ids": [],
                "hard_negative_doc_ids": [],
            }
        )
        rag_candidates.append(candidate)
    rag_rows = sorted(
        rag_candidates,
        key=lambda row: _stable_hash("rag|" + row["id"]),
    )[: min(rag_size, len(rag_candidates))]

    files = {
        "expert_core_candidates": output_dir / "expert_core_candidates.jsonl",
        "challenge_candidates": output_dir / "challenge_candidates.jsonl",
        "rag_retrieval_candidates": output_dir / "rag_retrieval_candidates.jsonl",
        "README": output_dir / "README.md",
    }
    counts = {
        "expert_core_candidates": _write_jsonl(
            files["expert_core_candidates"],
            (_candidate_row(row, index.get(row["_row_id"]), "expert_core") for row in core_rows),
        ),
        "challenge_candidates": _write_jsonl(
            files["challenge_candidates"],
            (_candidate_row(row, index.get(row["_row_id"]), "challenge") for row in challenge_rows),
        ),
        "rag_retrieval_candidates": _write_jsonl(files["rag_retrieval_candidates"], rag_rows),
    }
    files["README"].write_text(
        "\n".join(
            [
                "# MalApp evaluation annotation package",
                "",
                "These files are annotation candidates, not expert gold labels.",
                "Set annotation_status=approved only after two independent reviews and adjudication.",
                "Do not use an approved frozen test item for training, prompt tuning, threshold tuning, or DPO.",
                "RAG rows require relevant_doc_ids and hard_negative_doc_ids before retrieval metrics are valid.",
            ]
        ),
        encoding="utf-8",
    )
    summary = {
        "generated_at": now_iso(),
        "output_dir": str(output_dir),
        "counts": counts,
        "files": {key: str(path) for key, path in files.items()},
        "annotation_required": True,
        "leakage_audit": {
            "core_challenge_id_overlap": len(
                core_ids.intersection(row["_row_id"] for row in challenge_rows)
            ),
            "core_challenge_group_overlap": len(
                core_groups.intersection(_group_key(row) for row in challenge_rows)
            ),
        },
    }
    _write_json(output_dir / "summary.json", summary)
    return summary


def evaluation_plan() -> dict[str, Any]:
    return {
        "plan_version": "v1",
        "phases": [
            {
                "phase": 1,
                "duration": "1 week",
                "deliverables": [
                    "Frozen evaluation manifest and runtime snapshot",
                    "Completion queue for pending validation samples",
                    "Human review error taxonomy and corrected-output fields",
                    "Per-trace model, prompt/code, RAG, GPU and endpoint fingerprint",
                ],
                "exit_criteria": [
                    "All 2,155 validation items have an explicit judged/pending state",
                    "All known errors are assigned at least one root-cause category",
                    "Every new trace contains runtime_snapshot_id",
                ],
            },
            {
                "phase": 2,
                "duration": "1-2 weeks",
                "deliverables": [
                    "500 expert-core annotation candidates",
                    "300 challenge candidates",
                    "200 RAG retrieval candidates",
                    "Quality, calibration, structure and latency scorecard",
                ],
                "exit_criteria": [
                    "Core gold set has two independent labels plus adjudication",
                    "No entity-group leakage between train/dev/frozen test",
                    "Release scorecard is reproducible from a frozen manifest",
                ],
            },
            {
                "phase": 3,
                "duration": "2-4 weeks",
                "deliverables": [
                    "Leave-one-agent-out experiment runs",
                    "Model A/B replacement experiment runs",
                    "RAG off/vector/hybrid experiment runs",
                    "Fault injection and checkpoint-resume runs",
                ],
                "exit_criteria": [
                    "Each component has measured marginal quality, latency and cost",
                    "Transient failures recover without duplicate saved results",
                    "Candidate version passes all release gates",
                ],
            },
            {
                "phase": "continuous",
                "duration": "weekly/monthly",
                "deliverables": [
                    "Weekly error and uncertainty replay",
                    "Monthly frozen regression snapshot",
                    "Shadow and staged canary comparison",
                ],
                "exit_criteria": [
                    "No quality or reliability gate regression during canary",
                    "Rollback metadata is complete and tested",
                ],
            },
        ],
        "experiment_variants": {
            "full": {"description": "Current full pipeline", "environment": {}},
            "verification": {
                "description": "XGBoost-guided short model verification",
                "sample_overrides": {"evaluation_config": {"debate_mode": "verification"}},
            },
            "rag_off": {
                "description": "Disable RAG but keep the remaining pipeline",
                "environment": {"MALAPP_RAG_ENABLED": "0"},
            },
            "rag_vector": {
                "description": "Use vector retrieval without graph fusion",
                "environment": {"MALAPP_RAG_ENABLED": "1", "MALAPP_RAG_MODE": "vector"},
            },
            "rag_hybrid": {
                "description": "Use vector plus knowledge graph fusion",
                "environment": {"MALAPP_RAG_ENABLED": "1", "MALAPP_RAG_MODE": "hybrid"},
            },
            "fault_recovery": {
                "description": "Inject one transient failure into every domain agent",
                "sample_overrides": {
                    "agent_runtime_config": {
                        "agents": {
                            "static_analysis": {"max_restarts": 1},
                            "threat_intel": {"max_restarts": 1},
                            "impersonation": {"max_restarts": 1},
                            "business_label": {"max_restarts": 1},
                        }
                    },
                    "agent_runtime_faults": {
                        "static_analysis": {"failures": 1},
                        "threat_intel": {"failures": 1},
                        "impersonation": {"failures": 1},
                        "business_label": {"failures": 1},
                    },
                },
            },
        },
    }


def normalize_error_types(values: Any) -> list[str]:
    if isinstance(values, str):
        values = [item.strip() for item in values.split(",") if item.strip()]
    if not isinstance(values, list):
        return []
    normalized = []
    for value in values:
        key = _clean(value).lower()
        if key not in ERROR_TYPES:
            raise ValueError(f"unsupported error type: {key}")
        if key not in normalized:
            normalized.append(key)
    return normalized


def evaluation_overview(
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    scorecard = build_scorecard(validation_csv, data_dir)
    latest = _read_json(evaluation_dir(data_dir) / "manifests" / "latest.json", {})
    return {
        "plan": evaluation_plan(),
        "scorecard": scorecard,
        "latest_manifest": latest,
        "error_types": sorted(ERROR_TYPES),
    }
