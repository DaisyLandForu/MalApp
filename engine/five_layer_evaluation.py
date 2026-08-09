from __future__ import annotations

import hashlib
import csv
import json
import math
import os
import re
import sqlite3
import statistics
import threading
from collections import Counter, defaultdict
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from engine.evaluation_framework import (
    DEFAULT_VALIDATION_CSV,
    build_rag_retrieval_scorecard,
    build_scorecard,
    latest_human_review_index,
    latest_report_index,
    load_human_reviews,
    load_reports,
    load_validation_rows,
    sha256_file,
)
from runtime_data import resolve_data_dir


ROOT = Path(__file__).resolve().parents[1]
SUITE_VERSION = "five-layer-v1"
STRICT_RELEASE_EXTENSION_GLOB = "strict_untrained_release_*.csv"
LAYER_DEFINITIONS = {
    "layer1_model": {
        "name": "基础模型层",
        "decision": "在相同输入和输出协议下选择模型甲、模型乙或候选模型",
        "primary_metrics": [
            "verdict_accuracy",
            "malicious_recall",
            "benign_false_positive_rate",
            "macro_f1",
            "json_schema_success_rate",
            "calibration_ece",
            "latency_p95_ms",
        ],
    },
    "layer2_rag": {
        "name": "RAG与证据层",
        "decision": "选择无RAG、向量RAG或混合RAG，并控制错误引用",
        "primary_metrics": [
            "recall_at_5",
            "recall_at_10",
            "mrr",
            "ndcg_at_10",
            "context_precision",
            "evidence_faithfulness_rate",
            "retrieval_latency_p95_ms",
        ],
    },
    "layer3_agent": {
        "name": "Agent轨迹层",
        "decision": "判断四个领域Agent的结构、工具可靠性和边际贡献",
        "primary_metrics": [
            "trace_coverage",
            "agent_schema_success_rate",
            "agent_failure_rate",
            "agent_timeout_rate",
            "restart_recovery_rate",
            "marginal_recall_delta",
            "marginal_latency_delta_ms",
        ],
    },
    "layer4_e2e": {
        "name": "端到端研判层",
        "decision": "决定完整研判链是否达到发布质量门禁",
        "primary_metrics": [
            "coverage",
            "decided_accuracy",
            "malicious_recall",
            "benign_false_positive_rate",
            "macro_f1",
            "structure_success_rate",
            "latency_p95_ms",
        ],
    },
    "layer5_production": {
        "name": "生产运行层",
        "decision": "决定影子、灰度、全量或回退",
        "primary_metrics": [
            "success_rate",
            "failure_rate",
            "throughput_per_hour",
            "latency_p50_ms",
            "latency_p95_ms",
            "model_unavailable_rate",
            "agent_degraded_rate",
            "human_override_rate",
            "drift_psi",
        ],
    },
}
RELEASE_GATES = {
    "layer1_model": {
        "coverage_min": 1.0,
        "malicious_recall_min": 0.99,
        "benign_false_positive_rate_max": 0.01,
        "json_schema_success_rate_min": 0.995,
        "calibration_ece_max": 0.05,
    },
    "layer2_rag": {
        "approved_queries_min": 100,
        "recall_at_5_min": 0.90,
        "evidence_faithfulness_rate_min": 0.98,
        "hallucination_rate_max": 0.01,
        "graph_nodes_min": 1,
    },
    "layer3_agent": {
        "trace_coverage_min": 1.0,
        "agent_schema_success_rate_min": 0.995,
        "agent_failure_rate_max": 0.01,
        "agent_timeout_rate_max": 0.01,
        "restart_recovery_rate_min": 0.95,
        "required_ablation_variants": 5,
    },
    "layer4_e2e": {
        "coverage_min": 1.0,
        "decided_accuracy_min": 0.995,
        "malicious_recall_min": 0.995,
        "benign_false_positive_rate_max": 0.01,
        "structure_success_rate_min": 0.995,
        "latency_p95_ms_max": 120000,
    },
    "layer5_production": {
        "failure_rate_max": 0.02,
        "model_unavailable_rate_max": 0.01,
        "agent_degraded_rate_max": 0.02,
        "drift_psi_block": 0.25,
        "human_reviews_min": 100,
        "required_reliability_scenarios": 7,
    },
}

MODEL_INPUT_FIELDS = (
    "md5",
    "sample_id",
    "app_name",
    "package_name",
    "sha1",
    "sha256",
    "version_name",
    "file_size",
    "file_type",
    "signature_status",
    "certificate_fingerprint",
    "certificate_owner",
    "permissions",
    "plugins",
    "sdk_list",
    "packer",
    "code_fuscator",
    "unshell_info",
    "fake_app",
    "genuine",
    "official_app_name",
    "rebuild_type",
    "icon_md5",
    "virus_name",
    "virus_description",
    "fraud_flag",
    "fraud_type_info",
    "fraud_name",
    "fraud_category",
    "fraud_category_big",
    "fraud_category_small",
    "control_url",
    "download_url",
    "lt_urls",
    "dynamic_nets",
    "domains",
    "top_domains",
    "ips",
    "countries",
    "operators",
    "domain_count",
    "ip_count",
    "network_record_count",
    "engine_360_type",
    "engine_360_score",
    "engine_360_virus_name",
    "engine_cm_type",
    "engine_cm_score",
    "engine_cm_virus_name",
)
AGENT_NAMES = ("static_analysis", "threat_intel", "impersonation", "business_label")
VALID_LABELS = ("malicious", "suspicious", "benign")
MOJIBAKE_MARKERS = ("锟", "浣", "绔", "闈", "鍙", "鐨", "妯", "璇")
RAG_ANNOTATION_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def clean(value: Any) -> str:
    return str(value or "").strip()


def as_float(value: Any) -> float | None:
    try:
        result = float(value)
    except (TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def safe_div(numerator: float, denominator: float) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(ordered[lower], 3)
    result = ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)
    return round(result, 3)


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSONL at line {line_number}: {exc}") from exc
            if isinstance(row, dict):
                rows.append(row)
    return rows


def read_json(value: Any, default: Any = None) -> Any:
    if isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def readonly_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            (table,),
        ).fetchone()
        is not None
    )


def table_count(path: Path, table: str) -> int:
    if not path.exists():
        return 0
    conn = readonly_connection(path)
    try:
        if not table_exists(conn, table):
            return 0
        return int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
    finally:
        conn.close()


def database_inventory(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": path.exists(),
        "bytes": path.stat().st_size if path.exists() else 0,
        "tables": {},
    }
    if not path.exists():
        return result
    conn = readonly_connection(path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        for table in tables:
            columns = [
                row[1] for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()
            ]
            result["tables"][table] = {
                "rows": int(conn.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]),
                "columns": columns,
            }
    finally:
        conn.close()
    return result


def jsonl_profile(path: Path, *, inspect_limit: int = 1000) -> dict[str, Any]:
    profile = {
        "path": str(path),
        "exists": path.exists(),
        "bytes": path.stat().st_size if path.exists() else 0,
        "rows": 0,
        "invalid_json": 0,
        "inspected_text_rows": 0,
        "mojibake_rows": 0,
        "sample_ids": [],
    }
    if not path.exists():
        return profile
    sample_ids: list[str] = []
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            profile["rows"] += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                profile["invalid_json"] += 1
                continue
            if len(sample_ids) < 5 and isinstance(row, dict):
                metadata = row.get("metadata") or {}
                sample_id = clean(
                    row.get("md5")
                    or row.get("id")
                    or row.get("sample_id")
                    or metadata.get("md5")
                )
                if sample_id:
                    sample_ids.append(sample_id)
            if line_number <= inspect_limit:
                profile["inspected_text_rows"] += 1
                profile["mojibake_rows"] += int(
                    sum(line.count(marker) for marker in MOJIBAKE_MARKERS) >= 3
                )
    profile["sample_ids"] = sample_ids
    profile["invalid_json_rate"] = safe_div(profile["invalid_json"], profile["rows"])
    profile["mojibake_rate_in_inspected_rows"] = safe_div(
        profile["mojibake_rows"], profile["inspected_text_rows"]
    )
    return profile


def collect_training_ids() -> tuple[set[str], dict[str, int]]:
    paths = [ROOT / "data" / "datasets" / "train.jsonl"]
    paths.extend(sorted((ROOT / "training_artifacts" / "sft").glob("*/train.jsonl")))
    identifiers: set[str] = set()
    counts: dict[str, int] = {}
    for path in paths:
        if not path.exists():
            continue
        rows = 0
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                rows += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                metadata = row.get("metadata") or {}
                sample_id = clean(
                    row.get("md5")
                    or row.get("id")
                    or row.get("sample_id")
                    or metadata.get("md5")
                ).upper()
                if sample_id:
                    identifiers.add(sample_id)
        counts[str(path)] = rows

    database_sources = (
        (
            ROOT / "training_artifacts" / "training_dataset.db",
            "unified_samples",
            ("train",),
        ),
        (
            ROOT / "training_artifacts" / "training_dataset.db",
            "evidence_blocks",
            ("train",),
        ),
        (
            ROOT / "training_artifacts" / "xgb" / "xgb_training.db",
            "xgb_samples",
            ("train", "stack"),
        ),
        (
            ROOT
            / "training_artifacts"
            / "xgb_selected_20260616"
            / "xgb_training.db",
            "xgb_samples",
            ("train", "stack"),
        ),
    )
    for path, table, splits in database_sources:
        if not path.exists():
            continue
        conn = readonly_connection(path)
        try:
            if not table_exists(conn, table):
                continue
            placeholders = ",".join("?" for _ in splits)
            source_ids = {
                clean(value).upper()
                for (value,) in conn.execute(
                    f"SELECT DISTINCT md5 FROM [{table}] "
                    f"WHERE split IN ({placeholders}) AND md5 IS NOT NULL",
                    splits,
                )
                if clean(value)
            }
            identifiers.update(source_ids)
            key = f"{path}::{table}::{'+'.join(splits)}"
            counts[key] = len(source_ids)
        finally:
            conn.close()
    return identifiers, counts


def load_strict_release_extension(
    path: Path | None = None,
) -> list[dict[str, Any]]:
    paths = (
        [path]
        if path is not None
        else sorted(
            (ROOT / "training_artifacts").glob(STRICT_RELEASE_EXTENSION_GLOB)
        )
    )
    output: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}
    for source_path in paths:
        if not source_path.exists():
            continue
        for row in load_validation_rows(source_path):
            if clean(row.get("strict_untrained")).lower() not in {
                "1",
                "true",
                "yes",
            }:
                continue
            row["_strict_extension"] = True
            row["_label_tier"] = clean(row.get("label_quality")) or (
                "source_reference_requires_two_expert_reviews"
            )
            row["_strict_asset"] = source_path.name
            existing = by_id.get(row["_row_id"])
            if existing and existing.get("_gold_label") != row.get("_gold_label"):
                raise ValueError(
                    f"conflicting strict extension labels for {row['_row_id']}"
                )
            by_id.setdefault(row["_row_id"], row)
    output.extend(by_id.values())
    return output


def write_workflow_validation_csv(
    path: Path, rows: list[dict[str, Any]]
) -> int:
    public_rows = [
        {key: value for key, value in row.items() if not key.startswith("_")}
        for row in rows
    ]
    fields = sorted({key for row in public_rows for key in row})
    preferred = ["md5", "gold_label", "label_source"]
    fields = preferred + [field for field in fields if field not in preferred]
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(public_rows)
    return len(public_rows)


def validation_quality(rows: list[dict[str, Any]]) -> dict[str, Any]:
    identifiers = [row["_row_id"] for row in rows]
    id_counts = Counter(identifiers)
    required = ("md5", "gold_label", "label_source")
    missing = {
        field: sum(1 for row in rows if not clean(row.get(field))) for field in required
    }
    labels = Counter(row["_gold_label"] for row in rows)
    label_sources = Counter(clean(row.get("label_source")) or "unknown" for row in rows)
    malformed_md5 = sum(
        1 for row in rows if not re.fullmatch(r"[0-9A-F]{32}", row["_row_id"])
    )
    important_fields = (
        "app_name",
        "package_name",
        "virus_name",
        "signature_status",
        "permissions",
        "control_url",
        "download_url",
        "engine_360_score",
        "engine_cm_score",
        "xgb_probability",
    )
    completeness = {
        field: round(
            1 - sum(1 for row in rows if not clean(row.get(field))) / max(1, len(rows)),
            6,
        )
        for field in important_fields
    }
    return {
        "rows": len(rows),
        "unique_ids": len(id_counts),
        "duplicate_id_rows": sum(count - 1 for count in id_counts.values() if count > 1),
        "malformed_md5": malformed_md5,
        "missing_required": missing,
        "label_distribution": dict(labels),
        "label_source_distribution": dict(label_sources),
        "field_completeness": completeness,
        "grain": "one row per MD5",
    }


def source_inventory(
    *,
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    validation_csv = validation_csv.resolve()
    rows = load_validation_rows(validation_csv)
    reports = load_reports(data_dir)
    report_index = latest_report_index(reports)
    reviews = load_human_reviews(data_dir)
    training_ids, training_counts = collect_training_ids()
    validation_ids = {row["_row_id"] for row in rows}
    db_path = data_dir / "mvp.db"
    rag_path = data_dir / "rag" / "rag_store.db"
    if not rag_path.exists():
        rag_path = ROOT / "data" / "rag" / "rag_store.db"

    jsonl_paths = [
        ROOT / "data" / "datasets" / "train.jsonl",
        ROOT / "data" / "datasets" / "val.jsonl",
        ROOT / "data" / "datasets" / "test.jsonl",
        ROOT / "training_artifacts" / "frozen_evidence_blocks.jsonl",
        ROOT / "data" / "llm_validation_failures.jsonl",
    ]
    jsonl_paths.extend(sorted((ROOT / "training_artifacts" / "sft").glob("*/test.jsonl")))
    profiles = [jsonl_profile(path) for path in jsonl_paths]

    matched_reports = sum(1 for sample_id in validation_ids if sample_id in report_index)
    trace_count = table_count(db_path, "agent_traces")
    report_count = table_count(db_path, "judgements")
    rag_documents = table_count(rag_path, "rag_documents")
    graph_nodes = table_count(rag_path, "kg_nodes")
    graph_edges = table_count(rag_path, "kg_edges")
    app_label_distribution: dict[str, int] = {}
    manual_label_distribution: dict[str, int] = {}
    if db_path.exists():
        conn = readonly_connection(db_path)
        try:
            if table_exists(conn, "app_md5_labels"):
                app_label_distribution = {
                    clean(label) or "__missing__": int(count)
                    for label, count in conn.execute(
                        "SELECT label,COUNT(*) FROM app_md5_labels GROUP BY label "
                        "ORDER BY COUNT(*) DESC"
                    )
                }
            if table_exists(conn, "manual_labels"):
                manual_label_distribution = {
                    clean(label) or "__missing__": int(count)
                    for label, count in conn.execute(
                        "SELECT label,COUNT(*) FROM manual_labels GROUP BY label "
                        "ORDER BY COUNT(*) DESC"
                    )
                }
        finally:
            conn.close()
    issues: list[dict[str, Any]] = []
    quality = validation_quality(rows)
    if quality["duplicate_id_rows"]:
        issues.append(
            {
                "severity": "critical",
                "code": "validation_duplicate_ids",
                "count": quality["duplicate_id_rows"],
                "impact": "同一MD5会重复进入分母并污染准确率。",
            }
        )
    leakage = validation_ids.intersection(training_ids)
    if leakage:
        issues.append(
            {
                "severity": "high",
                "code": "train_eval_id_overlap",
                "count": len(leakage),
                "impact": "重叠样本不能用于冻结发布分数，生成器将单独标记。",
            }
        )
    mojibake_files = [
        profile
        for profile in profiles
        if (profile.get("mojibake_rate_in_inspected_rows") or 0) >= 0.05
    ]
    if mojibake_files:
        issues.append(
            {
                "severity": "high",
                "code": "legacy_jsonl_mojibake",
                "files": [profile["path"] for profile in mojibake_files],
                "impact": "旧JSONL只能用于结构鲁棒性测试，不能直接作为语义金标准。",
            }
        )
    if reviews:
        review_coverage = safe_div(len(reviews), matched_reports)
    else:
        review_coverage = 0.0
        issues.append(
            {
                "severity": "medium",
                "code": "human_review_coverage_low",
                "count": 0,
                "impact": "证据忠实度、幻觉和人工推翻率暂时没有可靠分母。",
            }
        )
    if rag_documents and not graph_nodes and not graph_edges:
        issues.append(
            {
                "severity": "high",
                "code": "rag_graph_index_empty",
                "count": rag_documents,
                "impact": "当前混合RAG没有可用知识图谱节点/边，不能声称已完成图谱增强对比。",
            }
        )
    return {
        "generated_at": now_iso(),
        "validation": {
            "path": str(validation_csv),
            "sha256": sha256_file(validation_csv),
            **quality,
        },
        "application_data": {
            "data_dir": str(data_dir),
            "database": database_inventory(db_path),
            "saved_report_rows": report_count,
            "unique_saved_reports": len(report_index),
            "validation_reports_matched": matched_reports,
            "agent_trace_rows": trace_count,
            "human_review_rows": len(reviews),
            "human_review_coverage": review_coverage,
            "app_label_distribution": app_label_distribution,
            "manual_label_distribution": manual_label_distribution,
        },
        "rag": {
            "database": database_inventory(rag_path),
            "document_rows": rag_documents,
            "graph_nodes": graph_nodes,
            "graph_edges": graph_edges,
        },
        "training": {
            "unique_training_ids": len(training_ids),
            "source_rows": training_counts,
            "validation_overlap_ids": len(leakage),
            "validation_overlap_examples": sorted(leakage)[:20],
        },
        "jsonl_profiles": profiles,
        "issues": issues,
        "usable_as_semantic_gold": str(validation_csv),
        "legacy_jsonl_policy": "structure_only_if_mojibake_rate_gte_0.05",
    }


def normalize_candidate_label(value: Any) -> str | None:
    text = clean(value).lower()
    if not text:
        return None
    if text in {"malicious", "恶意", "黑样本", "风险", "1", "true"}:
        return "malicious"
    if text in {"benign", "良性", "白样本", "正常", "0", "false"}:
        return "benign"
    if any(token in text for token in ("恶意", "黑样本", "病毒", "malicious")):
        return "malicious"
    if any(token in text for token in ("白样本", "良性", "benign", "normal")):
        return "benign"
    return None


def fresh_holdout_candidates(
    *,
    data_dir: Path,
    excluded_ids: set[str],
    size: int = 1000,
    salt: str,
) -> list[dict[str, Any]]:
    db_path = data_dir / "mvp.db"
    if not db_path.exists():
        return []
    conn = readonly_connection(db_path)
    try:
        if not table_exists(conn, "app_md5_labels"):
            return []
        candidates: dict[str, dict[str, Any]] = {}
        for (
            md5,
            source_sheet,
            label,
            app_name,
            fraud_type,
            fraud_subtype,
            raw_json,
        ) in conn.execute(
            "SELECT md5,source_sheet,label,app_name,fraud_type,fraud_subtype,raw_json "
            "FROM app_md5_labels"
        ):
            sample_id = clean(md5).upper()
            normalized_label = normalize_candidate_label(label)
            if (
                not re.fullmatch(r"[0-9A-F]{32}", sample_id)
                or sample_id in excluded_ids
                or normalized_label is None
            ):
                continue
            candidates.setdefault(
                sample_id,
                {
                    "id": sample_id,
                    "candidate_label": normalized_label,
                    "raw_label": label,
                    "source_sheet": source_sheet,
                    "app_name": app_name,
                    "fraud_type": fraud_type,
                    "fraud_subtype": fraud_subtype,
                    "raw": read_json(raw_json, {}),
                },
            )
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for candidate in candidates.values():
            grouped[candidate["candidate_label"]].append(candidate)
        for label in grouped:
            grouped[label].sort(
                key=lambda row: stable_hash(f"{salt}|{label}|{row['id']}")
            )
        selected: list[dict[str, Any]] = []
        target_each = max(1, size // 2)
        for label in ("malicious", "benign"):
            selected.extend(grouped[label][:target_each])
        if len(selected) < min(size, len(candidates)):
            selected_ids = {row["id"] for row in selected}
            remainder = sorted(
                (
                    row
                    for row in candidates.values()
                    if row["id"] not in selected_ids
                ),
                key=lambda row: stable_hash(f"{salt}|remainder|{row['id']}"),
            )
            selected.extend(remainder[: size - len(selected)])

        if table_exists(conn, "engine_detections") and selected:
            selected_by_id = {row["id"]: row for row in selected}
            sample_ids = list(selected_by_id)
            for start in range(0, len(sample_ids), 400):
                chunk = sample_ids[start : start + 400]
                placeholders = ",".join("?" for _ in chunk)
                query = (
                    "SELECT engine,md5,sha1,sha256,package_name,app_name,fake_app,"
                    "virus_name,detect_type,score,virus_description,description,"
                    "control_url,download_url,fraud_category_big,fraud_category_small,"
                    "fraud_family,official_pkg,official_app_name,sdk_list,cert_sha1,"
                    "cert_sha256,find_time FROM engine_detections "
                    f"WHERE md5 IN ({placeholders})"
                )
                columns = (
                    "engine",
                    "md5",
                    "sha1",
                    "sha256",
                    "package_name",
                    "app_name",
                    "fake_app",
                    "virus_name",
                    "detect_type",
                    "score",
                    "virus_description",
                    "description",
                    "control_url",
                    "download_url",
                    "fraud_category_big",
                    "fraud_category_small",
                    "fraud_family",
                    "official_pkg",
                    "official_app_name",
                    "sdk_list",
                    "cert_sha1",
                    "cert_sha256",
                    "find_time",
                )
                for values in conn.execute(query, chunk):
                    detection = dict(zip(columns, values))
                    sample_id = clean(detection.pop("md5")).upper()
                    selected_by_id[sample_id].setdefault("engine_records", []).append(
                        detection
                    )
    finally:
        conn.close()

    output = []
    for candidate in selected[:size]:
        output.append(
            {
                **candidate,
                "layer_usage": [
                    "layer1_model",
                    "layer2_rag",
                    "layer3_agent",
                    "layer4_e2e",
                ],
                "annotation_status": "needs_two_expert_reviews_and_adjudication",
                "gold_label": None,
                "training_overlap": False,
                "existing_validation_overlap": False,
                "selection_method": "balanced_from_app_md5_labels_excluding_all_known_train_and_validation_ids",
            }
        )
    return output


def build_structured_rag_corpus(
    *,
    data_dir: Path | None = None,
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    suite_dir: Path | None = None,
    size: int = 2000,
    rag_db_path: Path | None = None,
    reserved_fresh_size: int = 1000,
) -> dict[str, Any]:
    """Build a leakage-safe operational KG+vector corpus from existing records.

    Gold labels, saved model decisions, probabilities and manual-review outcomes
    are deliberately excluded.  All frozen validation IDs and the latest fresh
    expert-holdout candidates are also excluded, so retrieval cannot answer an
    evaluation item by looking up its previously saved outcome.
    """
    from engine.rag.store import (
        add_document,
        init_rag_db,
        rag_status,
        rebuild_graph_index,
    )

    data_dir = (data_dir or resolve_data_dir()).resolve()
    validation_csv = validation_csv.resolve()
    rag_db_path = (
        rag_db_path.resolve()
        if rag_db_path
        else data_dir / "rag" / "rag_store.db"
    )
    validation_rows = load_validation_rows(validation_csv)
    validation_ids = {
        clean(row.get("_row_id")).upper() for row in validation_rows
    }
    excluded_ids = set(validation_ids)
    training_ids, _ = collect_training_ids()
    canonical_fresh = (
        fresh_holdout_candidates(
            data_dir=data_dir,
            excluded_ids=training_ids.union(validation_ids),
            size=max(1, int(reserved_fresh_size)),
            salt=f"fresh-holdout-v1|{sha256_file(validation_csv)}",
        )
        if int(reserved_fresh_size) > 0
        else []
    )
    canonical_fresh_ids = {
        clean(row.get("id")).upper()
        for row in canonical_fresh
        if clean(row.get("id"))
    }
    excluded_ids.update(canonical_fresh_ids)

    if suite_dir is None:
        latest = latest_suite(data_dir=data_dir)
        latest_path = clean(latest.get("suite_dir"))
        if latest_path:
            candidate = Path(latest_path)
            if candidate.exists():
                suite_dir = candidate
    fresh_candidate_file = (
        suite_dir / "fresh_expert_holdout_candidates.jsonl"
        if suite_dir
        else None
    )
    fresh_candidate_ids: set[str] = set()
    if fresh_candidate_file and fresh_candidate_file.exists():
        fresh_candidate_ids = {
            clean(row.get("id")).upper()
            for row in read_jsonl(fresh_candidate_file)
            if clean(row.get("id"))
        }
        excluded_ids.update(fresh_candidate_ids)

    # Older suites used a suite-specific selection salt, so a later fresh
    # holdout could overlap documents already inserted by an earlier build.
    # Prune every structured document that is now reserved for evaluation and
    # rebuild the graph so no orphan sample node or edge can retain that ID.
    init_rag_db(rag_db_path)
    pruned_documents = 0
    with closing(sqlite3.connect(rag_db_path)) as conn:
        rows = conn.execute(
            """
            SELECT doc_id,metadata_json
            FROM rag_documents
            WHERE source_type='malapp_structured_sample'
            """
        ).fetchall()
        stale_doc_ids = []
        for doc_id, metadata_json in rows:
            metadata = read_json(metadata_json, {})
            sample_id = clean(metadata.get("md5")).upper()
            if sample_id and sample_id in excluded_ids:
                stale_doc_ids.append(doc_id)
        if stale_doc_ids:
            placeholders = ",".join("?" for _ in stale_doc_ids)
            conn.execute(
                f"DELETE FROM rag_documents WHERE doc_id IN ({placeholders})",
                stale_doc_ids,
            )
            for table in (
                "kg_edges",
                "kg_document_links",
                "kg_index_state",
                "kg_nodes",
            ):
                conn.execute(f"DELETE FROM {table}")
            conn.commit()
            pruned_documents = len(stale_doc_ids)

    requested = max(1, min(int(size), 10000))
    candidates = fresh_holdout_candidates(
        data_dir=data_dir,
        excluded_ids=excluded_ids,
        size=requested,
        salt=f"structured-rag-v1|{sha256_file(validation_csv)}",
    )

    def first_value(
        candidate: dict[str, Any],
        *keys: str,
    ) -> Any:
        sources: list[dict[str, Any]] = [candidate]
        raw = candidate.get("raw")
        if isinstance(raw, dict):
            sources.append(raw)
        sources.extend(
            item
            for item in candidate.get("engine_records") or []
            if isinstance(item, dict)
        )
        for source in sources:
            for key in keys:
                value = source.get(key)
                if value not in (None, "", [], {}):
                    return value
        return None

    def all_values(candidate: dict[str, Any], *keys: str) -> list[str]:
        values: list[str] = []
        sources: list[dict[str, Any]] = []
        raw = candidate.get("raw")
        if isinstance(raw, dict):
            sources.append(raw)
        sources.extend(
            item
            for item in candidate.get("engine_records") or []
            if isinstance(item, dict)
        )
        for source in sources:
            for key in keys:
                value = source.get(key)
                if isinstance(value, (list, tuple, set)):
                    values.extend(clean(item) for item in value if clean(item))
                elif clean(value):
                    values.extend(
                        item.strip()
                        for item in re.split(r"[,;|\n]+", clean(value))
                        if item.strip()
                    )
        return list(dict.fromkeys(values))[:20]

    added = 0
    skipped_without_entities = 0
    for candidate in candidates:
        sample_id = clean(candidate.get("id")).upper()
        metadata: dict[str, Any] = {
            "md5": sample_id,
            "source_sheet": clean(candidate.get("source_sheet")),
            "corpus_policy": "no_gold_label_no_saved_model_output",
        }
        scalar_fields = {
            "sha1": ("sha1",),
            "sha256": ("sha256",),
            "app_name": ("app_name", "official_app_name"),
            "official_app_name": ("official_app_name",),
            "package_name": ("package_name", "package", "pkg"),
            "official_pkg": ("official_pkg",),
            "fake_app": ("fake_app",),
            "virus_name": ("virus_name",),
            "fraud_family": ("fraud_family",),
            "fraud_category_big": ("fraud_category_big",),
            "fraud_category_small": ("fraud_category_small",),
            "control_url": ("control_url",),
            "download_url": ("download_url",),
            "certificate_fingerprint": (
                "certificate_fingerprint",
                "cert_sha1",
                "cert_sha256",
            ),
        }
        for output_key, input_keys in scalar_fields.items():
            value = first_value(candidate, *input_keys)
            if value not in (None, "", [], {}):
                metadata[output_key] = value
        for output_key, input_keys in {
            "domains": ("domains", "domain", "top_domains"),
            "ips": ("ips", "ip"),
            "sdk_list": ("sdk_list", "sdks"),
        }.items():
            value = all_values(candidate, *input_keys)
            if value:
                metadata[output_key] = value

        # A sample identifier alone is not useful operational knowledge. Require
        # at least one non-provenance entity before adding the document.
        useful_keys = set(metadata) - {"md5", "source_sheet", "corpus_policy"}
        if not useful_keys:
            skipped_without_entities += 1
            continue
        content_parts = []
        for key in (
            "md5",
            "sha1",
            "sha256",
            "app_name",
            "official_app_name",
            "package_name",
            "official_pkg",
            "fake_app",
            "virus_name",
            "fraud_family",
            "fraud_category_big",
            "fraud_category_small",
            "control_url",
            "download_url",
            "certificate_fingerprint",
            "domains",
            "ips",
            "sdk_list",
        ):
            value = metadata.get(key)
            if value not in (None, "", [], {}):
                rendered = ",".join(map(str, value)) if isinstance(value, list) else str(value)
                content_parts.append(f"{key}={rendered}")
        add_document(
            doc_id=f"malapp-structured:{sample_id}",
            source_type="malapp_structured_sample",
            source_name="app_md5_labels+engine_detections",
            title=f"MalApp结构化样本 {metadata.get('app_name') or sample_id}",
            content=";\n".join(content_parts),
            metadata=metadata,
            path=rag_db_path,
        )
        added += 1

    status = rag_status(rag_db_path)
    return {
        "generated_at": now_iso(),
        "status": "ready" if added and (status.get("graph") or {}).get("ready") else "partial",
        "rag_database": str(rag_db_path),
        "requested_documents": requested,
        "candidate_documents": len(candidates),
        "documents_added_or_updated": added,
        "documents_pruned_for_evaluation_isolation": pruned_documents,
        "skipped_without_entities": skipped_without_entities,
        "excluded_validation_ids": len(validation_ids),
        "excluded_canonical_fresh_candidate_ids": len(canonical_fresh_ids),
        "excluded_fresh_candidate_ids": len(fresh_candidate_ids),
        "leakage_policy": {
            "excluded_fields": [
                "gold_label",
                "candidate_label",
                "raw_label",
                "saved_model_verdict",
                "xgb_probability",
                "manual_review_result",
            ],
            "excluded_id_sets": [
                "frozen_validation_set",
                "fresh_expert_holdout_candidates",
            ],
        },
        "graph_rebuild": (
            rebuild_graph_index(rag_db_path) if pruned_documents else None
        ),
        "rag_status": rag_status(rag_db_path),
    }


def balanced_rows(
    rows: list[dict[str, Any]],
    size: int,
    *,
    excluded_ids: set[str] | None = None,
    salt: str,
) -> list[dict[str, Any]]:
    excluded_ids = excluded_ids or set()
    available = [row for row in rows if row["_row_id"] not in excluded_ids]
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in available:
        groups[row["_gold_label"]].append(row)
    for label in groups:
        groups[label].sort(key=lambda row: stable_hash(f"{salt}|{row['_row_id']}"))
    labels = [label for label in ("malicious", "benign") if groups[label]]
    selected: list[dict[str, Any]] = []
    while len(selected) < min(size, len(available)) and labels:
        progressed = False
        for label in labels:
            if groups[label] and len(selected) < size:
                selected.append(groups[label].pop(0))
                progressed = True
        if not progressed:
            break
    if len(selected) < min(size, len(available)):
        selected_ids = {row["_row_id"] for row in selected}
        remainder = sorted(
            (row for row in available if row["_row_id"] not in selected_ids),
            key=lambda row: stable_hash(f"{salt}|remainder|{row['_row_id']}"),
        )
        selected.extend(remainder[: size - len(selected)])
    return selected


def challenge_score(row: dict[str, Any], report: dict[str, Any] | None) -> tuple[int, str]:
    score = 0
    reasons: list[str] = []
    probability = as_float(row.get("xgb_probability"))
    if probability is not None and 0.3 <= probability <= 0.7:
        score += 5
        reasons.append("xgb_boundary")
    score_360 = as_float(row.get("engine_360_score"))
    score_cm = as_float(row.get("engine_cm_score"))
    if score_360 is not None and score_cm is not None and abs(score_360 - score_cm) >= 60:
        score += 5
        reasons.append("engine_conflict")
    if "conflict" in clean(row.get("label_source")).lower() or clean(row.get("conflict_type")):
        score += 4
        reasons.append("manual_conflict")
    missing = sum(
        1
        for field in (
            "signature_status",
            "permissions",
            "control_url",
            "download_url",
            "virus_name",
        )
        if not clean(row.get(field))
    )
    if missing >= 3:
        score += 2
        reasons.append("sparse_features")
    if report:
        verdict = clean((report.get("decision") or {}).get("verdict")).lower()
        if verdict and verdict != row["_gold_label"]:
            score += 8
            reasons.append("historical_error")
        debate = report.get("debate") or {}
        providers = debate.get("providers") or {}
        if any(
            clean(value.get("status")).lower() in {"unavailable", "failed", "timeout"}
            for value in providers.values()
            if isinstance(value, dict)
        ):
            score += 6
            reasons.append("model_runtime_issue")
        runtime_agents = (
            ((report.get("preprocess") or {}).get("agent_runtime") or {}).get("agents") or {}
        )
        if any(
            clean(value.get("status")).lower() in {"degraded", "failed", "timeout"}
            for value in runtime_agents.values()
            if isinstance(value, dict)
        ):
            score += 6
            reasons.append("agent_runtime_issue")
    return score, ",".join(reasons) or "stable_hash_sample"


def model_input(row: dict[str, Any]) -> dict[str, Any]:
    return {
        field: row.get(field)
        for field in MODEL_INPUT_FIELDS
        if row.get(field) not in ("", None)
    }


def report_latency_ms(report: dict[str, Any]) -> float | None:
    debate = report.get("debate") or {}
    metrics = debate.get("metrics") or {}
    value = as_float(metrics.get("latency_ms"))
    if value is not None:
        return value
    execution = report.get("execution") or {}
    return as_float(execution.get("latency_ms") or report.get("latency_ms"))


def report_summary(report: dict[str, Any] | None) -> dict[str, Any] | None:
    if not report:
        return None
    debate = report.get("debate") or {}
    return {
        "report_id": report.get("report_id"),
        "created_at": report.get("created_at"),
        "decision": report.get("decision"),
        "model_a": debate.get("model_a"),
        "model_b": debate.get("model_b"),
        "arbiter": debate.get("arbiter"),
        "providers": debate.get("providers"),
        "execution_mode": debate.get("execution_mode"),
        "debate_rounds": debate.get("debate_rounds"),
        "latency_ms": report_latency_ms(report),
        "runtime_snapshot": report.get("runtime_snapshot"),
    }


def agent_blocks(report: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not report:
        return []
    blocks = report.get("evidence_blocks") or []
    return [block for block in blocks if isinstance(block, dict)]


def agent_runtime(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report:
        return {}
    return (
        ((report.get("preprocess") or {}).get("agent_runtime") or {}).get("agents") or {}
    )


def rag_context(report: dict[str, Any] | None) -> dict[str, Any]:
    if not report:
        return {}
    return ((report.get("evidence_layers") or {}).get("rag_context") or {})


def load_rag_documents(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    conn = readonly_connection(path)
    try:
        if not table_exists(conn, "rag_documents"):
            return {}
        rows = conn.execute(
            "SELECT doc_id,source_type,source_name,title,content,metadata_json,updated_at "
            "FROM rag_documents"
        ).fetchall()
    finally:
        conn.close()
    result = {}
    for row in rows:
        result[row[0]] = {
            "doc_id": row[0],
            "source_type": row[1],
            "source_name": row[2],
            "title": row[3],
            "content": row[4],
            "metadata": read_json(row[5], {}),
            "updated_at": row[6],
        }
    return result


def weak_relevance(
    row: dict[str, Any],
    retrieved_ids: list[str],
    documents: dict[str, dict[str, Any]],
) -> tuple[list[str], list[str]]:
    exact_tokens = {
        clean(row.get("md5")).lower(),
        clean(row.get("package_name")).lower(),
        clean(row.get("sha1")).lower(),
        clean(row.get("sha256")).lower(),
    }
    semantic_tokens = {
        clean(row.get("app_name")).lower(),
        clean(row.get("virus_name")).lower(),
        clean(row.get("fraud_name")).lower(),
        clean(row.get("fraud_category_big")).lower(),
        clean(row.get("fraud_category_small")).lower(),
    }
    exact_tokens.discard("")
    semantic_tokens.discard("")
    relevant: list[str] = []
    hard_negative: list[str] = []
    for doc_id in retrieved_ids:
        document = documents.get(doc_id) or {}
        haystack = " ".join(
            (
                clean(document.get("title")),
                clean(document.get("content")),
                json.dumps(document.get("metadata") or {}, ensure_ascii=False),
            )
        ).lower()
        if any(token in haystack for token in exact_tokens):
            relevant.append(doc_id)
        elif any(len(token) >= 3 and token in haystack for token in semantic_tokens):
            relevant.append(doc_id)
        else:
            hard_negative.append(doc_id)
    return relevant, hard_negative


def model_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for model_key in ("model_a", "model_b"):
        correct = total = malicious_total = malicious_correct = benign_total = false_positive = 0
        available = 0
        review_outputs = 0
        latencies: list[float] = []
        for row in validation_rows:
            report = reports.get(row["_row_id"])
            if not report:
                continue
            debate = report.get("debate") or {}
            output = debate.get(model_key) or {}
            verdict = clean(output.get("verdict")).lower()
            if verdict not in VALID_LABELS:
                continue
            available += 1
            gold = row["_gold_label"]
            review_outputs += int(verdict == "suspicious")
            if verdict != "suspicious":
                total += 1
                correct += int(verdict == gold)
            if gold == "malicious":
                malicious_total += 1
                malicious_correct += int(verdict == "malicious")
            elif gold == "benign":
                benign_total += 1
                false_positive += int(verdict == "malicious")
            latency = as_float(output.get("latency_ms"))
            if latency is not None:
                latencies.append(latency)
        result[model_key] = {
            "available_outputs": available,
            "review_outputs": review_outputs,
            "review_rate": safe_div(review_outputs, available),
            "decided_accuracy": safe_div(correct, total),
            "malicious_recall": safe_div(malicious_correct, malicious_total),
            "benign_false_positive_rate": safe_div(false_positive, benign_total),
            "latency_p95_ms": percentile(latencies, 0.95),
            "note": "基于历史报告中保存的模型单方输出；新模型必须在同一冻结输入上重新运行。",
        }
    return result


def official_gold_row(row: dict[str, Any]) -> bool:
    """Return whether a row may contribute to release-quality metrics."""
    tier = clean(row.get("_label_tier") or row.get("label_tier")).lower()
    status = clean(row.get("annotation_status")).lower()
    intended_use = clean(row.get("intended_use")).lower()
    if tier in {
        "frozen_validation_gold",
        "expert_approved_gold",
        "expert_adjudicated_gold",
    }:
        return True
    if status in {"gold_from_frozen_validation", "approved", "adjudicated"}:
        return True
    if intended_use == "release_gate" and "source_reference" not in tier:
        return True
    return not bool(row.get("_strict_extension")) and not tier and not status


def segmented_model_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    official_rows = [row for row in validation_rows if official_gold_row(row)]
    provisional_rows = [row for row in validation_rows if not official_gold_row(row)]
    official = model_baseline(official_rows, reports)
    provisional = model_baseline(provisional_rows, reports)
    combined = model_baseline(validation_rows, reports)
    # Backward-compatible top-level model_a/model_b now deliberately mean
    # official expert gold only.  Source-reference agreement is explicit.
    return {
        **official,
        "official_gold": {
            "dataset_total": len(official_rows),
            **official,
        },
        "provisional_source_reference": {
            "dataset_total": len(provisional_rows),
            **provisional,
        },
        "combined_diagnostic": {
            "dataset_total": len(validation_rows),
            **combined,
        },
        "metric_policy": (
            "发布准确率仅统计冻结、已批准或已仲裁专家金标；"
            "未复核来源标签只报告一致率。"
        ),
    }


def rag_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
    reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    enabled = nonempty = 0
    document_counts: list[int] = []
    for row in validation_rows:
        context = rag_context(reports.get(row["_row_id"]))
        if not context:
            continue
        if context.get("enabled"):
            enabled += 1
            items = context.get("items") or []
            nonempty += int(bool(items))
            document_counts.append(len(items))
    evidence_values = [
        review.get("evidence_supported")
        for review in reviews
        if isinstance(review.get("evidence_supported"), bool)
    ]
    hallucination_values = [
        review.get("hallucination")
        for review in reviews
        if isinstance(review.get("hallucination"), bool)
    ]
    return {
        "rag_enabled_reports": enabled,
        "nonempty_retrieval_rate": safe_div(nonempty, enabled),
        "average_retrieved_documents": (
            round(statistics.fmean(document_counts), 6) if document_counts else None
        ),
        "evidence_review_count": len(evidence_values),
        "evidence_faithfulness_rate": safe_div(sum(evidence_values), len(evidence_values)),
        "hallucination_rate": safe_div(
            sum(hallucination_values), len(hallucination_values)
        ),
        "retrieval_gold_status": (
            "requires_expert_annotation"
            if not evidence_values
            else "partial_human_annotation"
        ),
    }


def valid_agent_block(block: dict[str, Any]) -> bool:
    agent = clean(block.get("agent"))
    score = as_float(block.get("score") if "score" in block else block.get("risk_score"))
    evidence = block.get("evidence")
    if evidence is None:
        evidence = block.get("evidence_items")
    return bool(agent in AGENT_NAMES and score is not None and isinstance(evidence, list))


def agent_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    report_count = block_count = valid_blocks = 0
    runtime_count = failures = timeouts = restarts = recovered = 0
    by_agent: dict[str, Counter[str]] = {name: Counter() for name in AGENT_NAMES}
    for row in validation_rows:
        report = reports.get(row["_row_id"])
        if not report:
            continue
        report_count += 1
        for block in agent_blocks(report):
            block_count += 1
            valid = valid_agent_block(block)
            valid_blocks += int(valid)
            name = clean(block.get("agent"))
            if name in by_agent:
                by_agent[name]["blocks"] += 1
                by_agent[name]["valid"] += int(valid)
        for name, status_data in agent_runtime(report).items():
            if not isinstance(status_data, dict):
                continue
            runtime_count += 1
            status = clean(status_data.get("status")).lower()
            restart_count = int(as_float(status_data.get("restart_count")) or 0)
            failures += int(status in {"failed", "degraded", "timeout"})
            timeouts += int(status == "timeout")
            restarts += int(restart_count > 0)
            recovered += int(
                restart_count > 0 and status in {"completed", "success", "healthy"}
            )
            if name in by_agent:
                by_agent[name][status or "unknown"] += 1
    return {
        "reports_with_saved_output": report_count,
        "trace_coverage": safe_div(report_count, len(validation_rows)),
        "agent_blocks": block_count,
        "agent_schema_success_rate": safe_div(valid_blocks, block_count),
        "agent_failure_rate": safe_div(failures, runtime_count),
        "agent_timeout_rate": safe_div(timeouts, runtime_count),
        "restart_recovery_rate": safe_div(recovered, restarts),
        "per_agent": {name: dict(counts) for name, counts in by_agent.items()},
        "marginal_contribution_status": "requires_leave_one_agent_out_runs",
    }


def production_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
    data_dir: Path,
    reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    latencies: list[float] = []
    dates: Counter[str] = Counter()
    model_unavailable = agent_degraded = 0
    for report in reports.values():
        latency = report_latency_ms(report)
        if latency is not None:
            latencies.append(latency)
        created = clean(report.get("created_at"))
        if created:
            dates[created[:10]] += 1
        providers = (report.get("debate") or {}).get("providers") or {}
        model_unavailable += int(
            any(
                clean(value.get("status")).lower()
                in {"unavailable", "failed", "timeout", "model_unavailable"}
                for value in providers.values()
                if isinstance(value, dict)
            )
        )
        agent_degraded += int(
            any(
                clean(value.get("status")).lower() in {"degraded", "failed", "timeout"}
                for value in agent_runtime(report).values()
                if isinstance(value, dict)
            )
        )
    review_correctness = [
        review.get("is_correct")
        for review in reviews
        if isinstance(review.get("is_correct"), bool)
    ]
    db_path = data_dir / "mvp.db"
    batch_jobs: dict[str, int] = {}
    if db_path.exists():
        conn = readonly_connection(db_path)
        try:
            if table_exists(conn, "batch_jobs"):
                batch_jobs = {
                    clean(status) or "unknown": int(count)
                    for status, count in conn.execute(
                        "SELECT status,COUNT(*) FROM batch_jobs GROUP BY status"
                    )
                }
        finally:
            conn.close()
    completed_days = len(dates)
    throughput_per_day = safe_div(sum(dates.values()), completed_days)
    return {
        "saved_reports": len(reports),
        "validation_coverage": safe_div(len(reports), len(validation_rows)),
        "latency_ms": {
            "count": len(latencies),
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "p99": percentile(latencies, 0.99),
        },
        "average_saved_reports_per_active_day": throughput_per_day,
        "active_days": completed_days,
        "model_unavailable_report_rate": safe_div(model_unavailable, len(reports)),
        "agent_degraded_report_rate": safe_div(agent_degraded, len(reports)),
        "human_review_count": len(review_correctness),
        "human_override_rate": safe_div(
            sum(1 for value in review_correctness if not value),
            len(review_correctness),
        ),
        "batch_job_status": batch_jobs,
        "throughput_per_hour_status": "requires_worker_active_time_windows",
    }


def end_to_end_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    correct = incorrect = review = tp = fn = fp = tn = 0
    malicious_total = benign_total = 0
    latencies: list[float] = []
    evaluated = 0
    for row in validation_rows:
        report = reports.get(row["_row_id"])
        verdict = clean(((report or {}).get("decision") or {}).get("verdict")).lower()
        if verdict not in VALID_LABELS:
            continue
        evaluated += 1
        gold = row["_gold_label"]
        malicious_total += int(gold == "malicious")
        benign_total += int(gold == "benign")
        if verdict == "suspicious":
            review += 1
        elif verdict == gold:
            correct += 1
        else:
            incorrect += 1
        tp += int(gold == "malicious" and verdict == "malicious")
        fn += int(gold == "malicious" and verdict == "benign")
        fp += int(gold == "benign" and verdict == "malicious")
        tn += int(gold == "benign" and verdict == "benign")
        latency = report_latency_ms(report or {})
        if latency is not None:
            latencies.append(latency)
    decided = correct + incorrect
    malicious_precision = safe_div(tp, tp + fp)
    malicious_recall = safe_div(tp, malicious_total)
    benign_precision = safe_div(tn, tn + fn)
    benign_recall = safe_div(tn, tn + fp)
    malicious_f1 = (
        2 * malicious_precision * malicious_recall
        / (malicious_precision + malicious_recall)
        if malicious_precision is not None
        and malicious_recall is not None
        and malicious_precision + malicious_recall
        else None
    )
    benign_f1 = (
        2 * benign_precision * benign_recall / (benign_precision + benign_recall)
        if benign_precision is not None
        and benign_recall is not None
        and benign_precision + benign_recall
        else None
    )
    return {
        "dataset_total": len(validation_rows),
        "evaluated_total": evaluated,
        "pending_total": len(validation_rows) - evaluated,
        "coverage": safe_div(evaluated, len(validation_rows)),
        "correct": correct,
        "incorrect": incorrect,
        "review": review,
        "decided_accuracy": safe_div(correct, decided),
        "malicious_recall": malicious_recall,
        "benign_false_positive_rate": safe_div(fp, benign_total),
        "macro_f1": (
            round((malicious_f1 + benign_f1) / 2, 6)
            if malicious_f1 is not None and benign_f1 is not None
            else None
        ),
        "latency_ms": {
            "count": len(latencies),
            "p50": percentile(latencies, 0.5),
            "p95": percentile(latencies, 0.95),
        },
    }


def segmented_end_to_end_baseline(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    official_rows = [row for row in validation_rows if official_gold_row(row)]
    provisional_rows = [row for row in validation_rows if not official_gold_row(row)]
    official = end_to_end_baseline(official_rows, reports)
    return {
        **official,
        "official_gold": official,
        "provisional_source_reference": end_to_end_baseline(
            provisional_rows, reports
        ),
        "combined_diagnostic": end_to_end_baseline(validation_rows, reports),
        "metric_policy": (
            "端到端发布门禁只使用专家金标；来源参考样本不进入正式准确率。"
        ),
    }


def feature_distribution(rows: list[dict[str, Any]], field: str) -> dict[str, Any]:
    counts = Counter(clean(row.get(field)) or "__missing__" for row in rows)
    total = sum(counts.values())
    return {
        "field": field,
        "total": total,
        "values": {
            key: {"count": count, "rate": safe_div(count, total)}
            for key, count in counts.most_common(50)
        },
    }


def build_data_quality_report(inventory: dict[str, Any]) -> dict[str, Any]:
    issue_counts = Counter(issue["severity"] for issue in inventory["issues"])
    release_safe = not any(
        issue["severity"] in {"critical", "high"} for issue in inventory["issues"]
    )
    return {
        "generated_at": now_iso(),
        "release_safe_without_exclusions": release_safe,
        "severity_counts": dict(issue_counts),
        "findings": inventory["issues"],
        "automated_checks": [
            "validation_md5_unique",
            "validation_gold_label_not_null",
            "validation_label_allowed",
            "training_validation_id_disjoint",
            "jsonl_valid_json",
            "legacy_text_mojibake_rate",
            "report_validation_join_coverage",
            "trace_report_join_coverage",
            "rag_document_embedding_presence",
            "human_review_coverage",
        ],
        "policy": {
            "semantic_gold": "仅使用编码正常的冻结验证CSV和已仲裁人工标签。",
            "legacy_mojibake_jsonl": "仅用于JSON结构、修复和鲁棒性挑战，不计语义准确率。",
            "weak_rag_relevance": "仅作为预标注，专家批准前不计Recall@K。",
            "training_overlap": "重叠ID保留审计记录，但不进入冻结发布分数。",
        },
    }


def generate_five_layer_suite(
    *,
    name: str = "v1",
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
    output_root: Path | None = None,
    model_size: int = 500,
    rag_size: int = 200,
    agent_size: int = 500,
    challenge_size: int = 300,
    fresh_candidate_size: int = 1000,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    validation_csv = validation_csv.resolve()
    rows = load_validation_rows(validation_csv)
    strict_extension_rows = load_strict_release_extension()
    # A reviewed expansion is stored outside an individual five-layer suite.
    # Overlay only frozen, versioned expert labels here; source-reference labels
    # remain provisional and never become release gold implicitly.
    from engine.gold_expansion import load_frozen_gold_index

    frozen_expansion = load_frozen_gold_index(data_dir)
    for row in strict_extension_rows:
        frozen = frozen_expansion.get(row["_row_id"])
        if not frozen:
            continue
        final_label = clean((frozen.get("expected") or {}).get("verdict")).lower()
        if final_label not in {"malicious", "benign"}:
            continue
        row["gold_label"] = final_label
        row["_gold_label"] = final_label
        row["label_source"] = clean(
            (frozen.get("expected") or {}).get("label_source")
        ) or "two_expert_review_with_adjudication_policy"
        row["annotation_status"] = clean(frozen.get("annotation_status")) or "approved"
        row["label_tier"] = clean(frozen.get("label_tier")) or "expert_approved_gold"
        row["_label_tier"] = row["label_tier"]
        row["_gold_expansion"] = True
    reports_list = load_reports(data_dir)
    reports = latest_report_index(reports_list)
    reviews = load_human_reviews(data_dir)
    reviews_by_report, reviews_by_sample = latest_human_review_index(reviews)
    inventory = source_inventory(validation_csv=validation_csv, data_dir=data_dir)
    training_ids, _ = collect_training_ids()
    frozen_release_rows = [
        row
        for row in rows
        if row["_row_id"] not in training_ids
        and re.fullmatch(r"[0-9A-F]{32}", row["_row_id"])
    ]
    original_ids = {row["_row_id"] for row in rows}
    strict_extension_rows = [
        row
        for row in strict_extension_rows
        if row["_row_id"] not in training_ids
        and row["_row_id"] not in original_ids
        and re.fullmatch(r"[0-9A-F]{32}", row["_row_id"])
    ]
    release_rows = frozen_release_rows + strict_extension_rows
    valid_rows = [
        row for row in rows if re.fullmatch(r"[0-9A-F]{32}", row["_row_id"])
    ]

    suite_id = (
        f"{clean(name) or 'v1'}-{datetime.now().strftime('%Y%m%d_%H%M%S')}-"
        f"{stable_hash(sha256_file(validation_csv))[:8]}"
    )
    output_root = (
        output_root.resolve()
        if output_root
        else data_dir / "evaluation" / "five_layer"
    )
    suite_dir = output_root / suite_id
    suite_dir.mkdir(parents=True, exist_ok=False)
    workflow_validation_csv = suite_dir / "strict_release_validation.csv"
    workflow_validation_count = write_workflow_validation_csv(
        workflow_validation_csv,
        rows + strict_extension_rows,
    )

    model_release_rows = balanced_rows(
        release_rows,
        len(release_rows),
        salt=f"{suite_id}|model-release",
    )
    model_diagnostic_rows = balanced_rows(
        valid_rows,
        model_size,
        salt=f"{suite_id}|model-diagnostic",
    )
    model_ids = {row["_row_id"] for row in model_release_rows}
    ranked_challenges = sorted(
        (row for row in valid_rows if row["_row_id"] not in model_ids),
        key=lambda row: (
            challenge_score(row, reports.get(row["_row_id"]))[0],
            stable_hash(f"{suite_id}|challenge|{row['_row_id']}"),
        ),
        reverse=True,
    )
    challenge_rows = ranked_challenges[: min(challenge_size, len(ranked_challenges))]
    challenge_ids = {row["_row_id"] for row in challenge_rows}

    layer1_dir = suite_dir / "layer1_model"
    model_release_records = []
    for row in model_release_rows:
        model_release_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer1_model",
                "track": "single_model_feature_only",
                "input": model_input(row),
                "expected": {
                    "verdict": row["_gold_label"],
                    "label_source": row.get("label_source"),
                    "output_schema": {
                        "required": [
                            "verdict",
                            "score",
                            "risk_level",
                            "confidence",
                            "evidence_refs",
                        ],
                        "verdict_enum": list(VALID_LABELS),
                    },
                },
                "models": ["model_a", "model_b", "candidate_model"],
                "annotation_status": (
                    clean(row.get("annotation_status"))
                    if row.get("_gold_expansion")
                    else "strict_source_reference_requires_two_expert_reviews"
                    if row.get("_strict_extension")
                    else "gold_from_frozen_validation"
                ),
                "label_tier": (
                    clean(row.get("label_tier") or row.get("_label_tier"))
                    if row.get("_gold_expansion")
                    else row.get("_label_tier")
                    if row.get("_strict_extension")
                    else "frozen_validation_gold"
                ),
                "intended_use": (
                    "release_gate"
                    if row.get("_gold_expansion")
                    else "provisional_strict_release_diagnostic"
                    if row.get("_strict_extension")
                    else "release_gate"
                ),
                "training_overlap": False,
            }
        )
    model_release_count = write_jsonl(
        layer1_dir / "model_release_holdout.jsonl", model_release_records
    )
    expert_gold_records = [
        record
        for record in model_release_records
        if official_gold_row(record)
    ]
    expert_gold_count = write_jsonl(
        layer1_dir / "expert_gold_holdout.jsonl", expert_gold_records
    )
    approved_expansion_gold_count = sum(
        1 for row in strict_extension_rows if row.get("_gold_expansion")
    )
    strict_extension_review_pending = max(
        0, len(strict_extension_rows) - approved_expansion_gold_count
    )
    model_diagnostic_records = []
    for row in model_diagnostic_rows:
        model_diagnostic_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer1_model",
                "track": "single_model_feature_only",
                "input": model_input(row),
                "expected": {
                    "verdict": row["_gold_label"],
                    "label_source": row.get("label_source"),
                    "output_schema": {
                        "required": [
                            "verdict",
                            "score",
                            "risk_level",
                            "confidence",
                            "evidence_refs",
                        ],
                        "verdict_enum": list(VALID_LABELS),
                    },
                },
                "models": ["model_a", "model_b", "candidate_model"],
                "annotation_status": "gold_from_frozen_validation",
                "intended_use": "regression_diagnostic_only",
                "training_overlap": row["_row_id"] in training_ids,
            }
        )
    model_diagnostic_count = write_jsonl(
        layer1_dir / "model_diagnostic_eval.jsonl",
        model_diagnostic_records,
    )

    schema_failures = []
    failure_paths = [
        data_dir / "llm_validation_failures.jsonl",
        ROOT / "data" / "llm_validation_failures.jsonl",
    ]
    seen_failures: set[str] = set()
    for path in failure_paths:
        if not path.exists():
            continue
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                payload = read_json(line, {})
                raw_text = clean(payload.get("raw_text"))
                key = stable_hash(
                    f"{payload.get('model')}|{payload.get('phase')}|{raw_text}"
                )
                if not raw_text or key in seen_failures:
                    continue
                seen_failures.add(key)
                schema_failures.append(
                    {
                        "id": key[:24],
                        "layer": "layer1_model",
                        "track": "schema_repair_challenge",
                        "model": payload.get("model"),
                        "phase": payload.get("phase"),
                        "raw_output": raw_text,
                        "parsed_output": payload.get("parsed"),
                        "expected": {
                            "valid_json_object": True,
                            "no_think_block": True,
                            "repair_without_inventing_evidence": True,
                        },
                        "semantic_scoring_allowed": False,
                        "source": str(path),
                    }
                )
    schema_failure_count = write_jsonl(
        layer1_dir / "model_schema_challenges.jsonl", schema_failures
    )

    fresh_candidates = fresh_holdout_candidates(
        data_dir=data_dir,
        excluded_ids=training_ids.union(
            row["_row_id"] for row in rows + strict_extension_rows
        ),
        size=fresh_candidate_size,
        salt=f"fresh-holdout-v1|{sha256_file(validation_csv)}",
    )
    fresh_candidate_ids = {
        clean(row.get("id")).upper() for row in fresh_candidates if clean(row.get("id"))
    }

    layer2_dir = suite_dir / "layer2_rag"
    rag_path = data_dir / "rag" / "rag_store.db"
    if not rag_path.exists():
        rag_path = ROOT / "data" / "rag" / "rag_store.db"
    documents = load_rag_documents(rag_path)
    rag_evaluation_ids = {
        row["_row_id"] for row in rows + strict_extension_rows
    }.union(fresh_candidate_ids)
    excluded_rag_doc_ids = {
        doc_id
        for doc_id, document in documents.items()
        if clean((document.get("metadata") or {}).get("md5")).upper()
        in rag_evaluation_ids
    }
    rag_candidates = []
    for row in valid_rows:
        context = rag_context(reports.get(row["_row_id"]))
        query = clean(context.get("query"))
        items = [
            item
            for item in context.get("items") or []
            if isinstance(item, dict)
            and clean(item.get("doc_id")) not in excluded_rag_doc_ids
        ]
        retrieved_ids = [
            clean(item.get("doc_id")) for item in items if clean(item.get("doc_id"))
        ]
        if not query:
            query = " ".join(
                value
                for value in (
                    clean(row.get("app_name")),
                    clean(row.get("package_name")),
                    clean(row.get("virus_name")),
                    clean(row.get("fraud_category_big")),
                )
                if value
            )
        if not query:
            continue
        relevant, negatives = weak_relevance(row, retrieved_ids, documents)
        priority = (
            int(bool(retrieved_ids)) * 2
            + int(bool(relevant)) * 3
            + challenge_score(row, reports.get(row["_row_id"]))[0]
        )
        rag_candidates.append(
            (
                priority,
                {
                    "id": row["_row_id"],
                    "layer": "layer2_rag",
                    "query": query,
                    "sample": {
                        "md5": row["_row_id"],
                        "app_name": row.get("app_name"),
                        "package_name": row.get("package_name"),
                        "virus_name": row.get("virus_name"),
                        "gold_label": row["_gold_label"],
                    },
                    "retrieved_doc_ids": retrieved_ids,
                    "retrieved_items": items,
                    "weak_relevant_doc_ids": relevant,
                    "weak_hard_negative_doc_ids": negatives,
                    "relevant_doc_ids": [],
                    "hard_negative_doc_ids": [],
                    "evidence_supported": None,
                    "hallucination": None,
                    "wrong_evidence": False,
                    "missing_evidence": False,
                    "annotation_status": "needs_expert_review",
                    "weak_label_method": "exact_identifier_or_semantic_field_match",
                    "metrics_allowed_before_approval": [
                        "retrieval_nonempty_rate",
                        "latency",
                    ],
                },
            )
        )
    rag_candidates.sort(
        key=lambda item: (
            item[0],
            stable_hash(f"{suite_id}|rag|{item[1]['id']}"),
        ),
        reverse=True,
    )
    rag_records = [item[1] for item in rag_candidates[: min(rag_size, len(rag_candidates))]]
    rag_dataset_path = layer2_dir / "rag_retrieval_eval.jsonl"
    rag_count = write_jsonl(rag_dataset_path, rag_records)
    write_json(
        layer2_dir / "rag_scorecard.json",
        build_rag_retrieval_scorecard(rag_dataset_path),
    )
    corpus_records = [
        {
            "doc_id": document["doc_id"],
            "source_type": document["source_type"],
            "source_name": document["source_name"],
            "title": document["title"],
            "metadata": document["metadata"],
            "content_sha256": hashlib.sha256(
                clean(document["content"]).encode("utf-8", errors="ignore")
            ).hexdigest(),
            "updated_at": document["updated_at"],
        }
        for document in sorted(documents.values(), key=lambda value: value["doc_id"])
        if document["doc_id"] not in excluded_rag_doc_ids
    ]
    corpus_count = write_jsonl(layer2_dir / "rag_corpus_inventory.jsonl", corpus_records)

    faithfulness_records = []
    for row in rag_records:
        report = reports.get(row["id"])
        if not report:
            continue
        review = reviews_by_report.get(clean(report.get("report_id")))
        if not review:
            review = reviews_by_sample.get(row["id"])
        faithfulness_records.append(
            {
                "id": row["id"],
                "layer": "layer2_rag",
                "rag_context": rag_context(report),
                "final_decision": report.get("decision"),
                "evidence_blocks": agent_blocks(report),
                "human_annotation": review,
                "annotation_status": (
                    clean((review or {}).get("review_status")) or "needs_expert_review"
                ),
                "required_labels": [
                    "evidence_supported",
                    "hallucination",
                    "wrong_evidence",
                    "missing_evidence",
                ],
            }
        )
    faithfulness_count = write_jsonl(
        layer2_dir / "evidence_faithfulness_eval.jsonl", faithfulness_records
    )

    layer3_dir = suite_dir / "layer3_agent"
    agent_source_rows = balanced_rows(
        [row for row in valid_rows if row["_row_id"] in reports],
        agent_size,
        salt=f"{suite_id}|agent",
    )
    agent_records = []
    for row in agent_source_rows:
        report = reports.get(row["_row_id"])
        agent_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer3_agent",
                "gold_label": row["_gold_label"],
                "label_source": row.get("label_source"),
                "input": model_input(row),
                "agent_blocks": agent_blocks(report),
                "agent_runtime": agent_runtime(report),
                "expected_agents": list(AGENT_NAMES),
                "expected_block_contract": {
                    "required": ["agent", "score", "evidence"],
                    "score_range": [0, 1],
                    "evidence_must_reference_input_fields": True,
                },
                "report_id": (report or {}).get("report_id"),
                "intended_use": (
                    "release_gate"
                    if row["_row_id"] not in training_ids
                    else "regression_diagnostic_only"
                ),
                "training_overlap": row["_row_id"] in training_ids,
            }
        )
    agent_count = write_jsonl(layer3_dir / "agent_trace_eval.jsonl", agent_records)
    fault_records = []
    fault_samples = agent_source_rows[: min(25, len(agent_source_rows))]
    for row in fault_samples:
        for agent in AGENT_NAMES:
            for fault_type in ("transient_failure", "timeout", "invalid_schema"):
                fault_records.append(
                    {
                        "id": f"{row['_row_id']}:{agent}:{fault_type}",
                        "layer": "layer3_agent",
                        "sample_id": row["_row_id"],
                        "agent": agent,
                        "fault_type": fault_type,
                        "fault_config": {
                            "agent_runtime_faults": {
                                agent: {
                                    "failures": 1,
                                    "mode": fault_type,
                                }
                            },
                            "agent_runtime_config": {
                                "agents": {agent: {"max_restarts": 1}}
                            },
                        },
                        "expected": {
                            "no_duplicate_report": True,
                            "checkpoint_persisted": True,
                            "status_after_transient_failure": "completed_or_degraded",
                        },
                    }
                )
    fault_count = write_jsonl(layer3_dir / "agent_fault_eval.jsonl", fault_records)
    ablation_records = [
        {
            "id": row["_row_id"],
            "layer": "layer3_agent",
            "gold_label": row["_gold_label"],
            "input": model_input(row),
            "variants": [
                "full",
                "no_static_analysis",
                "no_threat_intel",
                "no_impersonation",
                "no_business_label",
            ],
            "comparison_metrics": [
                "malicious_recall_delta",
                "benign_false_positive_rate_delta",
                "macro_f1_delta",
                "latency_p95_delta_ms",
            ],
        }
        for row in challenge_rows
    ]
    ablation_count = write_jsonl(
        layer3_dir / "agent_ablation_eval.jsonl", ablation_records
    )

    layer4_dir = suite_dir / "layer4_e2e"
    release_e2e_records = []
    for row in release_rows:
        report = reports.get(row["_row_id"])
        release_e2e_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer4_e2e",
                "input": model_input(row),
                "expected": {
                    "verdict": row["_gold_label"],
                    "label_source": row.get("label_source"),
                },
                "saved_result": report_summary(report),
                "status": "judged" if report else "pending",
                "training_overlap": False,
                "intended_use": "release_gate",
            }
        )
    release_e2e_count = write_jsonl(
        layer4_dir / "end_to_end_release_holdout.jsonl", release_e2e_records
    )
    diagnostic_e2e_records = []
    for row in valid_rows:
        report = reports.get(row["_row_id"])
        diagnostic_e2e_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer4_e2e",
                "input": model_input(row),
                "expected": {
                    "verdict": row["_gold_label"],
                    "label_source": row.get("label_source"),
                },
                "saved_result": report_summary(report),
                "status": "judged" if report else "pending",
                "training_overlap": row["_row_id"] in training_ids,
                "intended_use": "regression_diagnostic_only",
            }
        )
    diagnostic_e2e_count = write_jsonl(
        layer4_dir / "end_to_end_diagnostic_all.jsonl",
        diagnostic_e2e_records,
    )
    challenge_records = []
    for row in challenge_rows:
        score, reasons = challenge_score(row, reports.get(row["_row_id"]))
        challenge_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer4_e2e",
                "input": model_input(row),
                "expected": {
                    "verdict": row["_gold_label"],
                    "label_source": row.get("label_source"),
                },
                "challenge_score": score,
                "challenge_reasons": reasons.split(","),
                "saved_result": report_summary(reports.get(row["_row_id"])),
                "training_overlap": row["_row_id"] in training_ids,
                "intended_use": "challenge_diagnostic_only",
            }
        )
    challenge_count_written = write_jsonl(
        layer4_dir / "end_to_end_challenge_eval.jsonl", challenge_records
    )

    layer5_dir = suite_dir / "layer5_production"
    production_records = []
    for row in rows:
        report = reports.get(row["_row_id"])
        if not report:
            continue
        providers = (report.get("debate") or {}).get("providers") or {}
        review = reviews_by_report.get(clean(report.get("report_id")))
        if not review:
            review = reviews_by_sample.get(row["_row_id"])
        production_records.append(
            {
                "id": row["_row_id"],
                "layer": "layer5_production",
                "report_id": report.get("report_id"),
                "created_at": report.get("created_at"),
                "gold_label": row["_gold_label"],
                "decision": report.get("decision"),
                "correct": clean((report.get("decision") or {}).get("verdict")).lower()
                == row["_gold_label"],
                "latency_ms": report_latency_ms(report),
                "providers": providers,
                "agent_runtime": agent_runtime(report),
                "execution": report.get("execution"),
                "runtime_snapshot": report.get("runtime_snapshot"),
                "human_review": review,
            }
        )
    production_count = write_jsonl(
        layer5_dir / "production_replay_eval.jsonl", production_records
    )
    reliability_scenarios = []
    scenario_types = (
        "model_a_unavailable",
        "model_b_timeout",
        "rag_empty",
        "rag_database_locked",
        "invalid_model_json",
        "process_interruption",
        "checkpoint_resume",
    )
    for row in challenge_rows[: min(20, len(challenge_rows))]:
        for scenario in scenario_types:
            reliability_scenarios.append(
                {
                    "id": f"{row['_row_id']}:{scenario}",
                    "layer": "layer5_production",
                    "sample_id": row["_row_id"],
                    "scenario": scenario,
                    "expected": {
                        "request_is_bounded": True,
                        "failure_is_observable": True,
                        "no_duplicate_saved_report": True,
                        "resume_is_idempotent": True,
                        "fallback_is_labeled": True,
                    },
                }
            )
    reliability_count = write_jsonl(
        layer5_dir / "production_reliability_eval.jsonl",
        reliability_scenarios,
    )
    drift_reference = {
        "generated_at": now_iso(),
        "validation_sha256": sha256_file(validation_csv),
        "reference_count": len(rows),
        "distributions": [
            feature_distribution(rows, field)
            for field in (
                "gold_label",
                "label_source",
                "file_type",
                "signature_status",
                "fraud_category_big",
                "engine_360_type",
                "engine_cm_type",
                "xgb_verdict",
            )
        ],
        "numeric_reference": {
            field: {
                "count": len(values),
                "mean": round(statistics.fmean(values), 6) if values else None,
                "p50": percentile(values, 0.5),
                "p95": percentile(values, 0.95),
            }
            for field, values in {
                field: [
                    value
                    for value in (as_float(row.get(field)) for row in rows)
                    if value is not None
                ]
                for field in (
                    "engine_360_score",
                    "engine_cm_score",
                    "xgb_probability",
                    "file_size",
                )
            }.items()
        },
        "psi_bins": 10,
        "drift_thresholds": {
            "warning_psi": 0.1,
            "block_psi": 0.25,
        },
    }
    write_json(layer5_dir / "drift_reference.json", drift_reference)

    fresh_candidate_count = write_jsonl(
        suite_dir / "fresh_expert_holdout_candidates.jsonl",
        fresh_candidates,
    )

    baselines = {
        "layer1_model": {
            "release_holdout": segmented_model_baseline(release_rows, reports),
            "diagnostic_all": model_baseline(rows, reports),
        },
        "layer2_rag": rag_baseline(rows, reports, reviews),
        "layer3_agent": agent_baseline(rows, reports),
        "layer4_e2e": {
            "release_holdout": segmented_end_to_end_baseline(
                release_rows, reports
            ),
            "diagnostic_all": build_scorecard(validation_csv, data_dir)["metrics"],
        },
        "layer5_production": production_baseline(rows, reports, data_dir, reviews),
    }
    write_json(suite_dir / "baseline_scorecards.json", baselines)
    write_json(suite_dir / "source_inventory.json", inventory)
    quality_report = build_data_quality_report(inventory)
    write_json(suite_dir / "data_quality_report.json", quality_report)

    dataset_counts = {
        "layer1_model": {
            "model_release_holdout": model_release_count,
            "expert_gold_holdout": expert_gold_count,
            "model_diagnostic_eval": model_diagnostic_count,
            "model_schema_challenges": schema_failure_count,
        },
        "layer2_rag": {
            "rag_retrieval_eval": rag_count,
            "rag_corpus_inventory": corpus_count,
            "evidence_faithfulness_eval": faithfulness_count,
        },
        "layer3_agent": {
            "agent_trace_eval": agent_count,
            "agent_fault_eval": fault_count,
            "agent_ablation_eval": ablation_count,
        },
        "layer4_e2e": {
            "end_to_end_release_holdout": release_e2e_count,
            "end_to_end_diagnostic_all": diagnostic_e2e_count,
            "end_to_end_challenge_eval": challenge_count_written,
        },
        "layer5_production": {
            "production_replay_eval": production_count,
            "production_reliability_eval": reliability_count,
            "drift_reference": len(rows),
        },
        "cross_layer": {
            "fresh_expert_holdout_candidates": fresh_candidate_count,
        },
    }
    manifest = {
        "suite_version": SUITE_VERSION,
        "suite_id": suite_id,
        "created_at": now_iso(),
        "status": "generated_requires_annotation_and_experiment_runs",
        "suite_dir": str(suite_dir),
        "validation_source": {
            "path": str(validation_csv),
            "sha256": sha256_file(validation_csv),
            "rows": len(rows),
        },
        "workflow_validation_source": {
            "path": str(workflow_validation_csv),
            "sha256": sha256_file(workflow_validation_csv),
            "rows": workflow_validation_count,
        },
        "application_data_dir": str(data_dir),
        "layers": LAYER_DEFINITIONS,
        "release_gates": RELEASE_GATES,
        "dataset_counts": dataset_counts,
        "selection": {
            "release_training_overlap_excluded": True,
            "release_holdout_count": len(release_rows),
            "frozen_gold_release_count": expert_gold_count,
            "base_frozen_gold_count": len(frozen_release_rows),
            "approved_expansion_gold_count": approved_expansion_gold_count,
            "expert_gold_holdout_count": expert_gold_count,
            "strict_source_reference_extension_count": len(strict_extension_rows),
            "strict_source_reference_requires_expert_review": strict_extension_review_pending,
            "diagnostic_all_count": len(valid_rows),
            "training_overlap_count": inventory["training"]["validation_overlap_ids"],
            "model_challenge_id_overlap": len(model_ids.intersection(challenge_ids)),
            "stable_hash_selection": True,
            "fresh_candidate_count": fresh_candidate_count,
        },
        "annotation_requirements": {
            "layer1": (
                "仅expert_gold_holdout中的冻结/批准/仲裁专家金标进入发布准确率；"
                "严格来源扩展只报告一致率，diagnostic_eval只做历史回归。"
            ),
            "layer2": "weak_relevant_doc_ids必须经专家批准后复制到relevant_doc_ids。",
            "layer3": "边际贡献必须运行五个消融变体后计算。",
            "layer4": "冻结测试集不得用于提示词、阈值、SFT或DPO调参。",
            "layer5": "故障场景必须在隔离数据目录运行。",
        },
        "quality_gate": {
            "release_safe_without_exclusions": quality_report[
                "release_safe_without_exclusions"
            ],
            "high_or_critical_findings": sum(
                count
                for severity, count in quality_report["severity_counts"].items()
                if severity in {"high", "critical"}
            ),
        },
        "files": {
            "manifest": str(suite_dir / "manifest.json"),
            "source_inventory": str(suite_dir / "source_inventory.json"),
            "data_quality_report": str(suite_dir / "data_quality_report.json"),
            "baseline_scorecards": str(suite_dir / "baseline_scorecards.json"),
            "strict_release_validation": str(workflow_validation_csv),
            "expert_gold_holdout": str(
                layer1_dir / "expert_gold_holdout.jsonl"
            ),
            "fresh_expert_holdout_candidates": str(
                suite_dir / "fresh_expert_holdout_candidates.jsonl"
            ),
        },
    }
    write_json(suite_dir / "manifest.json", manifest)
    validation_report = validate_five_layer_suite(suite_dir)
    validation_path = suite_dir / "suite_validation.json"
    write_json(validation_path, validation_report)
    manifest["files"]["suite_validation"] = str(validation_path)
    manifest["suite_validation"] = {
        "passed": validation_report["passed"],
        "checks_total": validation_report["checks_total"],
        "checks_passed": validation_report["checks_passed"],
        "checks_failed": validation_report["checks_failed"],
    }
    write_json(suite_dir / "manifest.json", manifest)
    write_json(output_root / "latest.json", manifest)
    return manifest


def score_model_predictions(
    dataset_jsonl: Path,
    predictions_jsonl: Path,
) -> dict[str, Any]:
    dataset_jsonl = dataset_jsonl.expanduser().resolve()
    predictions_jsonl = predictions_jsonl.expanduser().resolve()
    dataset = {clean(row.get("id")).upper(): row for row in read_jsonl(dataset_jsonl)}
    predictions = {}
    duplicate_predictions = 0
    for row in read_jsonl(predictions_jsonl):
        sample_id = clean(row.get("id") or row.get("sample_id") or row.get("md5")).upper()
        if not sample_id:
            continue
        duplicate_predictions += int(sample_id in predictions)
        predictions[sample_id] = row

    correct = incorrect = review = tp = fn = fp = tn = valid_schema = 0
    malicious_gold = benign_gold = 0
    latencies: list[float] = []
    calibration: list[tuple[int, float]] = []
    matched = 0
    for sample_id, example in dataset.items():
        prediction = predictions.get(sample_id)
        if not prediction:
            continue
        matched += 1
        output = prediction.get("output") if isinstance(prediction.get("output"), dict) else prediction
        verdict = clean(output.get("verdict")).lower()
        score = as_float(output.get("score") or output.get("final_score"))
        evidence_refs = output.get("evidence_refs")
        schema_valid = (
            verdict in VALID_LABELS
            and score is not None
            and 0 <= score <= 1
            and isinstance(evidence_refs, list)
        )
        valid_schema += int(schema_valid)
        gold = clean((example.get("expected") or {}).get("verdict")).lower()
        malicious_gold += int(gold == "malicious")
        benign_gold += int(gold == "benign")
        if verdict == "suspicious":
            review += 1
        elif verdict == gold:
            correct += 1
        elif verdict in VALID_LABELS:
            incorrect += 1
        tp += int(gold == "malicious" and verdict == "malicious")
        fn += int(gold == "malicious" and verdict == "benign")
        fp += int(gold == "benign" and verdict == "malicious")
        tn += int(gold == "benign" and verdict == "benign")
        if score is not None:
            calibration.append((1 if gold == "malicious" else 0, min(1.0, max(0.0, score))))
        latency = as_float(prediction.get("latency_ms") or output.get("latency_ms"))
        if latency is not None:
            latencies.append(latency)

    brier = (
        round(statistics.fmean((label - score) ** 2 for label, score in calibration), 6)
        if calibration
        else None
    )
    decided = correct + incorrect
    result = {
        "generated_at": now_iso(),
        "dataset": str(dataset_jsonl),
        "dataset_sha256": sha256_file(dataset_jsonl),
        "predictions": str(predictions_jsonl),
        "predictions_sha256": sha256_file(predictions_jsonl),
        "dataset_total": len(dataset),
        "prediction_total": len(predictions),
        "matched_total": matched,
        "missing_predictions": len(dataset) - matched,
        "duplicate_predictions": duplicate_predictions,
        "metrics": {
            "coverage": safe_div(matched, len(dataset)),
            "decided_accuracy": safe_div(correct, decided),
            "malicious_recall": safe_div(tp, malicious_gold),
            "benign_false_positive_rate": safe_div(fp, benign_gold),
            "review_rate": safe_div(review, matched),
            "json_schema_success_rate": safe_div(valid_schema, matched),
            "brier_score": brier,
            "latency_ms": {
                "count": len(latencies),
                "p50": percentile(latencies, 0.5),
                "p95": percentile(latencies, 0.95),
            },
        },
    }
    return result


def categorical_psi(
    reference: dict[str, Any],
    current_rows: list[dict[str, Any]],
) -> float | None:
    field = clean(reference.get("field"))
    if not field or not current_rows:
        return None
    current_counts = Counter(clean(row.get(field)) or "__missing__" for row in current_rows)
    current_total = sum(current_counts.values())
    reference_values = reference.get("values") or {}
    keys = set(reference_values).union(current_counts)
    epsilon = 1e-6
    psi = 0.0
    for key in keys:
        expected = float((reference_values.get(key) or {}).get("rate") or 0)
        actual = current_counts.get(key, 0) / current_total
        expected = max(expected, epsilon)
        actual = max(actual, epsilon)
        psi += (actual - expected) * math.log(actual / expected)
    return round(psi, 6)


def score_production_drift(
    suite_dir: Path,
    current_csv: Path,
) -> dict[str, Any]:
    suite_dir = suite_dir.expanduser().resolve()
    current_csv = current_csv.expanduser().resolve()
    reference_path = suite_dir / "layer5_production" / "drift_reference.json"
    reference = read_json(reference_path.read_text(encoding="utf-8"), {})
    current_rows = load_validation_rows(current_csv)
    field_results = []
    for distribution in reference.get("distributions") or []:
        psi = categorical_psi(distribution, current_rows)
        field_results.append(
            {
                "field": distribution.get("field"),
                "psi": psi,
                "status": (
                    "blocked"
                    if psi is not None and psi >= 0.25
                    else "warning"
                    if psi is not None and psi >= 0.1
                    else "ok"
                ),
            }
        )
    max_psi = max(
        (item["psi"] for item in field_results if item["psi"] is not None),
        default=None,
    )
    return {
        "generated_at": now_iso(),
        "suite_dir": str(suite_dir),
        "reference": str(reference_path),
        "current_csv": str(current_csv),
        "current_sha256": sha256_file(current_csv),
        "current_rows": len(current_rows),
        "max_categorical_psi": max_psi,
        "status": (
            "blocked"
            if max_psi is not None and max_psi >= 0.25
            else "warning"
            if max_psi is not None and max_psi >= 0.1
            else "ok"
        ),
        "fields": field_results,
    }


def validate_five_layer_suite(suite_dir: Path) -> dict[str, Any]:
    suite_dir = suite_dir.expanduser().resolve()
    manifest_path = suite_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest not found: {manifest_path}")
    manifest = read_json(manifest_path.read_text(encoding="utf-8"), {})
    expected_files = (
        "layer1_model/model_release_holdout.jsonl",
        "layer1_model/expert_gold_holdout.jsonl",
        "layer1_model/model_diagnostic_eval.jsonl",
        "layer1_model/model_schema_challenges.jsonl",
        "layer2_rag/rag_retrieval_eval.jsonl",
        "layer2_rag/rag_corpus_inventory.jsonl",
        "layer2_rag/evidence_faithfulness_eval.jsonl",
        "layer3_agent/agent_trace_eval.jsonl",
        "layer3_agent/agent_fault_eval.jsonl",
        "layer3_agent/agent_ablation_eval.jsonl",
        "layer4_e2e/end_to_end_release_holdout.jsonl",
        "layer4_e2e/end_to_end_diagnostic_all.jsonl",
        "layer4_e2e/end_to_end_challenge_eval.jsonl",
        "layer5_production/production_replay_eval.jsonl",
        "layer5_production/production_reliability_eval.jsonl",
        "fresh_expert_holdout_candidates.jsonl",
    )
    checks: list[dict[str, Any]] = []
    datasets: dict[str, list[dict[str, Any]]] = {}
    for relative in expected_files:
        path = suite_dir / relative
        exists = path.exists()
        rows: list[dict[str, Any]] = []
        error = ""
        if exists:
            try:
                rows = read_jsonl(path)
            except Exception as exc:
                error = f"{type(exc).__name__}: {exc}"
        datasets[relative] = rows
        checks.append(
            {
                "check": f"file:{relative}",
                "passed": exists and not error,
                "rows": len(rows),
                "error": error or None,
            }
        )

    release_model = datasets["layer1_model/model_release_holdout.jsonl"]
    expert_gold = datasets["layer1_model/expert_gold_holdout.jsonl"]
    release_e2e = datasets["layer4_e2e/end_to_end_release_holdout.jsonl"]
    challenge = datasets["layer4_e2e/end_to_end_challenge_eval.jsonl"]
    fresh = datasets["fresh_expert_holdout_candidates.jsonl"]
    for name, rows in (
        ("release_model_unique", release_model),
        ("expert_gold_unique", expert_gold),
        ("release_e2e_unique", release_e2e),
        ("fresh_candidates_unique", fresh),
    ):
        ids = [clean(row.get("id")).upper() for row in rows]
        checks.append(
            {
                "check": name,
                "passed": len(ids) == len(set(ids)) and all(ids),
                "rows": len(ids),
            }
        )
    checks.append(
        {
            "check": "release_model_training_disjoint",
            "passed": all(not row.get("training_overlap") for row in release_model),
            "rows": len(release_model),
        }
    )
    checks.append(
        {
            "check": "expert_gold_policy",
            "passed": bool(expert_gold)
            and all(official_gold_row(row) for row in expert_gold)
            and all(
                clean(row.get("intended_use")).lower() == "release_gate"
                for row in expert_gold
            ),
            "rows": len(expert_gold),
        }
    )
    release_ids = {clean(row.get("id")).upper() for row in release_model}
    challenge_ids = {clean(row.get("id")).upper() for row in challenge}
    checks.append(
        {
            "check": "release_challenge_id_disjoint",
            "passed": not release_ids.intersection(challenge_ids),
            "overlap": len(release_ids.intersection(challenge_ids)),
        }
    )
    validation_rows = load_validation_rows(
        Path((manifest.get("validation_source") or {}).get("path"))
    )
    validation_ids = {row["_row_id"] for row in validation_rows}
    fresh_ids = {clean(row.get("id")).upper() for row in fresh}
    checks.append(
        {
            "check": "fresh_existing_validation_disjoint",
            "passed": not fresh_ids.intersection(validation_ids),
        }
    )
    structured_rag = [
        row
        for row in datasets["layer2_rag/rag_corpus_inventory.jsonl"]
        if row.get("source_type") == "malapp_structured_sample"
    ]
    forbidden_fields = {
        "gold_label",
        "candidate_label",
        "raw_label",
        "saved_model_verdict",
        "xgb_probability",
        "manual_review_result",
    }
    forbidden_found = sorted(
        {
            key
            for row in structured_rag
            for key in (row.get("metadata") or {})
            if key in forbidden_fields
        }
    )
    checks.append(
        {
            "check": "structured_rag_answer_fields_absent",
            "passed": not forbidden_found,
            "forbidden_fields_found": forbidden_found,
            "rows": len(structured_rag),
        }
    )
    structured_ids = {
        clean((row.get("metadata") or {}).get("md5")).upper()
        for row in structured_rag
        if clean((row.get("metadata") or {}).get("md5"))
    }
    evaluation_overlap = structured_ids.intersection(validation_ids.union(fresh_ids))
    checks.append(
        {
            "check": "structured_rag_evaluation_id_disjoint",
            "passed": not evaluation_overlap,
            "overlap": len(evaluation_overlap),
            "rows": len(structured_rag),
        }
    )
    failed = [check for check in checks if not check.get("passed")]
    return {
        "generated_at": now_iso(),
        "suite_dir": str(suite_dir),
        "suite_id": manifest.get("suite_id"),
        "passed": not failed,
        "checks_total": len(checks),
        "checks_passed": len(checks) - len(failed),
        "checks_failed": len(failed),
        "checks": checks,
    }


def _command_argument(args: list[Any], name: str) -> str:
    values = [str(value) for value in args]
    try:
        return values[values.index(name) + 1]
    except (ValueError, IndexError):
        return ""


def _first_checkpoint_error(checkpoint: dict[str, Any]) -> str:
    for item in (checkpoint.get("items") or {}).values():
        if isinstance(item, dict) and item.get("status") == "failed":
            return clean(item.get("error"))
    return ""


def _recovered_workflow_job(
    *, data_dir: Path, suite_id: str, action: str
) -> dict[str, Any]:
    """Rebuild the workflow index from stable run directories.

    Job JSON files are useful for live process state, but checkpoints and result
    files are the durable source of truth.  This fallback keeps completed and
    partial results visible after an application restart or an index-file loss.
    """
    run_root = data_dir / "evaluation" / "five_layer_runs"
    definitions: dict[str, list[tuple[str, str]]] = {
        "gold_compare": [("专家金标集", f"{suite_id}-gold-compare")],
        "model_release": [("严格训练未见集", f"{suite_id}-model-release")],
        "complete_release": [("严格训练未见集", f"{suite_id}-model-release")],
        "rag_compare": [
            ("无RAG", f"{suite_id}-rag_off"),
            ("向量RAG", f"{suite_id}-rag_vector"),
            ("混合RAG", f"{suite_id}-rag_hybrid"),
        ],
        "agent_ablation": [
            ("完整系统", f"{suite_id}-full"),
            ("去静态分析Agent", f"{suite_id}-no-static_analysis"),
            ("去威胁情报Agent", f"{suite_id}-no-threat_intel"),
            ("去仿冒研判Agent", f"{suite_id}-no-impersonation"),
            ("去业务标签Agent", f"{suite_id}-no-business_label"),
        ],
        "production_reliability": [
            ("瞬时故障恢复", f"{suite_id}-fault-recovery"),
            ("相同检查点幂等重放", f"{suite_id}-fault-recovery"),
        ],
    }
    commands = []
    activity: list[float] = []
    for name, run_id in definitions.get(action, []):
        run_dir = run_root / run_id
        durable_files = [
            run_dir / "checkpoint.json",
            run_dir / "result.json",
            run_dir / "scorecard.json",
            run_dir / "run_config.json",
        ]
        existing = [path for path in durable_files if path.exists()]
        if not existing:
            continue
        commands.append(
            {
                "name": name,
                "args": [
                    "run",
                    "--run-id",
                    run_id,
                    "--output-root",
                    str(run_root),
                ],
            }
        )
        activity.extend(path.stat().st_mtime for path in existing)
    if not commands:
        return {}
    recovered_at = datetime.fromtimestamp(
        max(activity), tz=timezone.utc
    ).isoformat()
    return {
        "job_id": f"recovered-{suite_id}-{action}",
        "action": action,
        "suite_id": suite_id,
        "status": "completed",
        "created_at": recovered_at,
        "updated_at": recovered_at,
        "recovered_from_run_files": True,
        "commands": commands,
    }


def _workflow_experiment(
    *,
    data_dir: Path,
    suite_id: str,
    action: str,
    expected_variants: int,
) -> dict[str, Any]:
    directory = data_dir / "evaluation" / "five_layer_jobs"
    jobs: list[dict[str, Any]] = []
    if directory.exists():
        for path in directory.glob("*.json"):
            payload = read_json(path.read_text(encoding="utf-8"), {})
            if (
                isinstance(payload, dict)
                and clean(payload.get("action")) == action
                and clean(payload.get("suite_id")) == suite_id
            ):
                jobs.append(payload)
    jobs.sort(key=lambda item: clean(item.get("created_at")), reverse=True)
    if not jobs:
        recovered = _recovered_workflow_job(
            data_dir=data_dir, suite_id=suite_id, action=action
        )
        if recovered:
            jobs.append(recovered)
        else:
            return {
                "action": action,
                "status": "not_run",
                "expected_variants": expected_variants,
                "completed_variants": 0,
                "failed_variants": 0,
                "variants": [],
            }
    job = jobs[0]
    variants: list[dict[str, Any]] = []
    for command_item in job.get("commands") or []:
        args = command_item.get("args") or []
        run_id = _command_argument(args, "--run-id")
        output_root = _command_argument(args, "--output-root")
        run_dir = Path(output_root) / run_id if output_root and run_id else Path()
        result_path = run_dir / "result.json" if output_root and run_id else Path()
        scorecard_path = run_dir / "scorecard.json" if output_root and run_id else Path()
        config_path = run_dir / "run_config.json" if output_root and run_id else Path()
        checkpoint_path = run_dir / "checkpoint.json" if output_root and run_id else Path()
        result = (
            read_json(result_path.read_text(encoding="utf-8"), {})
            if result_path.exists()
            else {}
        )
        scorecard = (
            read_json(scorecard_path.read_text(encoding="utf-8"), {})
            if scorecard_path.exists()
            else {}
        )
        config = (
            read_json(config_path.read_text(encoding="utf-8"), {})
            if config_path.exists()
            else {}
        )
        checkpoint = (
            read_json(checkpoint_path.read_text(encoding="utf-8"), {})
            if checkpoint_path.exists()
            else {}
        )
        checkpoint_items = checkpoint.get("items") or {}
        checkpoint_completed = sum(
            1
            for item in checkpoint_items.values()
            if isinstance(item, dict) and item.get("status") == "completed"
        )
        checkpoint_failed = sum(
            1
            for item in checkpoint_items.values()
            if isinstance(item, dict) and item.get("status") == "failed"
        )
        failed = max(
            checkpoint_failed, int(result.get("failed_this_invocation") or 0)
        )
        completed = max(
            checkpoint_completed,
            int(result.get("completed_this_invocation") or 0)
            + int(result.get("skipped_completed") or 0),
        )
        disabled = []
        agents = (
            ((config.get("sample_overrides") or {}).get("agent_runtime_config") or {}).get(
                "agents"
            )
            or {}
        )
        for agent, agent_config in agents.items():
            if isinstance(agent_config, dict) and agent_config.get("enabled") is False:
                disabled.append(clean(agent))
        metrics = scorecard.get("metrics") or result.get("metrics") or {}
        run_status = (
            "failed"
            if failed or result.get("status") == "failed"
            else "completed"
            if completed and result
            else "missing"
        )
        variants.append(
            {
                "name": command_item.get("name"),
                "run_id": run_id,
                "variant": config.get("variant") or result.get("variant"),
                "disabled_agents": disabled,
                "status": run_status,
                "completed_samples": completed,
                "failed_samples": failed,
                "skipped_completed": int(result.get("skipped_completed") or 0),
                "metrics": {
                    "decided_accuracy": metrics.get("decided_accuracy"),
                    "malicious_recall": metrics.get("malicious_recall"),
                    "benign_false_positive_rate": metrics.get(
                        "benign_false_positive_rate"
                    ),
                    "macro_f1": metrics.get("macro_f1"),
                    "structure_success_rate": metrics.get("structure_success_rate"),
                    "latency_p95_ms": (metrics.get("latency_ms") or {}).get("p95"),
                },
                "failure_reason": _first_checkpoint_error(checkpoint),
                "run_data_dir": str(run_dir / "data") if output_root and run_id else "",
            }
        )
    completed_variants = sum(1 for item in variants if item["status"] == "completed")
    failed_variants = sum(1 for item in variants if item["status"] == "failed")
    active_status = clean(job.get("status")).lower()
    status = (
        active_status
        if active_status in {"queued", "running", "cancelling", "cancelled"}
        else "failed"
        if failed_variants or completed_variants < expected_variants
        else "completed"
    )
    failure_reason = next(
        (item["failure_reason"] for item in variants if item["failure_reason"]),
        clean(job.get("error")),
    )
    return {
        "action": action,
        "job_id": job.get("job_id"),
        "created_at": job.get("created_at"),
        "status": status,
        "expected_variants": expected_variants,
        "completed_variants": completed_variants,
        "failed_variants": failed_variants,
        "failure_reason": failure_reason,
        "variants": variants,
    }


def _agent_recovery_metrics(experiment: dict[str, Any]) -> dict[str, Any]:
    if experiment.get("status") != "completed":
        return {
            "restart_attempts": 0,
            "restart_recovered": 0,
            "restart_recovery_rate": None,
            "idempotent_replay_skipped": 0,
        }
    run_dirs = {
        clean(item.get("run_data_dir"))
        for item in experiment.get("variants") or []
        if clean(item.get("run_data_dir"))
    }
    attempts = recovered = 0
    for directory in run_dirs:
        for report in load_reports(Path(directory)):
            for status_data in agent_runtime(report).values():
                if not isinstance(status_data, dict):
                    continue
                restart_count = int(as_float(status_data.get("restart_count")) or 0)
                attempts += restart_count
                recovered += restart_count * int(
                    clean(status_data.get("status")).lower()
                    in {"completed", "success", "healthy"}
                )
    replay_skipped = max(
        (
            int(item.get("skipped_completed") or 0)
            for item in experiment.get("variants") or []
        ),
        default=0,
    )
    return {
        "restart_attempts": attempts,
        "restart_recovered": recovered,
        "restart_recovery_rate": safe_div(recovered, attempts),
        "idempotent_replay_skipped": replay_skipped,
    }


def _model_release_experiment_metrics(
    experiment: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    variants = experiment.get("variants") or []
    run_data_dirs = [
        Path(clean(item.get("run_data_dir")))
        for item in variants
        if clean(item.get("run_data_dir"))
    ]
    release_path = (
        Path(clean(manifest.get("suite_dir")))
        / "layer1_model"
        / "model_release_holdout.jsonl"
    )
    validation_rows = []
    if release_path.exists():
        for row in read_jsonl(release_path):
            expected = row.get("expected") or {}
            validation_rows.append(
                {
                    "_row_id": clean(row.get("id")).upper(),
                    "_gold_label": clean(expected.get("verdict")).lower(),
                    "label_tier": row.get("label_tier"),
                    "annotation_status": row.get("annotation_status"),
                    "intended_use": row.get("intended_use"),
                }
            )
    reference_total = len(validation_rows)
    if not run_data_dirs or not validation_rows:
        return {
            "model_a": {},
            "model_b": {},
            "formal_reports": 0,
            "reference_total": reference_total,
            "reference_channels": {},
            "reference_metric_policy": (
                "严格训练未见集全部样本均按现有参考标签计算；"
                "专家金标子集仍单独保留，便于识别标签可信度差异。"
            ),
        }
    reports_list: list[dict[str, Any]] = []
    for run_data_dir in dict.fromkeys(run_data_dirs):
        reports_list.extend(load_reports(run_data_dir))
    report_index = latest_report_index(reports_list)
    baseline = segmented_model_baseline(validation_rows, report_index)
    reference_channels = {
        channel: _score_report_channel(validation_rows, report_index, channel)
        for channel in ("pipeline_final", "model_a", "model_b", "xgboost")
    }
    return {
        "model_a": baseline.get("model_a") or {},
        "model_b": baseline.get("model_b") or {},
        "official_gold": baseline.get("official_gold") or {},
        "provisional_source_reference": baseline.get(
            "provisional_source_reference"
        )
        or {},
        "combined_diagnostic": baseline.get("combined_diagnostic") or {},
        "metric_policy": baseline.get("metric_policy"),
        "formal_reports": len(report_index),
        "reference_total": reference_total,
        "reference_channels": reference_channels,
        "reference_metric_policy": (
            "严格训练未见集全部样本均按现有参考标签计算准确率、恶意召回、"
            "良性误报和待复核率；其中来源参考标签尚未全部完成双专家复核。"
        ),
    }


def _score_report_channel(
    validation_rows: list[dict[str, Any]],
    reports: dict[str, dict[str, Any]],
    channel: str,
) -> dict[str, Any]:
    correct = decided = available = review = malicious_total = benign_total = 0
    true_positive = false_positive = 0
    latencies: list[float] = []
    for row in validation_rows:
        report = reports.get(row["_row_id"])
        if not report:
            continue
        if channel == "pipeline_final":
            output = report.get("decision") or {}
        elif channel in {"model_a", "model_b"}:
            output = (report.get("debate") or {}).get(channel) or {}
        elif channel == "xgboost":
            output = (report.get("decision") or {}).get("xgb") or {}
        else:
            raise ValueError(f"unknown comparison channel: {channel}")
        verdict = clean(output.get("verdict")).lower()
        if verdict not in VALID_LABELS:
            continue
        available += 1
        latency = (
            report_latency_ms(report)
            if channel == "pipeline_final"
            else as_float(output.get("latency_ms"))
        )
        if latency is not None:
            latencies.append(latency)
        gold = row["_gold_label"]
        malicious_total += int(gold == "malicious")
        benign_total += int(gold == "benign")
        true_positive += int(gold == "malicious" and verdict == "malicious")
        false_positive += int(gold == "benign" and verdict == "malicious")
        if verdict == "suspicious":
            review += 1
        else:
            decided += 1
            correct += int(verdict == gold)
    return {
        "dataset_total": len(validation_rows),
        "available_outputs": available,
        "coverage": safe_div(available, len(validation_rows)),
        "decided_accuracy": safe_div(correct, decided),
        "malicious_recall": safe_div(true_positive, malicious_total),
        "benign_false_positive_rate": safe_div(false_positive, benign_total),
        "review_rate": safe_div(review, available),
        "latency_p95_ms": percentile(latencies, 0.95),
        "correct": correct,
        "decided": decided,
        "review": review,
    }


def _gold_compare_experiment_metrics(
    experiment: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    gold_path = (
        Path(clean(manifest.get("suite_dir")))
        / "layer1_model"
        / "expert_gold_holdout.jsonl"
    )
    run_dirs = [
        Path(clean(item.get("run_data_dir")))
        for item in experiment.get("variants") or []
        if clean(item.get("run_data_dir"))
    ]
    if not gold_path.exists() or not run_dirs:
        return {
            "gold_total": 0,
            "channels": {},
            "metric_policy": "仅专家金标参与四路对照。",
        }
    rows = []
    for row in read_jsonl(gold_path):
        expected = row.get("expected") or {}
        rows.append(
            {
                "_row_id": clean(row.get("id")).upper(),
                "_gold_label": clean(expected.get("verdict")).lower(),
                "label_tier": row.get("label_tier"),
                "annotation_status": row.get("annotation_status"),
                "intended_use": row.get("intended_use"),
            }
        )
    rows = [row for row in rows if official_gold_row(row)]
    reports_list: list[dict[str, Any]] = []
    for run_dir in dict.fromkeys(run_dirs):
        reports_list.extend(load_reports(run_dir))
    report_index = latest_report_index(reports_list)
    channels = {
        "pipeline_final": _score_report_channel(rows, report_index, "pipeline_final"),
        "model_a": _score_report_channel(rows, report_index, "model_a"),
        "model_b": _score_report_channel(rows, report_index, "model_b"),
        "xgboost": _score_report_channel(rows, report_index, "xgboost"),
    }
    return {
        "gold_total": len(rows),
        "formal_reports": len(report_index),
        "channels": channels,
        "metric_policy": (
            "同一冻结专家金标、同一输入快照比较最终融合、模型甲单方、"
            "模型乙单方与XGBoost；来源参考标签不进入分母。"
        ),
    }


def collect_five_layer_experiments(
    manifest: dict[str, Any], data_dir: Path
) -> dict[str, Any]:
    suite_id = clean(manifest.get("suite_id"))
    model_release = _workflow_experiment(
        data_dir=data_dir,
        suite_id=suite_id,
        action="model_release",
        expected_variants=1,
    )
    model_resume = _workflow_experiment(
        data_dir=data_dir,
        suite_id=suite_id,
        action="complete_release",
        expected_variants=1,
    )
    model_candidates = [model_release, model_resume]
    model_release = max(
        model_candidates,
        key=lambda item: (
            sum(
                int(variant.get("completed_samples") or 0)
                for variant in item.get("variants") or []
            ),
            clean(item.get("created_at")),
        ),
    )
    model_release.update(_model_release_experiment_metrics(model_release, manifest))
    gold_compare = _workflow_experiment(
        data_dir=data_dir,
        suite_id=suite_id,
        action="gold_compare",
        expected_variants=1,
    )
    gold_compare.update(_gold_compare_experiment_metrics(gold_compare, manifest))
    rag = _workflow_experiment(
        data_dir=data_dir,
        suite_id=suite_id,
        action="rag_compare",
        expected_variants=3,
    )
    agent = _workflow_experiment(
        data_dir=data_dir,
        suite_id=suite_id,
        action="agent_ablation",
        expected_variants=5,
    )
    recovery = _workflow_experiment(
        data_dir=data_dir,
        suite_id=suite_id,
        action="production_reliability",
        expected_variants=2,
    )
    recovery.update(_agent_recovery_metrics(recovery))
    return {
        "model_release": model_release,
        "gold_compare": gold_compare,
        "rag_compare": rag,
        "agent_ablation": agent,
        "recovery": recovery,
    }


def suite_readiness(
    manifest: dict[str, Any], experiments: dict[str, Any] | None = None
) -> dict[str, Any]:
    suite_dir = Path(clean(manifest.get("suite_dir")))
    baselines = read_json(
        (suite_dir / "baseline_scorecards.json").read_text(encoding="utf-8"),
        {},
    )
    inventory = read_json(
        (suite_dir / "source_inventory.json").read_text(encoding="utf-8"),
        {},
    )
    release_total = int((manifest.get("selection") or {}).get("release_holdout_count") or 0)
    release_label_pending = int(
        (manifest.get("selection") or {}).get(
            "strict_source_reference_requires_expert_review"
        )
        or 0
    )
    layer2 = baselines.get("layer2_rag") or {}
    graph = inventory.get("rag") or {}
    layer3 = baselines.get("layer3_agent") or {}
    layer4 = (baselines.get("layer4_e2e") or {}).get("release_holdout") or {}
    layer5 = baselines.get("layer5_production") or {}
    experiments = experiments or {}
    rag_experiment = experiments.get("rag_compare") or {}
    agent_experiment = experiments.get("agent_ablation") or {}
    recovery_experiment = experiments.get("recovery") or {}
    model_experiment = experiments.get("model_release") or {}
    strict_channels = model_experiment.get("reference_channels") or {}
    strict_pipeline = strict_channels.get("pipeline_final") or {}
    strict_model_a = strict_channels.get("model_a") or {}
    strict_model_b = strict_channels.get("model_b") or {}
    strict_xgboost = strict_channels.get("xgboost") or {}
    official_total = int(
        (manifest.get("selection") or {}).get("expert_gold_holdout_count")
        or (manifest.get("selection") or {}).get("frozen_gold_release_count")
        or (
            release_total
            if not int(
                (manifest.get("selection") or {}).get(
                    "strict_source_reference_extension_count"
                )
                or 0
            )
            else 0
        )
    )
    rag_scorecard_path = suite_dir / "layer2_rag" / "rag_scorecard.json"
    rag_scorecard = (
        read_json(rag_scorecard_path.read_text(encoding="utf-8"), {})
        if rag_scorecard_path.exists()
        else {}
    )
    rag_metrics = rag_scorecard.get("metrics") or {}
    approved_queries = int(rag_scorecard.get("approved_rows") or 0)

    readiness = {
        "layer1_model": {
            "status": (
                "ready"
                if release_total
                and all(
                    channel.get("available_outputs") == release_total
                    for channel in (
                        strict_pipeline,
                        strict_model_a,
                        strict_model_b,
                        strict_xgboost,
                    )
                )
                and model_experiment.get("status") == "completed"
                else "partial"
            ),
            "reason": (
                f"严格集全量参考口径{release_total}条（专家金标{official_total}条、"
                f"来源参考{release_label_pending}条）；全量输出最终融合/甲/乙/XGBoost "
                f"{strict_pipeline.get('available_outputs', 0)}/"
                f"{strict_model_a.get('available_outputs', 0)}/"
                f"{strict_model_b.get('available_outputs', 0)}/"
                f"{strict_xgboost.get('available_outputs', 0)}条。"
                f"全部{release_total}条均计算参考准确率；其中{release_label_pending}条"
                "尚待双专家复核，专家金标子集另行保留。"
            ),
        },
        "layer2_rag": {
            "status": (
                "ready"
                if graph.get("graph_nodes")
                and approved_queries >= 100
                and rag_metrics.get("recall_at_5") is not None
                and rag_metrics.get("recall_at_5") >= 0.90
                and rag_metrics.get("evidence_faithfulness_rate") is not None
                and rag_metrics.get("evidence_faithfulness_rate") >= 0.98
                and rag_metrics.get("hallucination_rate") is not None
                and rag_metrics.get("hallucination_rate") <= 0.01
                and rag_experiment.get("status") == "completed"
                else "blocked"
            ),
            "reason": (
                f"图谱节点{graph.get('graph_nodes', 0)}；专家批准{approved_queries}条；"
                f"RAG三变体{rag_experiment.get('completed_variants', 0)}/3完成"
                f"、失败{rag_experiment.get('failed_variants', 0)}个。"
            ),
        },
        "layer3_agent": {
            "status": (
                "ready"
                if agent_experiment.get("status") == "completed"
                and recovery_experiment.get("restart_recovery_rate") is not None
                and recovery_experiment.get("restart_recovery_rate") >= 0.95
                else "blocked"
                if agent_experiment.get("status") == "failed"
                or recovery_experiment.get("status") == "failed"
                else "partial"
            ),
            "reason": (
                f"消融{agent_experiment.get('completed_variants', 0)}/5完成、"
                f"失败{agent_experiment.get('failed_variants', 0)}个；"
                f"断点恢复率{recovery_experiment.get('restart_recovery_rate')}。"
            ),
        },
        "layer4_e2e": {
            "status": "ready" if layer4.get("coverage") == 1.0 else "partial",
            "reason": (
                f"严格未见集覆盖率{layer4.get('coverage')}; "
                f"待研判{layer4.get('pending_total')}条。"
            ),
        },
        "layer5_production": {
            "status": (
                "ready"
                if layer5.get("human_review_count")
                and not (layer5.get("batch_job_status") or {}).get("running")
                else "partial"
            ),
            "reason": (
                f"人工复核{layer5.get('human_review_count', 0)}条；"
                f"批任务状态{layer5.get('batch_job_status') or {}}。"
            ),
        },
    }
    return {
        "overall_status": (
            "ready"
            if all(value["status"] == "ready" for value in readiness.values())
            else "blocked"
            if any(value["status"] == "blocked" for value in readiness.values())
            else "partial"
        ),
        "layers": readiness,
    }


def five_layer_test_results(
    manifest: dict[str, Any],
    readiness: dict[str, Any] | None = None,
    experiments: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return UI-ready measured results without mixing diagnostic and release sets."""
    if not manifest:
        return {}
    suite_dir = Path(clean(manifest.get("suite_dir")))
    baselines_path = suite_dir / "baseline_scorecards.json"
    if not baselines_path.exists():
        return {}
    baselines = read_json(baselines_path.read_text(encoding="utf-8"), {})
    validation_path = suite_dir / "suite_validation.json"
    validation = (
        read_json(validation_path.read_text(encoding="utf-8"), {})
        if validation_path.exists()
        else validate_five_layer_suite(suite_dir)
    )
    experiments = experiments or {}
    readiness = readiness or suite_readiness(manifest, experiments)
    layer_status = readiness.get("layers") or {}
    counts = manifest.get("dataset_counts") or {}
    release_total = int((manifest.get("selection") or {}).get("release_holdout_count") or 0)
    selection = manifest.get("selection") or {}

    layer1 = (baselines.get("layer1_model") or {}).get("release_holdout") or {}
    model_a = layer1.get("model_a") or {}
    model_b = layer1.get("model_b") or {}
    layer2 = baselines.get("layer2_rag") or {}
    layer3 = baselines.get("layer3_agent") or {}
    layer4 = (baselines.get("layer4_e2e") or {}).get("release_holdout") or {}
    layer5 = baselines.get("layer5_production") or {}
    rag_experiment = experiments.get("rag_compare") or {}
    agent_experiment = experiments.get("agent_ablation") or {}
    recovery_experiment = experiments.get("recovery") or {}
    model_experiment = experiments.get("model_release") or {}
    gold_experiment = experiments.get("gold_compare") or {}
    formal_model_a = model_experiment.get("model_a") or {}
    formal_model_b = model_experiment.get("model_b") or {}
    strict_channels = model_experiment.get("reference_channels") or {}
    combined_diagnostic = model_experiment.get("combined_diagnostic") or {}
    strict_model_a = (
        strict_channels.get("model_a")
        or combined_diagnostic.get("model_a")
        or formal_model_a
    )
    strict_model_b = (
        strict_channels.get("model_b")
        or combined_diagnostic.get("model_b")
        or formal_model_b
    )
    provisional = model_experiment.get("provisional_source_reference") or {}
    provisional_model_a = provisional.get("model_a") or {}
    provisional_model_b = provisional.get("model_b") or {}
    gold_channels = gold_experiment.get("channels") or {}
    rag_scorecard_path = suite_dir / "layer2_rag" / "rag_scorecard.json"
    rag_scorecard = (
        read_json(rag_scorecard_path.read_text(encoding="utf-8"), {})
        if rag_scorecard_path.exists()
        else {}
    )
    rag_metrics = rag_scorecard.get("metrics") or {}
    silver_metrics = rag_scorecard.get("silver_metrics") or {}

    results = {
        "layer1_model": {
            "name": LAYER_DEFINITIONS["layer1_model"]["name"],
            "scope": "严格训练未见集",
            "sample_total": release_total,
            "status": (layer_status.get("layer1_model") or {}).get("status", "partial"),
            "metrics": {
                "historical_model_a_outputs": int(
                    model_a.get("available_outputs") or 0
                ),
                "historical_model_b_outputs": int(
                    model_b.get("available_outputs") or 0
                ),
                "historical_model_a_accuracy": model_a.get("decided_accuracy"),
                "historical_model_b_accuracy": model_b.get("decided_accuracy"),
                "model_a_outputs": int(
                    strict_model_a.get("available_outputs") or 0
                ),
                "model_a_coverage": safe_div(
                    int(strict_model_a.get("available_outputs") or 0), release_total
                ),
                "model_a_decided_accuracy": strict_model_a.get("decided_accuracy"),
                "model_a_malicious_recall": strict_model_a.get("malicious_recall"),
                "model_a_false_positive_rate": strict_model_a.get(
                    "benign_false_positive_rate"
                ),
                "model_a_review_rate": strict_model_a.get("review_rate"),
                "model_b_outputs": int(
                    strict_model_b.get("available_outputs") or 0
                ),
                "model_b_coverage": safe_div(
                    int(strict_model_b.get("available_outputs") or 0), release_total
                ),
                "model_b_decided_accuracy": strict_model_b.get("decided_accuracy"),
                "model_b_malicious_recall": strict_model_b.get("malicious_recall"),
                "model_b_false_positive_rate": strict_model_b.get(
                    "benign_false_positive_rate"
                ),
                "model_b_review_rate": strict_model_b.get("review_rate"),
                "model_release_status": model_experiment.get("status", "not_run"),
                "model_release_completed": sum(
                    int(item.get("completed_samples") or 0)
                    for item in model_experiment.get("variants") or []
                ),
                "model_release_failed": sum(
                    int(item.get("failed_samples") or 0)
                    for item in model_experiment.get("variants") or []
                ),
                "model_release_failure_reason": model_experiment.get(
                    "failure_reason"
                ),
                "strict_reference_total": int(
                    model_experiment.get("reference_total") or release_total
                ),
                "strict_reference_channels": strict_channels,
                "official_metric_policy": model_experiment.get(
                    "reference_metric_policy"
                )
                or "严格集全部样本按现有参考标签计算；专家金标子集另行保留。",
                "provisional_model_a_outputs": int(
                    provisional_model_a.get("available_outputs") or 0
                ),
                "provisional_model_a_agreement": provisional_model_a.get(
                    "decided_accuracy"
                ),
                "provisional_model_b_outputs": int(
                    provisional_model_b.get("available_outputs") or 0
                ),
                "provisional_model_b_agreement": provisional_model_b.get(
                    "decided_accuracy"
                ),
                "gold_compare_status": gold_experiment.get("status", "not_run"),
                "gold_compare_total": int(gold_experiment.get("gold_total") or 0),
                "gold_compare_completed": sum(
                    int(item.get("completed_samples") or 0)
                    for item in gold_experiment.get("variants") or []
                ),
                "gold_compare_channels": gold_channels,
                "frozen_gold_release_count": int(
                    selection.get("frozen_gold_release_count") or 0
                ),
                "base_frozen_gold_count": int(
                    selection.get("base_frozen_gold_count")
                    or selection.get("frozen_gold_release_count")
                    or 0
                ),
                "approved_expansion_gold_count": int(
                    selection.get("approved_expansion_gold_count") or 0
                ),
                "strict_extension_count": int(
                    selection.get("strict_source_reference_extension_count") or 0
                ),
                "strict_extension_review_pending": int(
                    selection.get(
                        "strict_source_reference_requires_expert_review"
                    )
                    or 0
                ),
            },
            "note": (
                "严格集全部样本均参与全量参考准确率、召回率和误报率计算；"
                "专家金标子集同时保留，便于区分专家口径与来源参考口径。"
            ),
        },
        "layer2_rag": {
            "name": LAYER_DEFINITIONS["layer2_rag"]["name"],
            "scope": "历史回放＋专家检索集",
            "sample_total": int(
                ((counts.get("layer2_rag") or {}).get("rag_retrieval_eval")) or 0
            ),
            "status": (layer_status.get("layer2_rag") or {}).get("status", "blocked"),
            "metrics": {
                "rag_enabled_reports": int(layer2.get("rag_enabled_reports") or 0),
                "nonempty_retrieval_rate": layer2.get("nonempty_retrieval_rate"),
                "average_retrieved_documents": layer2.get(
                    "average_retrieved_documents"
                ),
                "evidence_review_count": int(
                    rag_scorecard.get("evidence_review_count") or 0
                ),
                "approved_queries": int(rag_scorecard.get("approved_rows") or 0),
                "recall_at_5": rag_metrics.get("recall_at_5"),
                "mrr": rag_metrics.get("mrr"),
                "ndcg_at_10": rag_metrics.get("ndcg_at_10"),
                "context_precision": rag_metrics.get("context_precision"),
                "evidence_faithfulness_rate": rag_metrics.get(
                    "evidence_faithfulness_rate"
                ),
                "hallucination_rate": rag_metrics.get("hallucination_rate"),
                "silver_prelabel_rows": int(
                    rag_scorecard.get("silver_prelabel_rows") or 0
                ),
                "silver_recall_at_5": silver_metrics.get("recall_at_5"),
                "silver_mrr": silver_metrics.get("mrr"),
                "silver_ndcg_at_10": silver_metrics.get("ndcg_at_10"),
                "rag_comparison_status": rag_experiment.get("status", "not_run"),
                "rag_variants_completed": int(
                    rag_experiment.get("completed_variants") or 0
                ),
                "rag_variants_failed": int(
                    rag_experiment.get("failed_variants") or 0
                ),
                "rag_experiment_failure_reason": rag_experiment.get(
                    "failure_reason"
                ),
            },
            "note": "银标指标仅用于发现检索问题；只有专家批准指标进入发布门禁。",
        },
        "layer3_agent": {
            "name": LAYER_DEFINITIONS["layer3_agent"]["name"],
            "scope": "已保存轨迹＋五变体消融",
            "sample_total": int(
                ((counts.get("layer3_agent") or {}).get("agent_trace_eval")) or 0
            ),
            "status": (layer_status.get("layer3_agent") or {}).get("status", "partial"),
            "metrics": {
                "reports_with_saved_output": int(
                    layer3.get("reports_with_saved_output") or 0
                ),
                "trace_coverage": layer3.get("trace_coverage"),
                "agent_schema_success_rate": layer3.get(
                    "agent_schema_success_rate"
                ),
                "agent_failure_rate": layer3.get("agent_failure_rate"),
                "agent_timeout_rate": layer3.get("agent_timeout_rate"),
                "ablation_status": agent_experiment.get("status", "not_run"),
                "ablation_variants_completed": int(
                    agent_experiment.get("completed_variants") or 0
                ),
                "ablation_variants_failed": int(
                    agent_experiment.get("failed_variants") or 0
                ),
                "ablation_failure_reason": agent_experiment.get("failure_reason"),
                "restart_recovery_rate": recovery_experiment.get(
                    "restart_recovery_rate"
                ),
                "restart_attempts": int(
                    recovery_experiment.get("restart_attempts") or 0
                ),
                "restart_recovered": int(
                    recovery_experiment.get("restart_recovered") or 0
                ),
                "idempotent_replay_skipped": int(
                    recovery_experiment.get("idempotent_replay_skipped") or 0
                ),
                "recovery_status": recovery_experiment.get("status", "not_run"),
                "recovery_failure_reason": recovery_experiment.get(
                    "failure_reason"
                ),
            },
            "note": "卡片分别展示历史轨迹基线、五变体消融和故障恢复；实验失败不会计为完成。",
        },
        "layer4_e2e": {
            "name": LAYER_DEFINITIONS["layer4_e2e"]["name"],
            "scope": "严格训练未见端到端集",
            "sample_total": int(layer4.get("dataset_total") or release_total),
            "status": (layer_status.get("layer4_e2e") or {}).get("status", "partial"),
            "metrics": {
                "evaluated_total": int(layer4.get("evaluated_total") or 0),
                "pending_total": int(layer4.get("pending_total") or 0),
                "coverage": layer4.get("coverage"),
                "decided_accuracy": layer4.get("decided_accuracy"),
                "malicious_recall": layer4.get("malicious_recall"),
                "benign_false_positive_rate": layer4.get(
                    "benign_false_positive_rate"
                ),
                "macro_f1": layer4.get("macro_f1"),
                "latency_p50_ms": (layer4.get("latency_ms") or {}).get("p50"),
                "latency_p95_ms": (layer4.get("latency_ms") or {}).get("p95"),
            },
            "note": "未完成样本不能从分母删除；覆盖率达到100%后才判断发布质量。",
        },
        "layer5_production": {
            "name": LAYER_DEFINITIONS["layer5_production"]["name"],
            "scope": "生产回放＋可靠性场景",
            "sample_total": int(
                ((counts.get("layer5_production") or {}).get("production_replay_eval"))
                or 0
            ),
            "status": (layer_status.get("layer5_production") or {}).get(
                "status", "partial"
            ),
            "metrics": {
                "saved_reports": int(layer5.get("saved_reports") or 0),
                "validation_coverage": layer5.get("validation_coverage"),
                "latency_p50_ms": (layer5.get("latency_ms") or {}).get("p50"),
                "latency_p95_ms": (layer5.get("latency_ms") or {}).get("p95"),
                "model_unavailable_rate": layer5.get(
                    "model_unavailable_report_rate"
                ),
                "agent_degraded_rate": layer5.get("agent_degraded_report_rate"),
                "human_review_count": int(layer5.get("human_review_count") or 0),
                "human_override_rate": layer5.get("human_override_rate"),
                "batch_job_status": layer5.get("batch_job_status") or {},
            },
            "note": "生产门禁还需故障场景实跑、吞吐时间窗和人工复核分母。",
        },
    }
    return {
        "suite_id": manifest.get("suite_id"),
        "generated_at": now_iso(),
        "suite_validation": {
            "passed": bool(validation.get("passed")),
            "checks_total": int(validation.get("checks_total") or 0),
            "checks_passed": int(validation.get("checks_passed") or 0),
            "checks_failed": int(validation.get("checks_failed") or 0),
        },
        "layers": results,
    }


def latest_suite(
    *,
    data_dir: Path | None = None,
    output_root: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    root = output_root.resolve() if output_root else data_dir / "evaluation" / "five_layer"
    path = root / "latest.json"
    if not path.exists():
        return {}
    return read_json(path.read_text(encoding="utf-8"), {})


def list_five_layer_suites(
    *,
    data_dir: Path | None = None,
    output_root: Path | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Return persisted suites, newest first, with durable result counts."""
    data_dir = (data_dir or resolve_data_dir()).resolve()
    root = output_root.resolve() if output_root else data_dir / "evaluation" / "five_layer"
    latest_id = clean(latest_suite(data_dir=data_dir, output_root=root).get("suite_id"))
    run_root = data_dir / "evaluation" / "five_layer_runs"
    suites: list[dict[str, Any]] = []
    if not root.exists():
        return suites
    for suite_dir in root.iterdir():
        manifest_path = suite_dir / "manifest.json"
        if not suite_dir.is_dir() or not manifest_path.exists():
            continue
        manifest = read_json(manifest_path.read_text(encoding="utf-8"), {})
        if not isinstance(manifest, dict):
            continue
        suite_id = clean(manifest.get("suite_id")) or suite_dir.name
        completed = failed = run_count = 0
        latest_activity = manifest_path.stat().st_mtime
        if run_root.exists():
            for run_dir in run_root.glob(f"{suite_id}-*"):
                if not run_dir.is_dir():
                    continue
                durable = [
                    run_dir / "checkpoint.json",
                    run_dir / "result.json",
                    run_dir / "scorecard.json",
                ]
                existing = [path for path in durable if path.exists()]
                if not existing:
                    continue
                run_count += 1
                latest_activity = max(
                    latest_activity, *(path.stat().st_mtime for path in existing)
                )
                checkpoint_path = run_dir / "checkpoint.json"
                checkpoint = (
                    read_json(checkpoint_path.read_text(encoding="utf-8"), {})
                    if checkpoint_path.exists()
                    else {}
                )
                for item in (checkpoint.get("items") or {}).values():
                    if not isinstance(item, dict):
                        continue
                    completed += int(item.get("status") == "completed")
                    failed += int(item.get("status") == "failed")
        suites.append(
            {
                "suite_id": suite_id,
                "created_at": manifest.get("created_at"),
                "status": manifest.get("status"),
                "suite_dir": str(suite_dir),
                "is_latest": suite_id == latest_id,
                "run_count": run_count,
                "completed_executions": completed,
                "failed_executions": failed,
                "has_results": bool(run_count or completed or failed),
                "latest_activity": datetime.fromtimestamp(
                    latest_activity, tz=timezone.utc
                ).isoformat(),
                "dataset_counts": manifest.get("dataset_counts") or {},
                "selection": manifest.get("selection") or {},
            }
        )
    suites.sort(
        key=lambda item: clean(item.get("created_at")) or clean(item.get("latest_activity")),
        reverse=True,
    )
    return suites[: max(1, int(limit))]


def selected_five_layer_suite(
    suite_id: str = "",
    *,
    data_dir: Path | None = None,
    output_root: Path | None = None,
) -> dict[str, Any]:
    """Load an exact persisted suite, falling back to the latest suite."""
    data_dir = (data_dir or resolve_data_dir()).resolve()
    root = output_root.resolve() if output_root else data_dir / "evaluation" / "five_layer"
    requested = clean(suite_id)
    if requested and root.exists():
        for suite_dir in root.iterdir():
            if not suite_dir.is_dir() or suite_dir.name != requested:
                continue
            manifest_path = suite_dir / "manifest.json"
            if manifest_path.exists():
                manifest = read_json(manifest_path.read_text(encoding="utf-8"), {})
                if isinstance(manifest, dict):
                    return manifest
    return latest_suite(data_dir=data_dir, output_root=root)


def list_rag_annotations(
    *,
    data_dir: Path | None = None,
    status: str = "pending",
    limit: int = 20,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    manifest = latest_suite(data_dir=data_dir)
    if not manifest:
        return {"suite_id": None, "counts": {}, "items": []}
    dataset = (
        Path(clean(manifest.get("suite_dir")))
        / "layer2_rag"
        / "rag_retrieval_eval.jsonl"
    )
    rows = read_jsonl(dataset) if dataset.exists() else []
    counts = Counter(
        clean(row.get("annotation_status")) or "needs_expert_review" for row in rows
    )
    normalized_status = clean(status).lower()
    if normalized_status in {"pending", "needs_expert_review"}:
        selected = [
            row
            for row in rows
            if clean(row.get("annotation_status")).lower()
            not in {"approved", "adjudicated"}
        ]
    elif normalized_status in {"approved", "adjudicated"}:
        selected = [
            row
            for row in rows
            if clean(row.get("annotation_status")).lower() == normalized_status
        ]
    else:
        selected = rows
    output = []
    for row in selected[: max(1, min(int(limit), 100))]:
        output.append(
            {
                "id": row.get("id"),
                "query": row.get("query"),
                "retrieved_doc_ids": row.get("retrieved_doc_ids") or [],
                "retrieved_items": [
                    {
                        "doc_id": item.get("doc_id"),
                        "title": item.get("title"),
                        "source_type": item.get("source_type"),
                        "content": clean(item.get("content"))[:600],
                        "similarity": item.get("similarity"),
                    }
                    for item in row.get("retrieved_items") or []
                    if isinstance(item, dict)
                ][:10],
                "weak_relevant_doc_ids": row.get("weak_relevant_doc_ids") or [],
                "weak_hard_negative_doc_ids": row.get(
                    "weak_hard_negative_doc_ids"
                )
                or [],
                "relevant_doc_ids": row.get("relevant_doc_ids") or [],
                "hard_negative_doc_ids": row.get("hard_negative_doc_ids") or [],
                "annotation_status": row.get("annotation_status"),
                "reviewer": row.get("reviewer"),
                "review_notes": row.get("review_notes"),
                "no_relevant_document": bool(row.get("no_relevant_document")),
                "evidence_supported": row.get("evidence_supported"),
                "hallucination": row.get("hallucination"),
                "wrong_evidence": bool(row.get("wrong_evidence")),
                "missing_evidence": bool(row.get("missing_evidence")),
            }
        )
    return {
        "suite_id": manifest.get("suite_id"),
        "dataset": str(dataset),
        "total": len(rows),
        "counts": dict(counts),
        "items": output,
    }


def save_rag_annotation(
    *,
    sample_id: str,
    relevant_doc_ids: list[str],
    hard_negative_doc_ids: list[str],
    annotation_status: str,
    reviewer: str = "",
    review_notes: str = "",
    no_relevant_document: bool = False,
    evidence_supported: bool | None = None,
    hallucination: bool | None = None,
    wrong_evidence: bool = False,
    missing_evidence: bool = False,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    manifest = latest_suite(data_dir=data_dir)
    if not manifest:
        raise RuntimeError("请先生成五层评测套件。")
    dataset = (
        Path(clean(manifest.get("suite_dir")))
        / "layer2_rag"
        / "rag_retrieval_eval.jsonl"
    )
    normalized_id = clean(sample_id).upper()
    normalized_status = clean(annotation_status).lower()
    if normalized_status not in {
        "needs_expert_review",
        "approved",
        "adjudicated",
    }:
        raise ValueError(
            "annotation_status must be needs_expert_review, approved or adjudicated"
        )
    relevant = list(
        dict.fromkeys(clean(value) for value in relevant_doc_ids if clean(value))
    )
    hard_negative = list(
        dict.fromkeys(
            clean(value) for value in hard_negative_doc_ids if clean(value)
        )
    )
    overlap = set(relevant).intersection(hard_negative)
    if overlap:
        raise ValueError(
            "同一文档不能同时标为相关和困难负例：" + "、".join(sorted(overlap))
        )
    if normalized_status in {"approved", "adjudicated"} and not (
        relevant or no_relevant_document
    ):
        raise ValueError("批准标注前必须选择相关文档，或明确勾选“无相关文档”。")
    if normalized_status in {"approved", "adjudicated"} and (
        not isinstance(evidence_supported, bool)
        or not isinstance(hallucination, bool)
    ):
        raise ValueError("批准标注前必须填写证据是否支持结论以及是否存在幻觉。")

    with RAG_ANNOTATION_LOCK:
        rows = read_jsonl(dataset)
        matched = False
        for row in rows:
            if clean(row.get("id")).upper() != normalized_id:
                continue
            row["relevant_doc_ids"] = relevant
            row["hard_negative_doc_ids"] = hard_negative
            row["annotation_status"] = normalized_status
            row["reviewer"] = clean(reviewer)
            row["review_notes"] = clean(review_notes)
            row["no_relevant_document"] = bool(no_relevant_document)
            row["evidence_supported"] = evidence_supported
            row["hallucination"] = hallucination
            row["wrong_evidence"] = bool(wrong_evidence)
            row["missing_evidence"] = bool(missing_evidence)
            row["reviewed_at"] = now_iso()
            matched = True
            break
        if not matched:
            raise FileNotFoundError(f"RAG annotation item not found: {sample_id}")
        temporary = dataset.with_suffix(".jsonl.tmp")
        write_jsonl(temporary, rows)
        os.replace(temporary, dataset)
        scorecard = build_rag_retrieval_scorecard(dataset)
        write_json(dataset.parent / "rag_scorecard.json", scorecard)
    return {
        "saved": True,
        "suite_id": manifest.get("suite_id"),
        "sample_id": normalized_id,
        "annotation_status": normalized_status,
        "relevant_doc_ids": relevant,
        "hard_negative_doc_ids": hard_negative,
        "no_relevant_document": bool(no_relevant_document),
        "evidence_supported": evidence_supported,
        "hallucination": hallucination,
        "wrong_evidence": bool(wrong_evidence),
        "missing_evidence": bool(missing_evidence),
        "scorecard": scorecard,
    }


def five_layer_overview(
    *,
    validation_csv: Path = DEFAULT_VALIDATION_CSV,
    data_dir: Path | None = None,
    suite_id: str = "",
) -> dict[str, Any]:
    data_dir = (data_dir or resolve_data_dir()).resolve()
    manifest = selected_five_layer_suite(suite_id, data_dir=data_dir)
    history = list_five_layer_suites(data_dir=data_dir)
    experiments = collect_five_layer_experiments(manifest, data_dir) if manifest else {}
    readiness = suite_readiness(manifest, experiments) if manifest else {}
    return {
        "generated_at": now_iso(),
        "suite_version": SUITE_VERSION,
        "layers": LAYER_DEFINITIONS,
        "release_gates": RELEASE_GATES,
        "latest_suite": manifest,
        "selected_suite_id": manifest.get("suite_id") if manifest else None,
        "suite_history": history,
        "readiness": readiness,
        "test_results": (
            five_layer_test_results(manifest, readiness, experiments) if manifest else {}
        ),
        "experiments": experiments,
        "current_end_to_end": build_scorecard(validation_csv.resolve(), data_dir),
    }
