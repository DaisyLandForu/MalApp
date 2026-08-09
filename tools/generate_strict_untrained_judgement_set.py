from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
MD5_RE = re.compile(r"^[0-9A-F]{32}$")
MD5_IN_TEXT_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])")
LABEL_KEYS = {
    "candidate_label",
    "gold_label",
    "human_label",
    "is_correct",
    "is_malicious",
    "label",
    "label_source",
    "manual_label",
    "raw_label",
    "reference_label",
    "target",
    "verdict",
    "weak_label",
}


def clean(value: Any) -> str:
    return str(value or "").strip()


def normalize_md5(value: Any) -> str:
    value = clean(value).upper()
    return value if MD5_RE.fullmatch(value) else ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def report_path(path: Path, *, root: Path = ROOT, data_dir: Path | None = None) -> str:
    """Return a portable path without persisting a possibly mis-decoded user name."""
    resolved = path.resolve()
    try:
        return "workspace://" + resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        pass
    if data_dir is not None:
        try:
            return "malapp-data://" + resolved.relative_to(data_dir.resolve()).as_posix()
        except ValueError:
            pass
    return path.name


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            count += 1
    return count


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                rows.append(value)
    return rows


def row_md5(row: dict[str, Any]) -> str:
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    input_row = row.get("input") if isinstance(row.get("input"), dict) else {}
    return normalize_md5(
        row.get("md5")
        or row.get("sample_id")
        or row.get("id")
        or metadata.get("md5")
        or input_row.get("md5")
        or input_row.get("sample_id")
    )


def jsonl_ids(path: Path) -> tuple[set[str], int, int]:
    identifiers: set[str] = set()
    rows = 0
    invalid = 0
    if not path.exists():
        return identifiers, rows, invalid
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            rows += 1
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                invalid += 1
                continue
            if isinstance(row, dict):
                sample_id = row_md5(row)
                if sample_id:
                    identifiers.add(sample_id)
    return identifiers, rows, invalid


def nested_md5_ids(value: Any, *, key: str = "") -> set[str]:
    identifiers: set[str] = set()
    if isinstance(value, dict):
        for child_key, child in value.items():
            identifiers.update(nested_md5_ids(child, key=str(child_key).lower()))
    elif isinstance(value, list):
        for child in value:
            identifiers.update(nested_md5_ids(child, key=key))
    elif key in {"md5", "sample_id", "sample_md5"}:
        sample_id = normalize_md5(value)
        if sample_id:
            identifiers.add(sample_id)
    return identifiers


def training_loop_export_ids(root: Path) -> tuple[set[str], list[dict[str, Any]]]:
    identifiers: set[str] = set()
    inventory: list[dict[str, Any]] = []
    exports = root / "data" / "exports"
    if not exports.exists():
        return identifiers, inventory
    for path in sorted(exports.rglob("*.jsonl")):
        path_ids: set[str] = set()
        rows = 0
        invalid = 0
        with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
            for line in handle:
                if not line.strip():
                    continue
                rows += 1
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    invalid += 1
                    continue
                path_ids.update(nested_md5_ids(row))
        identifiers.update(path_ids)
        inventory.append(
            {
                "path": report_path(path, root=root),
                "rows": rows,
                "invalid_json": invalid,
                "unique_md5_ids": len(path_ids),
            }
        )
    return identifiers, inventory


def readonly_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    return bool(
        conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
    )


def db_split_ids(path: Path, table: str, splits: tuple[str, ...]) -> set[str]:
    if not path.exists():
        return set()
    conn = readonly_connection(path)
    try:
        if not table_exists(conn, table):
            return set()
        placeholders = ",".join("?" for _ in splits)
        return {
            sample_id
            for (value,) in conn.execute(
                f"SELECT DISTINCT md5 FROM [{table}] "
                f"WHERE split IN ({placeholders}) AND md5 IS NOT NULL",
                splits,
            )
            if (sample_id := normalize_md5(value))
        }
    finally:
        conn.close()


def load_validation_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        rows = list(csv.DictReader(handle))
    for row in rows:
        row["_md5"] = normalize_md5(row.get("md5") or row.get("id"))
    return [row for row in rows if row["_md5"]]


def find_latest_suite(data_dir: Path) -> Path | None:
    base = data_dir / "evaluation" / "five_layer"
    latest_path = base / "latest.json"
    if latest_path.exists():
        try:
            latest = json.loads(latest_path.read_text(encoding="utf-8"))
            suite = Path(clean(latest.get("suite_dir")))
            if suite.is_dir():
                return suite
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    suites = [path for path in base.iterdir() if path.is_dir()] if base.exists() else []
    return max(suites, key=lambda path: path.stat().st_mtime) if suites else None


def canonical_training_sources(root: Path) -> tuple[dict[str, set[str]], dict[str, Any]]:
    sources: dict[str, set[str]] = {}
    inventory: dict[str, Any] = {}

    jsonl_paths = {
        "general_dataset_train": root / "data" / "datasets" / "train.jsonl",
        "agent_sft_business_label_train": root
        / "training_artifacts"
        / "sft"
        / "business_label"
        / "train.jsonl",
        "agent_sft_impersonation_train": root
        / "training_artifacts"
        / "sft"
        / "impersonation"
        / "train.jsonl",
        "agent_sft_static_analysis_train": root
        / "training_artifacts"
        / "sft"
        / "static_analysis"
        / "train.jsonl",
        "agent_sft_threat_intel_train": root
        / "training_artifacts"
        / "sft"
        / "threat_intel"
        / "train.jsonl",
    }
    for stage, path in jsonl_paths.items():
        identifiers, rows, invalid = jsonl_ids(path)
        sources[stage] = identifiers
        inventory[stage] = {
            "path": report_path(path, root=root),
            "rows": rows,
            "unique_ids": len(identifiers),
            "invalid_json": invalid,
            "sha256": sha256_file(path) if path.exists() else "",
        }

    db_sources = {
        "unified_supervised_train": (
            root / "training_artifacts" / "training_dataset.db",
            "unified_samples",
            ("train",),
        ),
        "evidence_block_train": (
            root / "training_artifacts" / "training_dataset.db",
            "evidence_blocks",
            ("train",),
        ),
        "legacy_xgb_train": (
            root / "training_artifacts" / "xgb" / "xgb_training.db",
            "xgb_samples",
            ("train",),
        ),
        "legacy_xgb_stack": (
            root / "training_artifacts" / "xgb" / "xgb_training.db",
            "xgb_samples",
            ("stack",),
        ),
        "selected_20260616_xgb_train": (
            root
            / "training_artifacts"
            / "xgb_selected_20260616"
            / "xgb_training.db",
            "xgb_samples",
            ("train",),
        ),
        "selected_20260616_xgb_stack": (
            root
            / "training_artifacts"
            / "xgb_selected_20260616"
            / "xgb_training.db",
            "xgb_samples",
            ("stack",),
        ),
    }
    for stage, (path, table, splits) in db_sources.items():
        identifiers = db_split_ids(path, table, splits)
        sources[stage] = identifiers
        inventory[stage] = {
            "path": report_path(path, root=root),
            "table": table,
            "splits": list(splits),
            "unique_ids": len(identifiers),
        }

    loop_ids, loop_inventory = training_loop_export_ids(root)
    sources["training_loop_exports"] = loop_ids
    inventory["training_loop_exports"] = {
        "unique_ids": len(loop_ids),
        "files": loop_inventory,
    }
    return sources, inventory


def reserved_evaluation_ids(
    root: Path, validation_csv: Path
) -> tuple[set[str], dict[str, Any]]:
    sources: dict[str, set[str]] = {}
    for name, path in {
        "general_dataset_val": root / "data" / "datasets" / "val.jsonl",
        "general_dataset_test": root / "data" / "datasets" / "test.jsonl",
    }.items():
        identifiers, _, _ = jsonl_ids(path)
        sources[name] = identifiers
    for agent_dir in sorted((root / "training_artifacts" / "sft").glob("*")):
        if not agent_dir.is_dir():
            continue
        for split in ("val", "test"):
            identifiers, _, _ = jsonl_ids(agent_dir / f"{split}.jsonl")
            sources[f"agent_{agent_dir.name}_{split}"] = identifiers

    validation_rows = load_validation_rows(validation_csv)
    sources["current_validation_2155"] = {row["_md5"] for row in validation_rows}

    training_db = root / "training_artifacts" / "training_dataset.db"
    sources["unified_supervised_val_test"] = db_split_ids(
        training_db, "unified_samples", ("val", "test")
    )
    for name, db in {
        "legacy_xgb_val_test": root
        / "training_artifacts"
        / "xgb"
        / "xgb_training.db",
        "selected_20260616_xgb_val_test": root
        / "training_artifacts"
        / "xgb_selected_20260616"
        / "xgb_training.db",
    }.items():
        sources[name] = db_split_ids(db, "xgb_samples", ("val", "test"))

    combined = set().union(*sources.values()) if sources else set()
    return combined, {
        "unique_ids": len(combined),
        "source_counts": {name: len(values) for name, values in sources.items()},
    }


def existing_fresh_ids(suite: Path | None) -> set[str]:
    if not suite:
        return set()
    identifiers: set[str] = set()
    for path in (
        suite / "fresh_expert_holdout_candidates.jsonl",
        suite / "layer1_model" / "model_release_holdout.jsonl",
        suite / "layer4_e2e" / "end_to_end_release_holdout.jsonl",
    ):
        identifiers.update(
            sample_id
            for row in read_jsonl(path)
            if (sample_id := row_md5(row))
        )
    return identifiers


def published_strict_ids(root: Path) -> set[str]:
    identifiers: set[str] = set()
    for path in (root / "training_artifacts").glob("strict_untrained_release_*.csv"):
        identifiers.update(row["_md5"] for row in load_validation_rows(path))
    return identifiers


def operational_seen_ids(data_dir: Path) -> tuple[set[str], dict[str, int]]:
    db_path = data_dir / "mvp.db"
    if not db_path.exists():
        return set(), {}
    table_columns = {
        "agent_traces": "md5",
        "batch_items": "md5",
        "batch_job_items": "md5",
        "human_reviews": "md5",
        "judgements": "sample_id",
        "report_cache": "md5",
        "reward_records": "md5",
    }
    identifiers: set[str] = set()
    counts: dict[str, int] = {}
    conn = readonly_connection(db_path)
    try:
        for table, column in table_columns.items():
            if not table_exists(conn, table):
                continue
            values = {
                sample_id
                for (value,) in conn.execute(
                    f"SELECT DISTINCT [{column}] FROM [{table}] "
                    f"WHERE [{column}] IS NOT NULL"
                )
                if (sample_id := normalize_md5(value))
            }
            identifiers.update(values)
            counts[table] = len(values)
    finally:
        conn.close()
    return identifiers, counts


def rag_ids(data_dir: Path) -> tuple[set[str], int]:
    path = data_dir / "rag" / "rag_store.db"
    if not path.exists():
        return set(), 0
    conn = readonly_connection(path)
    identifiers: set[str] = set()
    rows = 0
    try:
        if not table_exists(conn, "rag_documents"):
            return identifiers, rows
        for doc_id, content, metadata in conn.execute(
            "SELECT doc_id,content,metadata_json FROM rag_documents"
        ):
            rows += 1
            for value in (doc_id, content, metadata):
                identifiers.update(
                    match.upper() for match in MD5_IN_TEXT_RE.findall(clean(value))
                )
    finally:
        conn.close()
    return identifiers, rows


def scrub_label_fields(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: scrub_label_fields(child)
            for key, child in value.items()
            if str(key).strip().lower() not in LABEL_KEYS
        }
    if isinstance(value, list):
        return [scrub_label_fields(child) for child in value]
    return value


def load_candidate_pool(
    data_dir: Path, excluded_ids: set[str]
) -> list[dict[str, Any]]:
    path = data_dir / "mvp.db"
    conn = readonly_connection(path)
    candidates: dict[str, dict[str, Any]] = {}
    try:
        for values in conn.execute(
            "SELECT md5,source_sheet,label,app_name,fraud_type,fraud_subtype,raw_json "
            "FROM app_md5_labels"
        ):
            (
                md5,
                source_sheet,
                label,
                app_name,
                fraud_type,
                fraud_subtype,
                raw_json,
            ) = values
            sample_id = normalize_md5(md5)
            reference_label = clean(label).lower()
            if (
                not sample_id
                or sample_id in excluded_ids
                or reference_label not in {"malicious", "benign"}
            ):
                continue
            try:
                raw = json.loads(raw_json) if clean(raw_json) else {}
            except json.JSONDecodeError:
                raw = {}
            if not isinstance(raw, dict):
                raw = {"raw_value": raw}
            candidates.setdefault(
                sample_id,
                {
                    "md5": sample_id,
                    "reference_label": reference_label,
                    "source_sheet": clean(source_sheet),
                    "app_name": clean(app_name),
                    "fraud_type": clean(fraud_type),
                    "fraud_subtype": clean(fraud_subtype),
                    "raw": raw,
                },
            )
    finally:
        conn.close()
    return list(candidates.values())


def select_balanced(
    candidates: list[dict[str, Any]], count: int, salt: str
) -> list[dict[str, Any]]:
    if count % 2:
        raise ValueError("count must be even for a balanced binary set")
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in candidates:
        grouped[row["reference_label"]].append(row)
    target = count // 2
    for label in ("malicious", "benign"):
        if len(grouped[label]) < target:
            raise RuntimeError(
                f"not enough {label} candidates: need {target}, found {len(grouped[label])}"
            )
        grouped[label].sort(
            key=lambda row: stable_hash(f"{salt}|{label}|{row['md5']}")
        )
    selected = grouped["malicious"][:target] + grouped["benign"][:target]
    selected.sort(key=lambda row: stable_hash(f"{salt}|order|{row['md5']}"))
    return selected


def add_engine_records(data_dir: Path, selected: list[dict[str, Any]]) -> None:
    if not selected:
        return
    conn = readonly_connection(data_dir / "mvp.db")
    selected_by_id = {row["md5"]: row for row in selected}
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
    try:
        sample_ids = list(selected_by_id)
        for start in range(0, len(sample_ids), 400):
            chunk = sample_ids[start : start + 400]
            placeholders = ",".join("?" for _ in chunk)
            for values in conn.execute(
                f"SELECT {','.join(columns)} FROM engine_detections "
                f"WHERE UPPER(md5) IN ({placeholders})",
                chunk,
            ):
                record = dict(zip(columns, values))
                sample_id = normalize_md5(record.pop("md5"))
                if sample_id in selected_by_id:
                    selected_by_id[sample_id].setdefault("engine_records", []).append(
                        record
                    )
    finally:
        conn.close()


def judgement_item(row: dict[str, Any]) -> dict[str, Any]:
    raw = scrub_label_fields(row.get("raw") or {})
    if not isinstance(raw, dict):
        raw = {}
    item = dict(raw)
    item["md5"] = row["md5"]
    item["sample_id"] = row["md5"]
    if row.get("app_name"):
        item.setdefault("app_name", row["app_name"])
    if row.get("fraud_type"):
        item.setdefault("fraud_category_big", row["fraud_type"])
    if row.get("fraud_subtype"):
        item.setdefault("fraud_category_small", row["fraud_subtype"])
    for record in row.get("engine_records") or []:
        if not isinstance(record, dict):
            continue
        engine = clean(record.get("engine")).lower()
        side = "a" if engine in {"360", "a", "engine_a"} else "b"
        for source_field, target_suffix in (
            ("score", "score"),
            ("detect_type", "label_text"),
            ("app_name", "app_name"),
            ("virus_name", "virus_name"),
            ("description", "description"),
        ):
            value = record.get(source_field)
            if clean(value):
                item.setdefault(f"engine_{side}_{target_suffix}", value)
        for field in (
            "sha1",
            "sha256",
            "package_name",
            "app_name",
            "fake_app",
            "virus_name",
            "virus_description",
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
        ):
            if clean(record.get(field)):
                item.setdefault(field, record[field])
    scrubbed = scrub_label_fields(item)
    # MalApp's current feature importer expects scalar top-level values. Preserve
    # any uncommon nested feature as JSON text instead of letting list/dict
    # membership checks fail during normalization.
    return {
        key: json.dumps(value, ensure_ascii=False, sort_keys=True)
        if isinstance(value, (dict, list, tuple, set))
        else value
        for key, value in scrubbed.items()
    }


def ids_found_in_split_table(
    path: Path,
    table: str,
    candidate_ids: set[str],
    splits: tuple[str, ...],
) -> set[str]:
    if not path.exists() or not candidate_ids:
        return set()
    conn = readonly_connection(path)
    try:
        if not table_exists(conn, table):
            return set()
        found: set[str] = set()
        values = list(candidate_ids)
        split_marks = ",".join("?" for _ in splits)
        for start in range(0, len(values), 350):
            chunk = values[start : start + 350]
            id_marks = ",".join("?" for _ in chunk)
            query = (
                f"SELECT DISTINCT md5 FROM [{table}] "
                f"WHERE split IN ({split_marks}) AND UPPER(md5) IN ({id_marks})"
            )
            found.update(
                normalize_md5(row[0])
                for row in conn.execute(query, (*splits, *chunk))
                if normalize_md5(row[0])
            )
        return found
    finally:
        conn.close()


def packaged_db_candidate_check(
    root: Path, candidate_ids: set[str]
) -> tuple[set[str], list[dict[str, Any]]]:
    found: set[str] = set()
    inventory: list[dict[str, Any]] = []
    paths = set((root / "training_artifacts").rglob("*.db"))
    paths.update((root / "release").rglob("*.db"))
    for path in sorted(paths):
        tables: list[tuple[str, tuple[str, ...]]] = []
        conn = readonly_connection(path)
        try:
            if table_exists(conn, "xgb_samples"):
                tables.append(("xgb_samples", ("train", "stack")))
            if table_exists(conn, "unified_samples"):
                tables.append(("unified_samples", ("train",)))
            if table_exists(conn, "evidence_blocks"):
                tables.append(("evidence_blocks", ("train",)))
        finally:
            conn.close()
        for table, splits in tables:
            hits = ids_found_in_split_table(
                path, table, candidate_ids, splits
            )
            found.update(hits)
            inventory.append(
                {
                    "path": report_path(path, root=root),
                    "table": table,
                    "splits": list(splits),
                    "candidate_overlap": len(hits),
                }
            )
    return found, inventory


def release_jsonl_mirror_inventory(
    root: Path, canonical_inventory: dict[str, Any]
) -> tuple[set[str], list[dict[str, Any]]]:
    canonical_hashes = {
        value.get("sha256", "")
        for value in canonical_inventory.values()
        if isinstance(value, dict) and value.get("sha256")
    }
    additional_ids: set[str] = set()
    inventory: list[dict[str, Any]] = []
    for path in sorted((root / "release").rglob("train.jsonl")):
        digest = sha256_file(path)
        is_canonical_copy = digest in canonical_hashes
        unique_ids = 0
        if not is_canonical_copy:
            identifiers, _, _ = jsonl_ids(path)
            additional_ids.update(identifiers)
            unique_ids = len(identifiers)
        inventory.append(
            {
                "path": report_path(path, root=root),
                "sha256": digest,
                "matches_canonical_training_file": is_canonical_copy,
                "additional_unique_ids_if_different": unique_ids,
            }
        )
    return additional_ids, inventory


def build_overlap_reports(
    output_dir: Path,
    validation_rows: list[dict[str, str]],
    training_sources: dict[str, set[str]],
    training_inventory: dict[str, Any],
) -> dict[str, Any]:
    validation_ids = {row["_md5"] for row in validation_rows}
    base = training_sources["general_dataset_train"]
    sft_names = [
        "agent_sft_business_label_train",
        "agent_sft_impersonation_train",
        "agent_sft_static_analysis_train",
        "agent_sft_threat_intel_train",
    ]
    sft_union = set().union(*(training_sources[name] for name in sft_names))
    historical_1987 = validation_ids & (base | sft_union)

    validation_by_id = {row["_md5"]: row for row in validation_rows}
    fieldnames = [
        "md5",
        "gold_label",
        "label_source",
        "app_name",
        "overlap_category",
        "general_dataset_train",
        *sft_names,
        "unified_supervised_train",
        "legacy_xgb_train",
        "legacy_xgb_stack",
        "selected_20260616_xgb_train",
        "selected_20260616_xgb_stack",
        "selected_20260616_xgb_test",
    ]
    selected_test = db_split_ids(
        ROOT
        / "training_artifacts"
        / "xgb_selected_20260616"
        / "xgb_training.db",
        "xgb_samples",
        ("test",),
    )
    detail_path = output_dir / "historical_overlap_1987_stage_detail.csv"
    with detail_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for sample_id in sorted(historical_1987):
            row = validation_by_id[sample_id]
            in_base = sample_id in base
            in_sft = sample_id in sft_union
            category = (
                "general_and_four_agent_sft"
                if in_base and in_sft
                else "general_only"
                if in_base
                else "four_agent_sft_only"
            )
            output = {
                "md5": sample_id,
                "gold_label": row.get("gold_label", ""),
                "label_source": row.get("label_source", ""),
                "app_name": row.get("app_name", ""),
                "overlap_category": category,
                "general_dataset_train": int(in_base),
                "unified_supervised_train": int(
                    sample_id in training_sources["unified_supervised_train"]
                ),
                "legacy_xgb_train": int(
                    sample_id in training_sources["legacy_xgb_train"]
                ),
                "legacy_xgb_stack": int(
                    sample_id in training_sources["legacy_xgb_stack"]
                ),
                "selected_20260616_xgb_train": int(
                    sample_id in training_sources["selected_20260616_xgb_train"]
                ),
                "selected_20260616_xgb_stack": int(
                    sample_id in training_sources["selected_20260616_xgb_stack"]
                ),
                "selected_20260616_xgb_test": int(sample_id in selected_test),
            }
            for name in sft_names:
                output[name] = int(sample_id in training_sources[name])
            writer.writerow(output)

    signatures = {
        "general_and_four_agent_sft": len(validation_ids & base & sft_union),
        "general_only": len((validation_ids & base) - sft_union),
        "four_agent_sft_only": len((validation_ids & sft_union) - base),
    }
    stage_overlaps = {
        name: len(validation_ids & values) for name, values in training_sources.items()
    }
    report = {
        "definition": (
            "The displayed 1,987 is the union of validation MD5s found in "
            "data/datasets/train.jsonl or any of the four Agent SFT train.jsonl files."
        ),
        "validation_rows": len(validation_rows),
        "validation_unique_ids": len(validation_ids),
        "historical_overlap_union": len(historical_1987),
        "general_dataset_train_overlap": len(validation_ids & base),
        "four_agent_sft_union_overlap": len(validation_ids & sft_union),
        "membership_signatures": signatures,
        "stage_overlaps": stage_overlaps,
        "selected_20260616_xgb_test_overlap": len(validation_ids & selected_test),
        "important_interpretation": (
            "All 2,155 validation IDs are in the selected 2026-06-16 XGBoost test "
            "split; zero are in that selected version's train or stack split. The "
            "1,987 warning refers to older/local general and Agent training assets."
        ),
        "training_source_inventory": training_inventory,
        "detail_csv": detail_path.name,
        "detail_csv_sha256": sha256_file(detail_path),
    }
    write_json(output_dir / "historical_overlap_stage_report.json", report)
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a leakage-audited, label-blind MalApp judgement set."
    )
    parser.add_argument("--count", type=int, default=400)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--data-dir", type=Path)
    parser.add_argument("--validation-csv", type=Path)
    parser.add_argument("--suite-dir", type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--salt", default="strict-untrained-additional-400-v1")
    parser.add_argument(
        "--skip-release-jsonl-hashes",
        action="store_true",
        help="Skip full SHA-256 verification of packaged release train.jsonl mirrors.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = args.root.resolve()
    data_dir = (
        args.data_dir.resolve()
        if args.data_dir
        else Path(os.environ.get("LOCALAPPDATA", root))
        / "MalApp_AgentTrace_LearningLoop"
        / "data"
    )
    validation_csv = (
        args.validation_csv.resolve()
        if args.validation_csv
        else root
        / "training_artifacts"
        / "xgb_selected_20260616"
        / "test_set_for_app.csv"
    )
    suite = args.suite_dir.resolve() if args.suite_dir else find_latest_suite(data_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = (
        args.output_dir.resolve()
        if args.output_dir
        else root
        / "generated_datasets"
        / f"strict_untrained_judgement_{args.count}_{timestamp}"
    )
    output_dir.mkdir(parents=True, exist_ok=False)

    training_sources, training_inventory = canonical_training_sources(root)
    mirror_inventory: list[dict[str, Any]] = []
    if not args.skip_release_jsonl_hashes:
        mirror_ids, mirror_inventory = release_jsonl_mirror_inventory(
            root, training_inventory
        )
        if mirror_ids:
            training_sources["noncanonical_release_train_jsonl"] = mirror_ids
            training_inventory["noncanonical_release_train_jsonl"] = {
                "unique_ids": len(mirror_ids)
            }

    validation_rows = load_validation_rows(validation_csv)
    overlap_report = build_overlap_reports(
        output_dir,
        validation_rows,
        training_sources,
        training_inventory,
    )

    training_ids = set().union(*training_sources.values())
    evaluation_ids, evaluation_inventory = reserved_evaluation_ids(
        root, validation_csv
    )
    fresh_ids = existing_fresh_ids(suite)
    published_ids = published_strict_ids(root)
    seen_ids, seen_inventory = operational_seen_ids(data_dir)
    retrieval_ids, rag_document_count = rag_ids(data_dir)
    excluded_ids = (
        training_ids
        | evaluation_ids
        | fresh_ids
        | published_ids
        | seen_ids
        | retrieval_ids
    )

    candidates = load_candidate_pool(data_dir, excluded_ids)
    selected = select_balanced(candidates, args.count, args.salt)
    add_engine_records(data_dir, selected)

    release_hits, release_db_inventory = packaged_db_candidate_check(
        root, {row["md5"] for row in selected}
    )
    if release_hits:
        excluded_ids.update(release_hits)
        candidates = load_candidate_pool(data_dir, excluded_ids)
        selected = select_balanced(candidates, args.count, args.salt)
        add_engine_records(data_dir, selected)
        release_hits, release_db_inventory = packaged_db_candidate_check(
            root, {row["md5"] for row in selected}
        )
    if release_hits:
        raise RuntimeError(
            f"release database audit still found {len(release_hits)} training overlaps"
        )

    items = [judgement_item(row) for row in selected]
    selected_ids = {row["md5"] for row in selected}
    label_distribution = Counter(row["reference_label"] for row in selected)
    prohibited_key_hits: list[dict[str, str]] = []

    def find_keys(value: Any, sample_id: str, prefix: str = "") -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if str(key).strip().lower() in LABEL_KEYS:
                    prohibited_key_hits.append({"md5": sample_id, "field": path})
                find_keys(child, sample_id, path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                find_keys(child, sample_id, f"{prefix}[{index}]")

    for row in items:
        find_keys(row, normalize_md5(row.get("md5")))

    input_json = output_dir / f"strict_untrained_judgement_{args.count}.json"
    input_jsonl = output_dir / f"strict_untrained_judgement_{args.count}.jsonl"
    ids_txt = output_dir / f"strict_untrained_judgement_{args.count}_ids.txt"
    key_csv = output_dir / f"strict_untrained_judgement_{args.count}_reference_key.csv"
    write_json(input_json, items)
    write_jsonl(input_jsonl, items)
    ids_txt.write_text("\n".join(sorted(selected_ids)) + "\n", encoding="utf-8")
    with key_csv.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "md5",
                "reference_label",
                "label_quality",
                "source_sheet",
                "annotation_status",
            ],
        )
        writer.writeheader()
        for row in sorted(selected, key=lambda value: value["md5"]):
            writer.writerow(
                {
                    "md5": row["md5"],
                    "reference_label": row["reference_label"],
                    "label_quality": "source_reference_not_expert_gold",
                    "source_sheet": row["source_sheet"],
                    "annotation_status": "needs_two_expert_reviews_and_adjudication",
                }
            )

    audit_checks = {
        "requested_count_met": len(items) == args.count,
        "unique_md5": len(selected_ids) == args.count,
        "valid_md5": all(MD5_RE.fullmatch(value) for value in selected_ids),
        "balanced_reference_labels": label_distribution
        == Counter({"malicious": args.count // 2, "benign": args.count // 2}),
        "training_overlap_zero": not bool(selected_ids & training_ids),
        "prior_evaluation_overlap_zero": not bool(selected_ids & evaluation_ids),
        "previous_fresh_candidate_overlap_zero": not bool(selected_ids & fresh_ids),
        "published_strict_extension_overlap_zero": not bool(
            selected_ids & published_ids
        ),
        "previously_judged_or_queued_overlap_zero": not bool(selected_ids & seen_ids),
        "rag_document_overlap_zero": not bool(selected_ids & retrieval_ids),
        "packaged_release_db_train_stack_overlap_zero": not bool(release_hits),
        "label_fields_absent_from_judgement_input": not prohibited_key_hits,
        "top_level_values_compatible_with_importer": all(
            not isinstance(value, (dict, list, tuple, set))
            for item in items
            for value in item.values()
        ),
    }
    audit = {
        "created_at_local": datetime.now().astimezone().isoformat(),
        "scope": (
            "Strictly unseen relative to all locally discoverable MalApp training, "
            "stacking, evaluation, RAG and operational judgement artifacts. This "
            "cannot prove absence from an external foundation model provider's "
            "private pretraining corpus."
        ),
        "intended_use": "blind APP judgement followed by two-expert review and adjudication",
        "grain": "one record per unique MD5",
        "count": len(items),
        "reference_label_distribution": dict(label_distribution),
        "candidate_pool_after_all_exclusions": len(candidates),
        "engine_record_coverage": {
            "samples_with_engine_records": sum(
                1 for row in selected if row.get("engine_records")
            ),
            "total_engine_records": sum(
                len(row.get("engine_records") or []) for row in selected
            ),
        },
        "exclusion_inventory": {
            "local_training_union_ids": len(training_ids),
            "reserved_evaluation_union_ids": len(evaluation_ids),
            "previous_fresh_candidate_ids": len(fresh_ids),
            "published_strict_extension_ids": len(published_ids),
            "operational_seen_union_ids": len(seen_ids),
            "rag_extracted_ids": len(retrieval_ids),
            "rag_document_rows": rag_document_count,
            "training_sources": training_inventory,
            "evaluation_sources": evaluation_inventory,
            "operational_seen_sources": seen_inventory,
        },
        "release_mirror_audit": {
            "train_jsonl_files_checked": len(mirror_inventory),
            "noncanonical_train_jsonl_files": sum(
                1
                for row in mirror_inventory
                if not row["matches_canonical_training_file"]
            ),
            "training_database_table_checks": len(release_db_inventory),
            "candidate_overlap": len(release_hits),
            "jsonl_inventory": mirror_inventory,
            "database_inventory": release_db_inventory,
        },
        "checks": audit_checks,
        "prohibited_key_hits": prohibited_key_hits,
        "files": {
            "judgement_json": input_json.name,
            "judgement_jsonl": input_jsonl.name,
            "ids_txt": ids_txt.name,
            "reference_key_csv_do_not_import": key_csv.name,
            "historical_overlap_detail": overlap_report["detail_csv"],
        },
    }
    audit_path = output_dir / "strict_untrained_audit.json"
    write_json(audit_path, audit)

    manifest = {
        "dataset_id": f"strict-untrained-judgement-{args.count}-{timestamp}",
        "created_at_local": datetime.now().astimezone().isoformat(),
        "selection_salt": args.salt,
        "source_database": report_path(
            data_dir / "mvp.db", root=root, data_dir=data_dir
        ),
        "validation_csv": report_path(validation_csv, root=root),
        "latest_five_layer_suite": (
            report_path(suite, root=root, data_dir=data_dir) if suite else ""
        ),
        "status": "generated_and_audited" if all(audit_checks.values()) else "audit_failed",
        "do_not_train_before_freeze": True,
        "do_not_add_to_rag_before_freeze": True,
        "reference_key_is_not_model_input": True,
        "sha256": {
            input_json.name: sha256_file(input_json),
            input_jsonl.name: sha256_file(input_jsonl),
            ids_txt.name: sha256_file(ids_txt),
            key_csv.name: sha256_file(key_csv),
            audit_path.name: sha256_file(audit_path),
        },
    }
    write_json(output_dir / "manifest.json", manifest)

    readme = f"""# MalApp 严格未训练 APP 研判集（{args.count} 条）

本批次是相对现有 1,000 条候选之外新增的盲测批次，共 {args.count} 条，MD5 唯一；参考分布为恶意 {label_distribution['malicious']} 条、良性 {label_distribution['benign']} 条。

## 使用

1. 在“数据加载”页面上传 `{input_json.name}`，导入数量设为 {args.count}。
2. 启动批量 APP 研判。
3. 在模型输出全部冻结前，不要打开或导入 `{key_csv.name}`。
4. 完成后由两名专家独立复核，冲突样本再仲裁；参考标签不是专家金标准。

## 严格隔离结果

- 本地训练/stack 集交集：0
- 既有验证/测试集交集：0
- 之前 1,000 条新鲜候选交集：0
- 已研判、已排队、已有报告/轨迹记录交集：0
- RAG 文档 MD5 交集：0
- release 内 XGBoost、unified、evidence train/stack 数据库交集：0
- 研判输入中的答案字段：0

“严格未训练”仅针对当前机器上可审计的 MalApp 训练资产；无法证明外部大模型供应商的私有预训练语料中从未出现过这些 MD5。

## 1,987 条历史重叠结论

- 通用训练集命中：{overlap_report['general_dataset_train_overlap']} 条
- 四 Agent 训练集并集命中：{overlap_report['four_agent_sft_union_overlap']} 条
- 同时出现在两类阶段：{overlap_report['membership_signatures']['general_and_four_agent_sft']} 条
- 仅通用训练阶段：{overlap_report['membership_signatures']['general_only']} 条
- 仅四 Agent 训练阶段：{overlap_report['membership_signatures']['four_agent_sft_only']} 条
- 2026-06-16 选定 XGBoost：2,155 条全部属于 test，train/stack 与当前验证集交集均为 0。

逐 MD5 阶段明细见 `historical_overlap_1987_stage_detail.csv`。
"""
    (output_dir / "README.md").write_text(readme, encoding="utf-8")

    if not all(audit_checks.values()):
        raise RuntimeError(f"dataset audit failed: {audit_checks}")
    print(json.dumps({"output_dir": str(output_dir), **manifest}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
