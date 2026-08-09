from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from contextlib import closing
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from engine.pipeline import DATA_DIR, DB_PATH, extract_iocs, load_json


ROOT = Path(__file__).resolve().parents[1]
BLOOM_PATH = DATA_DIR / "sample_seen.bloom"
BLOOM_BITS = 1_048_576
BLOOM_HASHES = 5
FIELD_REGISTRY_CACHE: set[str] = set()
ANALYSIS_CACHE_VERSION = "2026-06-15-strict-evidence-debate-v5"

DEFAULT_FIELD_ALIASES = {
    "MD5": "md5",
    "appName": "app_name",
    "input_appName": "app_name",
    "pkgName": "package_name",
    "signature": "signature",
    "permissions": "permissions",
    "plugins": "plugins",
    "fakeApp": "fake_app",
    "genuine": "genuine",
    "steady": "packer",
    "codeFuscator": "packer",
    "fraudTypeInfo": "fraud_type_info",
    "fraudName": "fraud_name",
    "fraudCategory": "fraud_category",
    "病毒名称": "virus_name",
    "类型": "engine_label_text",
    "危害类型": "risk_type",
    "病毒描述": "virus_description",
    "应用名称": "app_name",
    "包名": "package_name",
    "仿冒应用": "fake_app",
    "控制端地址": "control_url",
    "下载地址": "download_url",
    "控制邮箱": "control_mailbox",
    "控制手机号": "control_phone",
    "input_fraudGaType": "fraud_category_big",
    "input_fraudGaSubType": "fraud_category_small",
    "ltUrls": "lt_urls",
    "masterControlUrl": "control_url",
    "dynamicNets": "dynamic_nets",
    "score": "engine_c_feature_score",
    "domain": "domain",
    "topDomain": "top_domain",
    "ip": "ip",
    "subUrls": "sub_urls",
    "urlSource": "url_source",
    "urlSources": "url_sources",
    "domainType": "domain_type",
    "whiteFlag": "white_flag",
    "cdnFlag": "cdn_flag",
    "isFraud": "is_fraud_url",
    "operator": "operator",
    "country": "country",
    "province": "province",
    "city": "city",
    "cloud_or_oversea_providers": "cloud_or_oversea_providers",
    "domains": "domains",
    "ips": "ips",
    "countries": "countries",
    "operators": "operators",
    "应用名称": "app_name",
    "包名": "package_name",
    "病毒名称": "virus_name",
    "类型": "engine_label_text",
    "危害类型": "risk_type",
    "病毒描述": "virus_description",
    "仿冒应用": "fake_app",
    "控制端地址": "control_url",
    "下载地址": "download_url",
    "控制邮箱": "control_mailbox",
    "控制手机号": "control_phone",
    "人工审核结果": "human_label",
    "冲突类型": "conflict_type",
    "应用名称_360": "engine_a_app_name",
    "应用名称_cm": "engine_b_app_name",
    "类型_360": "engine_a_label_text",
    "类型_cm": "engine_b_label_text",
    "病毒名称_360": "engine_a_virus_name",
    "病毒名称_cm": "engine_b_virus_name",
    "人工审核结果": "human_label",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_preprocess_tables() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        statements = [
            """
            CREATE TABLE IF NOT EXISTS feature_registry (
                raw_field TEXT PRIMARY KEY,
                standard_field TEXT NOT NULL,
                source TEXT NOT NULL,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                sample_count INTEGER NOT NULL DEFAULT 0
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sample_features (
                md5 TEXT NOT NULL,
                source TEXT NOT NULL,
                payload_format TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                raw_json TEXT NOT NULL,
                normalized_json TEXT NOT NULL,
                static_package_json TEXT NOT NULL,
                network_ioc_package_json TEXT NOT NULL,
                priority_score REAL NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (md5, source, content_hash)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sample_features_md5 ON sample_features(md5)",
            """
            CREATE TABLE IF NOT EXISTS sample_tasks (
                md5 TEXT PRIMARY KEY,
                priority_score REAL NOT NULL,
                priority_reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                source TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sample_tasks_priority ON sample_tasks(status, priority_score DESC)",
            """
            CREATE TABLE IF NOT EXISTS report_cache (
                cache_key TEXT PRIMARY KEY,
                md5 TEXT NOT NULL,
                report_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_report_cache_md5 ON report_cache(md5)",
            """
            CREATE TABLE IF NOT EXISTS manual_labels (
                md5 TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                source_file TEXT NOT NULL,
                conflict_type TEXT,
                raw_json TEXT NOT NULL,
                imported_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS import_batches (
                batch_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                total_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS batch_items (
                batch_id TEXT NOT NULL,
                md5 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (batch_id, md5)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_batch_items_batch ON batch_items(batch_id, created_at)",
            """
            CREATE TABLE IF NOT EXISTS batch_jobs (
                job_id TEXT PRIMARY KEY,
                batch_id TEXT NOT NULL,
                requested INTEGER NOT NULL,
                total INTEGER NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0,
                succeeded INTEGER NOT NULL DEFAULT 0,
                failed INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                current_md5 TEXT NOT NULL DEFAULT '',
                results_json TEXT NOT NULL DEFAULT '[]',
                errors_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                finished_at TEXT NOT NULL DEFAULT ''
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS batch_job_items (
                job_id TEXT NOT NULL,
                md5 TEXT NOT NULL,
                sequence_no INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                PRIMARY KEY (job_id, md5)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_batch_job_items_status ON batch_job_items(job_id, status, sequence_no)",
        ]
        for statement in statements:
            conn.execute(statement)

        # A sample can be imported by more than one batch.  Keep the lifecycle
        # of each batch item here instead of reusing the global sample task state.
        batch_columns = {str(row[1]) for row in conn.execute("PRAGMA table_info(batch_items)").fetchall()}
        if "status" not in batch_columns:
            conn.execute("ALTER TABLE batch_items ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        if "updated_at" not in batch_columns:
            conn.execute("ALTER TABLE batch_items ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE batch_items SET status = 'pending' WHERE status IS NULL OR status = ''")
        conn.execute("UPDATE batch_items SET updated_at = created_at WHERE updated_at IS NULL OR updated_at = ''")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_batch_items_status "
            "ON batch_items(batch_id, status, created_at)"
        )
        conn.commit()
    finally:
        conn.close()


def parse_feature_payload(payload: Any, payload_format: str = "json") -> dict[str, Any]:
    """Parse JSON/XML/Protobuf-like payloads into a dict.

    Protobuf needs a compiled message schema in production. In this MVP, bytes
    are stored as hex metadata unless the caller has already converted them to
    a dict.
    """
    payload_format = payload_format.lower()
    if payload_format == "json":
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")
        return json.loads(payload) if isinstance(payload, str) and payload.strip() else {}
    if payload_format == "xml":
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="replace")
        root = ElementTree.fromstring(payload)
        return xml_to_dict(root)
    if payload_format in {"protobuf", "proto"}:
        if isinstance(payload, dict):
            return payload
        if isinstance(payload, bytes):
            return {"protobuf_hex": payload.hex(), "protobuf_length": len(payload)}
        return {"protobuf_text": str(payload)}
    raise ValueError(f"unsupported payload format: {payload_format}")


def xml_to_dict(node: ElementTree.Element) -> dict[str, Any]:
    children = list(node)
    if not children:
        return {node.tag: node.text or ""}
    result: dict[str, Any] = {}
    for child in children:
        item = xml_to_dict(child)
        key, value = next(iter(item.items()))
        if key in result:
            if not isinstance(result[key], list):
                result[key] = [result[key]]
            result[key].append(value)
        else:
            result[key] = value
    return {node.tag: result}


def load_alias_mapping() -> dict[str, str]:
    mapping = dict(DEFAULT_FIELD_ALIASES)
    mapping_path = DATA_DIR / "field_mapping.json"
    if mapping_path.exists():
        mapping.update(load_json(mapping_path))
    return mapping


def normalize_feature_record(
    raw: dict[str, Any],
    source: str = "unknown",
    *,
    register_fields: bool = True,
) -> tuple[dict[str, Any], list[str]]:
    mapping = load_alias_mapping()
    normalized: dict[str, Any] = {}
    unmapped: list[str] = []
    for key, value in raw.items():
        if value in {"nan", "None", None}:
            value = ""
        standard = mapping.get(key, key)
        normalized[standard] = coerce_value(standard, value)
        if standard == key and key not in mapping:
            unmapped.append(key)
        if register_fields:
            register_feature_field(key, standard, source)

    md5 = str(normalized.get("md5") or raw.get("MD5") or "").upper().strip()
    if md5:
        normalized["md5"] = md5
        normalized.setdefault("sample_id", md5)
    derive_engine_fields(normalized)
    return normalized, unmapped


def derive_engine_fields(sample: dict[str, Any]) -> None:
    """Promote engine-specific Excel columns into fields used by specialists."""
    for side in ("a", "b"):
        score_key = f"engine_{side}_score"
        label_key = f"engine_{side}_label"
        text_key = f"engine_{side}_label_text"
        if sample.get(score_key) not in ("", None):
            try:
                sample[score_key] = float(sample[score_key])
            except (TypeError, ValueError):
                pass
        if not sample.get(label_key):
            sample[label_key] = engine_label(sample.get(text_key), sample.get(score_key))

    if not sample.get("app_name"):
        sample["app_name"] = first_meaningful(
            sample.get("engine_b_app_name"),
            sample.get("engine_a_app_name"),
        )
    if not sample.get("virus_name"):
        candidates = (
            ("b", sample.get("engine_b_virus_name")),
            ("a", sample.get("engine_a_virus_name")),
        )
        malicious = [
            value
            for side, value in candidates
            if sample.get(f"engine_{side}_label") == "malicious" and meaningful(value)
        ]
        sample["virus_name"] = first_meaningful(*malicious, *(value for _, value in candidates))

    score_a = numeric_score(sample.get("engine_a_score"))
    score_b = numeric_score(sample.get("engine_b_score"))
    if score_a is not None or score_b is not None:
        sample["engine_conflict"] = {
            "engine_a_score": score_a,
            "engine_b_score": score_b,
            "score_gap": round(abs((score_a or 0.0) - (score_b or 0.0)), 2)
            if score_a is not None and score_b is not None
            else None,
            "engine_a_label": sample.get("engine_a_label", ""),
            "engine_b_label": sample.get("engine_b_label", ""),
            "conflict_type": sample.get("conflict_type", ""),
        }


def engine_label(text: Any, score: Any) -> str:
    value = str(text or "").strip().lower()
    if any(term in value for term in ("恶意", "病毒", "木马", "malicious")):
        return "malicious"
    if any(term in value for term in ("可疑", "风险", "suspicious")):
        return "suspicious"
    if any(term in value for term in ("白", "良性", "安全", "benign")):
        return "benign"
    numeric = numeric_score(score)
    if numeric is None:
        return ""
    if numeric >= 70:
        return "malicious"
    if numeric >= 45:
        return "suspicious"
    return "benign"


def numeric_score(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def meaningful(value: Any) -> bool:
    return str(value or "").strip().lower() not in {"", "nan", "none", "null", "未知", "-"}


def first_meaningful(*values: Any) -> str:
    for value in values:
        if meaningful(value):
            return str(value).strip()
    return ""


def coerce_value(field: str, value: Any) -> Any:
    if isinstance(value, str):
        value = strip_invisible(value).strip()
    if field in {"permissions", "plugins", "lt_urls", "dynamic_nets", "domains", "ips", "countries", "operators"}:
        return split_multi_value(value)
    if field in {"fake_app", "genuine", "packer", "is_fraud_url"}:
        return truthy(value)
    return value


def strip_invisible(text: str) -> str:
    return "".join(ch for ch in text if ch not in {"\ufeff", "\u200b", "\u200c", "\u200d", "\u2060", "\u200a"})


def split_multi_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except json.JSONDecodeError:
        pass
    parts = re_split(text)
    return [part for part in parts if part]


def re_split(text: str) -> list[str]:
    import re

    return [item.strip() for item in re.split(r"[;,，；\n\r\t]+", text) if item.strip()]


def truthy(value: Any) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y", "是", "恶意", "仿冒"}


def register_feature_field(raw_field: str, standard_field: str, source: str) -> None:
    cache_key = f"{raw_field}\x1f{standard_field}\x1f{source}"
    if cache_key in FIELD_REGISTRY_CACHE:
        return
    init_preprocess_tables()
    now = utc_now()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO feature_registry
            (raw_field, standard_field, source, first_seen_at, last_seen_at, sample_count)
            VALUES (?, ?, ?, ?, ?, 1)
            ON CONFLICT(raw_field) DO UPDATE SET
                standard_field=excluded.standard_field,
                source=excluded.source,
                last_seen_at=excluded.last_seen_at,
                sample_count=feature_registry.sample_count + 1
            """,
            (raw_field, standard_field, source, now, now),
        )
        conn.commit()
    finally:
        conn.close()
    FIELD_REGISTRY_CACHE.add(cache_key)


def build_feature_packages(sample: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    iocs = extract_iocs(sample)
    static_package = {
        "identity": {
            "md5": sample.get("md5", ""),
            "sha1": sample.get("sha1") or sample.get("fileSha1") or "",
            "sha256": sample.get("sha256") or sample.get("fileSha256") or "",
            "app_name": sample.get("app_name", ""),
            "package_name": sample.get("package_name", ""),
            "signature": sample.get("signature") or sample.get("signature_status", ""),
        },
        "permissions": sample.get("permissions", []),
        "plugins": sample.get("plugins", []),
        "packing": {
            "packer": sample.get("packer", False),
            "code_fuscator": sample.get("codeFuscator", ""),
            "unshell_info": sample.get("unshellInfo", ""),
        },
        "business": {
            "fraud_type_info": sample.get("fraud_type_info", ""),
            "fraud_name": sample.get("fraud_name") or sample.get("fraud_family", ""),
            "fraud_category": sample.get("fraud_category", ""),
            "fraud_category_big": sample.get("fraud_category_big", ""),
            "fraud_category_small": sample.get("fraud_category_small", ""),
        },
        "impersonation": {
            "fake_app": sample.get("fake_app", False),
            "genuine": sample.get("genuine", ""),
            "icon_md5": sample.get("iconMd5", ""),
            "rebuild_type": sample.get("rebuildType", ""),
        },
    }
    network_package = {
        "iocs": iocs,
        "urls": unique_values(as_list(sample.get("lt_urls")) + as_list(sample.get("sub_urls"))),
        "domains": unique_values(as_list(sample.get("domains")) + ([sample.get("domain")] if sample.get("domain") else [])),
        "top_domains": unique_values(as_list(sample.get("top_domains")) + ([sample.get("top_domain")] if sample.get("top_domain") else [])),
        "ips": unique_values(as_list(sample.get("ips")) + ([sample.get("ip")] if sample.get("ip") else [])),
        "url_source": sample.get("url_source", ""),
        "domain_type": sample.get("domain_type", ""),
        "is_fraud_url": sample.get("is_fraud_url", False),
        "cdn_flag": sample.get("cdn_flag", ""),
        "white_flag": sample.get("white_flag", ""),
        "geo": {
            "countries": sample.get("countries", []),
            "country": sample.get("country", ""),
            "province": sample.get("province", ""),
            "city": sample.get("city", ""),
            "operator": sample.get("operator", ""),
        },
    }
    return static_package, network_package


def as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return split_multi_value(value)


def unique_values(values: list[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        text = str(value or "").strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result


def compute_priority(sample: dict[str, Any], static_package: dict[str, Any], network_package: dict[str, Any]) -> tuple[float, str]:
    score = 0.0
    reasons = []
    if sample.get("conflict_type"):
        score += 40
        reasons.append("engine_conflict")
    if sample.get("human_label"):
        score += 30
        reasons.append("manual_label")
    if sample.get("fake_app"):
        score += 20
        reasons.append("fake_app")
    if static_package["business"].get("fraud_type_info") or static_package["business"].get("fraud_category_big"):
        score += 20
        reasons.append("fraud_business")
    if network_package.get("is_fraud_url"):
        score += 20
        reasons.append("fraud_url")
    if len(network_package.get("iocs", [])) >= 10:
        score += 10
        reasons.append("many_iocs")
    return min(score, 100.0), ",".join(reasons) or "normal"


def save_feature_record(
    raw: dict[str, Any],
    *,
    source: str,
    payload_format: str = "json",
    connection: sqlite3.Connection | None = None,
    register_fields: bool = True,
    write_bloom: bool = True,
    batch_id: str = "",
) -> dict[str, Any]:
    if connection is None:
        init_preprocess_tables()
    parsed = parse_feature_payload(raw, payload_format)
    normalized, unmapped = normalize_feature_record(parsed, source=source, register_fields=register_fields)
    md5 = str(normalized.get("md5", "")).upper().strip()
    if not md5:
        raise ValueError("feature record missing md5")
    static_package, network_package = build_feature_packages(normalized)
    priority_score, priority_reason = compute_priority(normalized, static_package, network_package)
    content_hash = stable_hash(parsed)
    now = utc_now()
    owns_connection = connection is None
    conn = connection or sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO sample_features
            (md5, source, payload_format, content_hash, raw_json, normalized_json,
             static_package_json, network_ioc_package_json, priority_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                md5,
                source,
                payload_format,
                content_hash,
                json.dumps(parsed, ensure_ascii=False),
                json.dumps(normalized, ensure_ascii=False),
                json.dumps(static_package, ensure_ascii=False),
                json.dumps(network_package, ensure_ascii=False),
                priority_score,
                now,
            ),
        )
        conn.execute(
            """
            INSERT INTO sample_tasks
            (md5, priority_score, priority_reason, status, source, created_at, updated_at)
            VALUES (?, ?, ?, 'pending', ?, ?, ?)
            ON CONFLICT(md5) DO UPDATE SET
                priority_score=max(sample_tasks.priority_score, excluded.priority_score),
                priority_reason=excluded.priority_reason,
                status='pending',
                source=excluded.source,
                updated_at=excluded.updated_at
            """,
            (md5, priority_score, priority_reason, source, now, now),
        )
        if batch_id:
            conn.execute(
                """
                INSERT INTO batch_items (batch_id, md5, status, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?)
                ON CONFLICT(batch_id, md5) DO UPDATE SET
                    status = 'pending',
                    updated_at = excluded.updated_at
                """,
                (batch_id, md5, now, now),
            )
        if owns_connection:
            conn.commit()
    finally:
        if owns_connection:
            conn.close()
    if write_bloom:
        bloom_add(md5)
    return {
        "md5": md5,
        "unmapped_fields": unmapped,
        "priority_score": priority_score,
        "priority_reason": priority_reason,
        "static_package": static_package,
        "network_ioc_package": network_package,
        "batch_id": batch_id,
    }


def create_import_batch(source: str) -> str:
    init_preprocess_tables()
    batch_id = f"batch-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}"
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO import_batches (batch_id, source, total_count, created_at) VALUES (?, ?, 0, ?)",
            (batch_id, source, utc_now()),
        )
        conn.commit()
    return batch_id


def finalize_import_batch(batch_id: str) -> int:
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        count = int(
            conn.execute("SELECT COUNT(*) FROM batch_items WHERE batch_id = ?", (batch_id,)).fetchone()[0]
        )
        conn.execute("UPDATE import_batches SET total_count = ? WHERE batch_id = ?", (count, batch_id))
        conn.commit()
    return count


def list_import_batches(limit: int = 30) -> list[dict[str, Any]]:
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT b.batch_id, b.source, b.total_count, b.created_at,
                   SUM(CASE WHEN COALESCE(i.status, 'pending') = 'pending' THEN 1 ELSE 0 END) AS pending,
                   SUM(CASE WHEN COALESCE(i.status, 'pending') = 'processing' THEN 1 ELSE 0 END) AS processing,
                   SUM(CASE WHEN COALESCE(i.status, 'pending') = 'completed' THEN 1 ELSE 0 END) AS completed,
                   SUM(CASE WHEN COALESCE(i.status, 'pending') = 'failed' THEN 1 ELSE 0 END) AS failed
            FROM import_batches b
            LEFT JOIN batch_items i ON i.batch_id = b.batch_id
            GROUP BY b.batch_id
            ORDER BY b.created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def batch_pending_md5s(batch_id: str, limit: int) -> list[str]:
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            """
            SELECT i.md5
            FROM batch_items i
            JOIN sample_tasks t ON t.md5 = i.md5
            WHERE i.batch_id = ? AND COALESCE(i.status, 'pending') = 'pending'
            ORDER BY t.priority_score DESC, i.created_at ASC
            LIMIT ?
            """,
            (batch_id, limit),
        ).fetchall()
    return [row[0] for row in rows]


def update_task_status(md5: str, status: str) -> None:
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "UPDATE sample_tasks SET status = ?, updated_at = ? WHERE md5 = ?",
            (status, utc_now(), md5.upper().strip()),
        )
        conn.commit()


def update_batch_item_status(batch_id: str, md5: str, status: str) -> None:
    """Update one sample within one import batch without affecting other batches."""
    if not batch_id:
        return
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "UPDATE batch_items SET status = ?, updated_at = ? WHERE batch_id = ? AND md5 = ?",
            (status, utc_now(), batch_id, md5.upper().strip()),
        )
        conn.commit()


def reset_runtime_state() -> dict[str, int]:
    """Clear only the unfinished import and queue state from a prior run.

    Completed judgements, report cache entries and agent traces are historical
    assets. They must remain available after restarting the desktop program.
    """
    init_preprocess_tables()
    runtime_tables = (
        "batch_job_items",
        "batch_jobs",
        "batch_items",
        "import_batches",
        "sample_tasks",
        "sample_features",
        "feature_registry",
    )
    cleared: dict[str, int] = {}
    with closing(sqlite3.connect(DB_PATH)) as conn:
        for table in runtime_tables:
            try:
                cleared[table] = int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                conn.execute(f"DELETE FROM {table}")
            except sqlite3.OperationalError:
                cleared[table] = 0
        conn.commit()
    try:
        BLOOM_PATH.unlink(missing_ok=True)
    except OSError:
        pass
    return cleared


def stable_hash(payload: Any) -> str:
    return hashlib.sha1(json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def load_feature_context(md5: str) -> dict[str, Any]:
    init_preprocess_tables()
    md5 = md5.upper().strip()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT normalized_json, static_package_json, network_ioc_package_json, source, created_at
            FROM sample_features
            WHERE md5 = ?
            ORDER BY created_at DESC
            """,
            (md5,),
        ).fetchall()
    finally:
        conn.close()
    merged: dict[str, Any] = {"md5": md5, "feature_sources": []}
    static_packages = []
    network_packages = []
    for row in rows:
        normalized = json.loads(row["normalized_json"])
        merged.update({key: value for key, value in normalized.items() if value not in ("", None) and value != []})
        merged["feature_sources"].append(row["source"])
        static_packages.append(json.loads(row["static_package_json"]))
        network_packages.append(json.loads(row["network_ioc_package_json"]))
    if static_packages:
        merged["static_feature_package"] = static_packages[0]
    if network_packages:
        merged["network_ioc_package"] = merge_network_packages(network_packages)
    derive_engine_fields(merged)
    return merged


def merge_network_packages(packages: list[dict[str, Any]]) -> dict[str, Any]:
    merged = {"iocs": [], "urls": [], "domains": [], "top_domains": [], "ips": []}
    for package in packages:
        for key, value in package.items():
            if value in ("", None, [], {}):
                continue
            current = merged.get(key)
            if isinstance(current, list) and isinstance(value, list):
                if key == "iocs":
                    merged[key] = unique_structured_values(current + value)
                else:
                    merged[key] = unique_values(current + value)
            elif isinstance(current, dict) and isinstance(value, dict):
                merged[key] = {**current, **value}
            elif key not in merged or current in ("", None, [], {}):
                merged[key] = value
    return merged


def unique_structured_values(values: list[Any]) -> list[Any]:
    seen = set()
    result = []
    for value in values:
        marker = stable_hash(value) if isinstance(value, (dict, list)) else str(value)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


def cache_key_for_sample(sample: dict[str, Any]) -> str:
    from engine.model_settings import model_cache_signature

    md5 = str(sample.get("md5") or sample.get("sample_id") or "").upper().strip()
    signature = model_cache_signature()
    return hashlib.sha1(
        (ANALYSIS_CACHE_VERSION + md5 + stable_hash(sample) + signature).encode("utf-8")
    ).hexdigest()


def get_cached_report(sample: dict[str, Any]) -> dict[str, Any] | None:
    init_preprocess_tables()
    key = cache_key_for_sample(sample)
    now = utc_now()
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            "SELECT report_json FROM report_cache WHERE cache_key = ?",
            (key,),
        ).fetchone()
    finally:
        conn.close()
    return json.loads(row[0]) if row else None


def get_latest_cached_report_by_md5(md5: str) -> dict[str, Any] | None:
    init_preprocess_tables()
    md5 = str(md5 or "").upper().strip()
    if not md5:
        return None
    now = utc_now()
    conn = sqlite3.connect(DB_PATH)
    try:
        row = conn.execute(
            """
            SELECT report_json FROM report_cache
            WHERE md5 = ? AND expires_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (md5, now),
        ).fetchone()
    finally:
        conn.close()
    return json.loads(row[0]) if row else None


def set_cached_report(sample: dict[str, Any], report: dict[str, Any], ttl_hours: int = 24) -> None:
    init_preprocess_tables()
    key = cache_key_for_sample(sample)
    md5 = str(sample.get("md5") or sample.get("sample_id") or "").upper().strip()
    now_dt = datetime.now(timezone.utc)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO report_cache
            (cache_key, md5, report_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                key,
                md5,
                json.dumps(report, ensure_ascii=False),
                now_dt.isoformat(),
                (now_dt + timedelta(hours=ttl_hours)).isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def next_tasks(limit: int = 20) -> list[dict[str, Any]]:
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT md5, priority_score, priority_reason, source, status, updated_at
            FROM sample_tasks
            WHERE status = 'pending'
            ORDER BY priority_score DESC, updated_at ASC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def task_status_summary() -> dict[str, int]:
    """Return database totals for the task page without applying a list limit."""
    init_preprocess_tables()
    counts = {"pending": 0, "processing": 0, "completed": 0, "failed": 0}
    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM sample_tasks GROUP BY status"
        ).fetchall()
    for status, count in rows:
        if status in counts:
            counts[status] = int(count)
    counts["total"] = sum(counts.values())
    return counts


def pull_conflict_samples(limit: int = 1000) -> dict[str, Any]:
    """Pull A/B engine conflicts into the feature store and priority queue."""
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        if conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'engine_detections'"
        ).fetchone() is None:
            return {"pulled": 0}
        rows = conn.execute(
            """
            SELECT a.md5,
                   a.score AS engine_a_score,
                   b.score AS engine_b_score,
                   a.app_name AS engine_a_app_name,
                   b.app_name AS engine_b_app_name,
                   a.virus_name AS engine_a_virus_name,
                   b.virus_name AS engine_b_virus_name,
                   a.detect_type AS engine_a_label_text,
                   b.detect_type AS engine_b_label_text
            FROM engine_detections a
            JOIN engine_detections b ON a.md5 = b.md5
            WHERE a.engine = '360' AND b.engine = 'cm'
              AND (
                    abs(CAST(a.score AS REAL) - CAST(b.score AS REAL)) >= 35
                    OR a.detect_type <> b.detect_type
                  )
            ORDER BY abs(CAST(a.score AS REAL) - CAST(b.score AS REAL)) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    if not rows:
        return {"pulled": 0, "batch_id": ""}
    batch_id = create_import_batch("engine_conflict_auto_pull")
    imported = 0
    for row in rows:
        raw = dict(row)
        raw["conflict_type"] = "auto_engine_conflict"
        save_feature_record(
            raw,
            source="engine_conflict_auto_pull",
            payload_format="json",
            write_bloom=False,
            batch_id=batch_id,
        )
        imported += 1
    finalize_import_batch(batch_id)
    return {"pulled": imported, "batch_id": batch_id}


def preprocess_stats() -> dict[str, Any]:
    init_preprocess_tables()
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        tables = {}
        for name in ("feature_registry", "sample_features", "sample_tasks", "report_cache", "manual_labels"):
            tables[name] = conn.execute(f"SELECT COUNT(*) AS count FROM {name}").fetchone()["count"]
        sources = [
            dict(row)
            for row in conn.execute(
                "SELECT source, COUNT(*) AS count FROM sample_features GROUP BY source ORDER BY count DESC"
            ).fetchall()
        ]
        pending = [
            dict(row)
            for row in conn.execute(
                "SELECT priority_reason, COUNT(*) AS count FROM sample_tasks GROUP BY priority_reason ORDER BY count DESC"
            ).fetchall()
        ]
    return {"tables": tables, "feature_sources": sources, "task_reasons": pending, "bloom_bits": BLOOM_BITS}


def bloom_data() -> bytearray:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    size = math.ceil(BLOOM_BITS / 8)
    try:
        if BLOOM_PATH.exists():
            data = bytearray(BLOOM_PATH.read_bytes())
            if len(data) == size:
                return data
    except OSError:
        return bytearray(size)
    return bytearray(size)


def bloom_positions(value: str) -> list[int]:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    positions = []
    for index in range(BLOOM_HASHES):
        chunk = digest[index * 4 : index * 4 + 4]
        positions.append(int.from_bytes(chunk, "big") % BLOOM_BITS)
    return positions


def bloom_add(value: str) -> None:
    data = bloom_data()
    for pos in bloom_positions(value):
        data[pos // 8] |= 1 << (pos % 8)
    try:
        BLOOM_PATH.write_bytes(data)
    except OSError:
        pass


def bloom_contains(value: str) -> bool:
    data = bloom_data()
    return all(data[pos // 8] & (1 << (pos % 8)) for pos in bloom_positions(value))


def save_manual_label(raw: dict[str, Any], source_file: str) -> None:
    init_preprocess_tables()
    normalized, _ = normalize_feature_record(raw, source="manual_label")
    md5 = str(normalized.get("md5", "")).upper().strip()
    if not md5:
        return
    label = normalize_manual_label(normalized.get("human_label") or raw.get("人工审核结果") or "")
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            INSERT INTO manual_labels
            (md5, label, source_file, conflict_type, raw_json, imported_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(md5) DO UPDATE SET
                label=excluded.label,
                source_file=excluded.source_file,
                conflict_type=excluded.conflict_type,
                raw_json=excluded.raw_json,
                imported_at=excluded.imported_at
            """,
            (
                md5,
                label,
                source_file,
                str(normalized.get("conflict_type") or raw.get("冲突类型") or ""),
                json.dumps(raw, ensure_ascii=False),
                utc_now(),
            ),
        )


def normalize_manual_label(value: Any) -> str:
    text = str(value).strip()
    if text in {"100", "1", "恶意", "malicious"}:
        return "malicious"
    if text in {"0", "白", "白样本", "良性", "benign"}:
        return "benign"
    if text in {"50", "可疑", "疑似", "suspicious"}:
        return "suspicious"
    return text or "unknown"
