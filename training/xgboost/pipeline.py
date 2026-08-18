from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "training_artifacts" / "xgb"
os.environ.setdefault("MPLCONFIGDIR", str(OUTPUT / ".matplotlib"))

import numpy as np  # noqa: E402
import xgboost as xgb  # noqa: E402

from malapp.governance.artifacts import build_xgboost_manifest  # noqa: E402
from malapp.governance.leakage import require_training_clearance  # noqa: E402
from training import pipeline as base  # noqa: E402

DB_PATH = OUTPUT / "xgb_training.db"
GENUINE_SQL = ROOT / "genuine_new.sql"
AGENTS = base.AGENTS
SPLITS = ("train", "stack", "val", "test")
WEAK_CONSENSUS_BENIGN_LIMIT = 24000
SQL_COLUMNS = (
    "id", "md5", "appid", "app_name", "alias_name", "app_version",
    "app_type", "app_subtype", "app_thirdtype", "sign_md5", "sign_sha1",
    "issuer", "owner", "serial", "icon_finger", "icon_base64", "app_dev",
    "app_dev_english", "app_dev_traditional", "packagename", "app_page",
    "status", "person", "author", "update_time", "file_sha1", "sign_sha256",
    "appname_unify",
)

FEATURES = {
    "static_analysis": [
        "has_signature_md5", "has_signature_sha1", "has_signature_sha256",
        "genuine_signature_match", "packer_present", "sdk_count",
        "file_size_log", "file_deleted", "platform_android", "engine_feature_coverage",
    ],
    "threat_intel": [
        "control_ioc_count", "download_ioc_count", "has_malware_family",
        "has_hacker_group", "has_anti_fraud_tag", "description_risk_terms",
        "engine_feature_coverage",
    ],
    "impersonation": [
        "fake_app", "impersonation_flag",
        "pirated_version", "has_official_reference", "official_md5_match",
        "genuine_md5_match", "genuine_name_match", "genuine_package_match",
        "genuine_signature_match", "name_obfuscation", "app_name_length",
        "impersonation_category_count", "engine_feature_coverage",
    ],
    "business_label": [
        "fraud_flag", "has_fraud_category", "has_harm_type", "has_anti_fraud_tag",
        "app_name_risk_terms", "description_risk_terms", "has_malware_family",
        "engine_feature_coverage",
    ],
}


def progress(message: str) -> None:
    print(f"[xgb] {message}", file=sys.stderr, flush=True)


def connect() -> sqlite3.Connection:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS genuine_apps (
            md5 TEXT PRIMARY KEY, app_name TEXT, alias_name TEXT, package_name TEXT,
            sign_md5 TEXT, sign_sha1 TEXT, sign_sha256 TEXT, issuer TEXT, owner TEXT,
            icon_finger TEXT, app_type TEXT, app_subtype TEXT, app_thirdtype TEXT,
            developer TEXT, status INTEGER
        );
        CREATE INDEX IF NOT EXISTS genuine_name_idx ON genuine_apps(app_name);
        CREATE INDEX IF NOT EXISTS genuine_package_idx ON genuine_apps(package_name);
        CREATE INDEX IF NOT EXISTS genuine_sign_md5_idx ON genuine_apps(sign_md5);
        CREATE INDEX IF NOT EXISTS genuine_sign_sha1_idx ON genuine_apps(sign_sha1);
        CREATE INDEX IF NOT EXISTS genuine_sign_sha256_idx ON genuine_apps(sign_sha256);
        CREATE TABLE IF NOT EXISTS engine_all (
            md5 TEXT PRIMARY KEY, engine_a_json TEXT, engine_b_json TEXT
        );
        CREATE TABLE IF NOT EXISTS xgb_samples (
            md5 TEXT PRIMARY KEY, label INTEGER NOT NULL, label_source TEXT NOT NULL,
            sample_weight REAL NOT NULL, split TEXT NOT NULL, group_id TEXT NOT NULL,
            payload_json TEXT NOT NULL, features_json TEXT NOT NULL
        );
        """
    )
    return conn


def parse_sql_tuple(source: str) -> list[Any]:
    source = source.strip()
    if source.endswith(");"):
        source = source[:-2]
    values: list[Any] = []
    token: list[str] = []
    quoted = False
    escaped = False
    for char in source:
        if quoted:
            if escaped:
                token.append({"n": "\n", "r": "\r", "t": "\t"}.get(char, char))
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "'":
                quoted = False
            else:
                token.append(char)
        elif char == "'":
            quoted = True
        elif char == ",":
            values.append(sql_value("".join(token)))
            token.clear()
        else:
            token.append(char)
    values.append(sql_value("".join(token)))
    return values


def iter_sql_records(path: Path) -> Iterable[str]:
    marker = b"INSERT INTO `genuine_new` VALUES ("
    buffer = b""
    started = False
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            buffer += chunk
            if not started:
                position = buffer.find(marker)
                if position < 0:
                    buffer = buffer[-len(marker) :]
                    continue
                buffer = buffer[position + len(marker) :]
                started = True
            while True:
                position = buffer.find(marker)
                if position < 0:
                    break
                record = buffer[:position]
                yield record.decode("utf-8", errors="replace")
                buffer = buffer[position + len(marker) :]
        if started and buffer:
            end = buffer.find(b"UNLOCK TABLES")
            if end >= 0:
                buffer = buffer[:end]
            yield buffer.decode("utf-8", errors="replace")


def sql_value(value: str) -> Any:
    value = value.strip()
    if value.upper() == "NULL":
        return ""
    return value


def import_genuine(conn: sqlite3.Connection) -> dict[str, int]:
    conn.execute("DELETE FROM genuine_apps")
    batch = []
    parsed = invalid = 0
    for statement in iter_sql_records(GENUINE_SQL):
        values = parse_sql_tuple(statement)
        if len(values) % len(SQL_COLUMNS):
            invalid += 1
            continue
        for offset in range(0, len(values), len(SQL_COLUMNS)):
            record = values[offset : offset + len(SQL_COLUMNS)]
            record[0] = str(record[0]).lstrip(" \r\n),(")
            record[-1] = str(record[-1]).rstrip(" \r\n),;(")
            row = dict(zip(SQL_COLUMNS, record, strict=False))
            md5 = base.md5_value(row["md5"])
            if not md5:
                invalid += 1
                continue
            batch.append(
                (
                    md5,
                    clean_text(row["app_name"]),
                    clean_text(row["alias_name"]),
                    clean_text(row["packagename"]).lower(),
                    clean_hash(row["sign_md5"]),
                    clean_hash(row["sign_sha1"]),
                    clean_hash(row["sign_sha256"]),
                    clean_text(row["issuer"]),
                    clean_text(row["owner"]),
                    clean_text(row["icon_finger"]),
                    clean_text(row["app_type"]),
                    clean_text(row["app_subtype"]),
                    clean_text(row["app_thirdtype"]),
                    clean_text(row["app_dev"]),
                    int(row["status"] or 0),
                )
            )
            parsed += 1
            if len(batch) >= 500:
                conn.executemany(
                    "INSERT OR REPLACE INTO genuine_apps VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    batch,
                )
                conn.commit()
                batch.clear()
            if parsed % 5000 == 0:
                progress(f"正版库已解析 {parsed:,} 条")
    if batch:
        conn.executemany(
            "INSERT OR REPLACE INTO genuine_apps VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            batch,
        )
        conn.commit()
    return {"genuine_parsed": parsed, "genuine_invalid": invalid}


def import_engines(conn: sqlite3.Connection) -> dict[str, int]:
    conn.execute("DELETE FROM engine_all")
    stats = Counter()
    for engine, path in base.ENGINE_FILES.items():
        column = f"{engine}_json"
        batch = []
        for index, raw in enumerate(base.iter_sheet(path), start=1):
            row = base.normalized_row(raw)
            md5 = base.md5_value(row.get("md5"))
            if not md5:
                continue
            compact = compact_payload(row, engine)
            batch.append((md5, json.dumps(compact, ensure_ascii=False)))
            if len(batch) >= 1000:
                conn.executemany(
                    f"""
                    INSERT INTO engine_all(md5,{column}) VALUES (?,?)
                    ON CONFLICT(md5) DO UPDATE SET {column}=excluded.{column}
                    """,
                    batch,
                )
                conn.commit()
                stats[f"{engine}_rows"] += len(batch)
                batch.clear()
            if index % 20000 == 0:
                progress(f"{engine} 已读取 {index:,} 行")
        if batch:
            conn.executemany(
                f"""
                INSERT INTO engine_all(md5,{column}) VALUES (?,?)
                ON CONFLICT(md5) DO UPDATE SET {column}=excluded.{column}
                """,
                batch,
            )
            conn.commit()
            stats[f"{engine}_rows"] += len(batch)
    return dict(stats)


def compact_payload(row: dict[str, Any], engine: str) -> dict[str, Any]:
    keep = {
        "md5", "app_name", "virus_name", "virus_description", "engine_label_text",
        "engine_score", "harm_type", "fake_app", "packer", "platform", "file_size",
        "control_url", "download_url", "control_mailbox", "control_phone",
        "anti_fraud_tag", "app_version_status", "fraud_flag", "fraud_category_big",
        "fraud_category_small", "fraud_family", "impersonation_flag", "official_pkg",
        "official_app_name", "official_md5", "impersonation_level1",
        "impersonation_level2", "impersonation_level3", "sdk_list", "file_type",
        "certificate_fingerprint", "cert_sha1", "cert_sha256", "hacker_group",
        "file_deleted", "sample_app_id", "developer_name", "certificate_owner",
        "certificate_developer",
    }
    result = {key: value for key, value in row.items() if key in keep and base.present(value)}
    score = base.numeric(row.get("engine_score"))
    result[f"{engine}_score"] = score
    result[f"{engine}_label"] = base.label_from_engine(row.get("engine_label_text"), score)
    result.pop("engine_score", None)
    result.pop("engine_label_text", None)
    return result


def load_reference_sets(conn: sqlite3.Connection) -> dict[str, set[str]]:
    result = {
        "md5": set(), "name": set(), "package": set(),
        "sign_md5": set(), "sign_sha1": set(), "sign_sha256": set(),
    }
    for row in conn.execute(
        "SELECT md5,app_name,alias_name,package_name,sign_md5,sign_sha1,sign_sha256 "
        "FROM genuine_apps WHERE status=1"
    ):
        result["md5"].add(row[0])
        if normalize_name(row[1]):
            result["name"].add(normalize_name(row[1]))
        for alias in str(row[2] or "").split("|"):
            if normalize_name(alias):
                result["name"].add(normalize_name(alias))
        if row[3]:
            result["package"].add(str(row[3]).lower())
        for key, value in zip(("sign_md5", "sign_sha1", "sign_sha256"), row[4:], strict=False):
            if value:
                result[key].add(str(value).lower())
    return result


def build_samples(conn: sqlite3.Connection) -> dict[str, int]:
    conn.execute("DELETE FROM xgb_samples")
    labels: dict[str, tuple[int, str, float, str, str]] = {}
    source_db = sqlite3.connect(base.DB_PATH)
    try:
        for md5, label, source, group_id, payload_json in source_db.execute(
            "SELECT md5,label,label_source,group_id,payload_json "
            "FROM unified_samples WHERE label IS NOT NULL"
        ):
            weight = 1.0 if source in {"known_malicious", "known_white"} else 0.9
            labels[md5] = (int(label), source, weight, group_id, payload_json)
    finally:
        source_db.close()

    references = load_reference_sets(conn)
    stats = Counter()
    weak_candidates: list[tuple[str, str, str, dict[str, Any]]] = []
    rows = conn.execute("SELECT md5,engine_a_json,engine_b_json FROM engine_all")
    batch = []
    for index, (md5, a_json, b_json) in enumerate(rows, start=1):
        payload = merge_payloads(a_json, b_json)
        explicit = labels.get(md5)
        if explicit:
            label, source, weight, group_id, original_json = explicit
            original = json.loads(original_json)
            payload.update({k: v for k, v in original.items() if base.present(v)})
        else:
            a_label = payload.get("engine_a_label")
            b_label = payload.get("engine_b_label")
            if md5 in references["md5"]:
                label, source, weight = 0, "genuine_md5_benign", 1.0
            elif a_label == b_label == "benign":
                weak_candidates.append((md5, a_json or "", b_json or "", payload))
                continue
            else:
                continue
            group_id = base.sample_group({"md5": md5, **payload})
        split = model_split(group_id)
        features = feature_vector(md5, payload, references)
        batch.append(
            (
                md5, label, source, weight, split, group_id,
                json.dumps(payload, ensure_ascii=False),
                json.dumps(features, ensure_ascii=False),
            )
        )
        stats[f"{source}_{split}"] += 1
        if len(batch) >= 1000:
            conn.executemany(
                "INSERT OR REPLACE INTO xgb_samples VALUES (?,?,?,?,?,?,?,?)", batch
            )
            conn.commit()
            batch.clear()
        if index % 20000 == 0:
            progress(f"已构建候选训练样本 {index:,} 条引擎记录")
    # A/B 一致良性是弱标签，只按 MD5 稳定抽取有限规模，防止其数量压过强标签。
    weak_candidates.sort(
        key=lambda item: hashlib.sha1(item[0].encode("ascii")).hexdigest()
    )
    for md5, _, _, payload in weak_candidates[:WEAK_CONSENSUS_BENIGN_LIMIT]:
        label, source, weight = 0, "weak_consensus_benign", 0.35
        group_id = base.sample_group({"md5": md5, **payload})
        split = weak_model_split(group_id)
        features = feature_vector(md5, payload, references)
        batch.append(
            (
                md5, label, source, weight, split, group_id,
                json.dumps(payload, ensure_ascii=False),
                json.dumps(features, ensure_ascii=False),
            )
        )
        stats[f"{source}_{split}"] += 1
    if batch:
        conn.executemany(
            "INSERT OR REPLACE INTO xgb_samples VALUES (?,?,?,?,?,?,?,?)", batch
        )
        conn.commit()
    stats["weak_consensus_benign_available"] = len(weak_candidates)
    stats["weak_consensus_benign_selected"] = min(
        len(weak_candidates), WEAK_CONSENSUS_BENIGN_LIMIT
    )
    return dict(stats)


def merge_payloads(a_json: str | None, b_json: str | None) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw in (a_json, b_json):
        if not raw:
            continue
        current = json.loads(raw)
        for key, value in current.items():
            if base.present(value) and not base.present(result.get(key)):
                result[key] = value
            elif key.startswith("engine_"):
                result[key] = value
    return result


def feature_vector(md5: str, sample: dict[str, Any], refs: dict[str, set[str]]) -> dict[str, float]:
    a = base.score_probability(sample.get("engine_a_score"), sample.get("engine_a_label"))
    b = base.score_probability(sample.get("engine_b_score"), sample.get("engine_b_label"))
    name = str(sample.get("app_name") or "")
    package = str(sample.get("sample_app_id") or sample.get("official_pkg") or "").lower()
    sign_md5 = clean_hash(sample.get("certificate_fingerprint"))
    sign_sha1 = clean_hash(sample.get("cert_sha1"))
    sign_sha256 = clean_hash(sample.get("cert_sha256"))
    text = " ".join(
        str(sample.get(key) or "").lower()
        for key in ("virus_name", "virus_description", "harm_type", "fraud_category_big",
                    "fraud_category_small", "anti_fraud_tag")
    )
    risk_terms = ("恶意", "木马", "病毒", "窃取", "涉诈", "诈骗", "勒索", "远控", "钓鱼")
    name_terms = ("贷款", "博彩", "赌博", "投资", "刷单", "返利", "钱包", "支付")
    sdk = sample.get("sdk_list")
    sdk_count = len(sdk) if isinstance(sdk, list) else len([x for x in re.split(r"[,|;]", str(sdk or "")) if x.strip()])
    size = base.numeric(sample.get("file_size")) or 0.0
    official_md5 = base.md5_value(sample.get("official_md5"))
    return {
        "engine_a_prob": a,
        "engine_b_prob": b,
        "engine_score_gap": abs(a - b),
        "engine_disagreement": float(sample.get("engine_a_label") != sample.get("engine_b_label")),
        "engine_feature_coverage": float(bool(sample.get("engine_a_label"))) + float(bool(sample.get("engine_b_label"))),
        "has_signature_md5": float(bool(sign_md5)),
        "has_signature_sha1": float(bool(sign_sha1)),
        "has_signature_sha256": float(bool(sign_sha256)),
        "genuine_signature_match": float(bool(
            (sign_md5 and sign_md5 in refs["sign_md5"])
            or (sign_sha1 and sign_sha1 in refs["sign_sha1"])
            or (sign_sha256 and sign_sha256 in refs["sign_sha256"])
        )),
        "packer_present": float(base.truthy(sample.get("packer"))),
        "sdk_count": float(min(sdk_count, 30)),
        "file_size_log": math.log1p(max(size, 0.0)),
        "file_deleted": float(base.truthy(sample.get("file_deleted"))),
        "platform_android": float("android" in str(sample.get("platform") or "").lower()),
        "control_ioc_count": float(sum(base.present(sample.get(k)) for k in ("control_url", "control_mailbox", "control_phone"))),
        "download_ioc_count": float(base.present(sample.get("download_url"))),
        "has_malware_family": float(base.present(sample.get("virus_name")) or base.present(sample.get("fraud_family"))),
        "has_hacker_group": float(base.present(sample.get("hacker_group"))),
        "has_anti_fraud_tag": float(base.present(sample.get("anti_fraud_tag"))),
        "description_risk_terms": float(sum(term in text for term in risk_terms)),
        "fake_app": float(base.truthy(sample.get("fake_app"))),
        "impersonation_flag": float(base.truthy(sample.get("impersonation_flag"))),
        "pirated_version": float(str(sample.get("app_version_status") or "").strip() == "2"),
        "has_official_reference": float(any(base.present(sample.get(k)) for k in ("official_pkg", "official_app_name", "official_md5"))),
        "official_md5_match": float(bool(official_md5) and official_md5 in refs["md5"]),
        "genuine_md5_match": float(md5 in refs["md5"]),
        "genuine_name_match": float(normalize_name(name) in refs["name"] if normalize_name(name) else False),
        "genuine_package_match": float(package in refs["package"] if package else False),
        "name_obfuscation": float(bool(re.search(r"\d{2,}$", name)) or bool(base.INVISIBLE_RE.search(name))),
        "app_name_length": float(min(len(name), 100)),
        "impersonation_category_count": float(sum(base.present(sample.get(k)) for k in ("impersonation_level1", "impersonation_level2", "impersonation_level3"))),
        "fraud_flag": float(str(sample.get("fraud_flag") or "").strip() in {"1", "是", "true"}),
        "has_fraud_category": float(any(base.present(sample.get(k)) for k in ("fraud_category_big", "fraud_category_small", "fraud_family"))),
        "has_harm_type": float(base.present(sample.get("harm_type"))),
        "app_name_risk_terms": float(sum(term in name.lower() for term in name_terms)),
    }


def train() -> dict[str, Any]:
    conn = connect()
    model_dir = OUTPUT / "models"
    curve_dir = OUTPUT / "curves"
    model_dir.mkdir(parents=True, exist_ok=True)
    curve_dir.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {"agents": {}}
    agent_models: dict[str, xgb.XGBClassifier] = {}
    try:
        records = load_records(conn)
        for agent in AGENTS:
            model, metrics, history = fit_model(records, FEATURES[agent], agent)
            agent_models[agent] = model
            model.save_model(model_dir / f"{agent}.json")
            save_curve(curve_dir / f"{agent}_loss.png", history, f"{agent} logloss")
            report["agents"][agent] = metrics

        stacked = stack_records(records, agent_models)
        fusion_features = [f"{agent}_prob" for agent in AGENTS]
        fusion, fusion_metrics, fusion_history = fit_model(
            stacked, fusion_features, "fusion", train_split="stack", validation_split="val"
        )
        fusion.save_model(model_dir / "fusion.json")
        save_curve(curve_dir / "fusion_loss.png", fusion_history, "fusion logloss")
        report["fusion"] = fusion_metrics

        wec_rows = add_wec_features(stacked, fusion, fusion_features)
        wec_features = [
            "engine_a_prob", "engine_b_prob", "engine_c_prob",
            "engine_score_gap", "engine_disagreement",
        ]
        wec, wec_metrics, wec_history = fit_model(
            wec_rows, wec_features, "wec", train_split="stack", validation_split="val"
        )
        wec.save_model(model_dir / "wec.json")
        save_curve(curve_dir / "wec_loss.png", wec_history, "WEC logloss")
        report["wec"] = wec_metrics

        thresholds = learn_thresholds(wec_rows, wec, wec_features)
        (model_dir / "thresholds.json").write_text(
            json.dumps(thresholds, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        report["thresholds"] = thresholds
        report["test"] = evaluate_split(wec_rows, wec, wec_features, "test", thresholds)
        export_test_set(conn, wec_rows, wec, wec_features, thresholds)
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        write_runtime_manifest(model_dir, thresholds, report)
    finally:
        conn.close()
    (OUTPUT / "training_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report


def load_records(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [
        {
            "md5": md5, "label": int(label), "label_source": source,
            "sample_weight": float(weight), "split": split,
            **json.loads(features_json),
        }
        for md5, label, source, weight, split, features_json
        in conn.execute(
            "SELECT md5,label,label_source,sample_weight,split,features_json FROM xgb_samples"
        )
    ]


def fit_model(
    rows: list[dict[str, Any]],
    features: list[str],
    name: str,
    train_split: str = "train",
    validation_split: str = "val",
) -> tuple[xgb.XGBClassifier, dict[str, Any], dict[str, list[float]]]:
    train_rows = [r for r in rows if r["split"] == train_split]
    val_rows = [r for r in rows if r["split"] == validation_split]
    x_train, y_train, w_train = arrays(train_rows, features)
    x_val, y_val, _ = arrays(val_rows, features)
    model = xgb.XGBClassifier(
        n_estimators=1200,
        max_depth=5,
        learning_rate=0.035,
        min_child_weight=5,
        subsample=0.82,
        colsample_bytree=0.85,
        reg_alpha=0.1,
        reg_lambda=1.5,
        objective="binary:logistic",
        eval_metric="logloss",
        tree_method="hist",
        random_state=20260612,
        n_jobs=max(1, min(8, (base.os.cpu_count() or 4))),
        early_stopping_rounds=70,
    )
    model.fit(
        x_train, y_train, sample_weight=w_train,
        eval_set=[(x_train, y_train), (x_val, y_val)],
        verbose=False,
    )
    history = model.evals_result()
    metrics = {
        "train": metrics_for(model, train_rows, features),
        "validation": metrics_for(model, val_rows, features),
        "test": metrics_for(model, [r for r in rows if r["split"] == "test"], features),
        "best_iteration": int(model.best_iteration),
        "final_train_logloss": history["validation_0"]["logloss"][model.best_iteration],
        "final_validation_logloss": history["validation_1"]["logloss"][model.best_iteration],
        "feature_importance": sorted(
            zip(features, model.feature_importances_.tolist(), strict=False),
            key=lambda item: item[1], reverse=True,
        ),
    }
    progress(
        f"{name}: best_iteration={model.best_iteration}, "
        f"val_logloss={metrics['final_validation_logloss']:.6f}"
    )
    return model, metrics, history


def stack_records(rows: list[dict[str, Any]], models: dict[str, xgb.XGBClassifier]) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        current = dict(row)
        for agent, model in models.items():
            current[f"{agent}_prob"] = float(
                model.predict_proba(np.asarray([[row.get(f, 0.0) for f in FEATURES[agent]]]))[0, 1]
            )
        result.append(current)
    return result


def add_wec_features(
    rows: list[dict[str, Any]], fusion: xgb.XGBClassifier, features: list[str]
) -> list[dict[str, Any]]:
    result = []
    for row in rows:
        current = dict(row)
        current["engine_c_prob"] = float(
            fusion.predict_proba(np.asarray([[row.get(f, 0.0) for f in features]]))[0, 1]
        )
        result.append(current)
    return result


def arrays(rows: list[dict[str, Any]], features: list[str]):
    x_values = np.asarray([[float(r.get(f, 0.0)) for f in features] for r in rows], dtype=np.float32)
    labels = np.asarray([r["label"] for r in rows], dtype=np.int32)
    weights = np.asarray([r.get("sample_weight", 1.0) for r in rows], dtype=np.float32)
    return x_values, labels, weights


def metrics_for(model, rows: list[dict[str, Any]], features: list[str]) -> dict[str, Any]:
    from sklearn.metrics import (
        accuracy_score,
        balanced_accuracy_score,
        brier_score_loss,
        log_loss,
        precision_recall_fscore_support,
        roc_auc_score,
    )

    if not rows:
        return {"count": 0}
    x_values, labels, _ = arrays(rows, features)
    probabilities = model.predict_proba(x_values)[:, 1]
    predictions = (probabilities >= 0.5).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        labels, predictions, average="binary", zero_division=0
    )
    return {
        "count": len(rows),
        "positive": int(labels.sum()),
        "negative": int(len(labels) - labels.sum()),
        "accuracy": round(float(accuracy_score(labels, predictions)), 6),
        "balanced_accuracy": round(float(balanced_accuracy_score(labels, predictions)), 6),
        "precision": round(float(precision), 6),
        "recall": round(float(recall), 6),
        "f1": round(float(f1), 6),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6) if len(set(labels)) > 1 else None,
        "logloss": round(float(log_loss(labels, probabilities)), 6),
        "brier": round(float(brier_score_loss(labels, probabilities)), 6),
    }


def learn_thresholds(
    rows: list[dict[str, Any]], model, features: list[str]
) -> dict[str, Any]:
    validation = [r for r in rows if r["split"] == "val"]
    x_values, labels, _ = arrays(validation, features)
    probabilities = model.predict_proba(x_values)[:, 1]
    best = None
    for lower in np.arange(0.05, 0.71, 0.01):
        for upper in np.arange(max(lower + 0.05, 0.30), 0.96, 0.01):
            benign = probabilities < lower
            malicious = probabilities >= upper
            review = ~(benign | malicious)
            false_benign = int(np.sum(benign & (labels == 1)))
            false_malicious = int(np.sum(malicious & (labels == 0)))
            review_count = int(review.sum())
            # 漏报成本最高，其次误报，人工复核有较低成本。
            total_cost = false_benign * 8.0 + false_malicious * 4.0 + review_count * 0.25
            normalized = total_cost / max(1, len(labels))
            candidate = (normalized, review_count, -int(malicious.sum()), float(lower), float(upper))
            if best is None or candidate < best:
                best = candidate
    assert best is not None
    return {
        "method": "validation_cost_minimization",
        "benign_threshold": round(best[3], 4),
        "malicious_threshold": round(best[4], 4),
        "validation_cost": round(best[0], 6),
        "validation_review_count": best[1],
        "costs": {"false_benign": 8.0, "false_malicious": 4.0, "manual_review": 0.25},
        "note": "阈值由验证集自动学习，中间区间进入可疑/人工复核。",
    }


def evaluate_split(rows, model, features, split, thresholds):
    from sklearn.metrics import log_loss, roc_auc_score

    selected = [r for r in rows if r["split"] == split]
    x_values, labels, _ = arrays(selected, features)
    probabilities = model.predict_proba(x_values)[:, 1]
    verdicts = np.where(
        probabilities < thresholds["benign_threshold"], "benign",
        np.where(probabilities >= thresholds["malicious_threshold"], "malicious", "suspicious"),
    )
    decided = verdicts != "suspicious"
    correct = ((verdicts == "malicious") & (labels == 1)) | ((verdicts == "benign") & (labels == 0))
    return {
        "count": len(selected),
        "positive": int(labels.sum()),
        "negative": int(len(labels) - labels.sum()),
        "benign": int(np.sum(verdicts == "benign")),
        "suspicious_review": int(np.sum(verdicts == "suspicious")),
        "malicious": int(np.sum(verdicts == "malicious")),
        "coverage": round(float(decided.mean()), 6),
        "decided_accuracy": round(float(correct[decided].mean()), 6) if decided.any() else 0.0,
        "false_benign": int(np.sum((verdicts == "benign") & (labels == 1))),
        "false_malicious": int(np.sum((verdicts == "malicious") & (labels == 0))),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 6),
        "logloss": round(float(log_loss(labels, probabilities)), 6),
    }


def export_test_set(conn, rows, model, features, thresholds):
    from openpyxl import Workbook

    test_rows = [r for r in rows if r["split"] == "test"]
    x_values, _, _ = arrays(test_rows, features)
    probabilities = model.predict_proba(x_values)[:, 1]
    payloads = {
        md5: json.loads(payload)
        for md5, payload in conn.execute(
            "SELECT md5,payload_json FROM xgb_samples WHERE split='test'"
        )
    }
    output_rows = []
    for row, probability in zip(test_rows, probabilities, strict=False):
        verdict = (
            "良性" if probability < thresholds["benign_threshold"]
            else "恶意" if probability >= thresholds["malicious_threshold"]
            else "可疑"
        )
        payload = payloads.get(row["md5"], {})
        output_rows.append(
            {
                "md5": row["md5"],
                "app_name": payload.get("app_name", ""),
                "gold_label": "恶意" if row["label"] else "良性",
                "label_source": row["label_source"],
                "sample_weight": row["sample_weight"],
                "xgb_probability": round(float(probability), 6),
                "xgb_verdict": verdict,
                "engine_a_score": payload.get("engine_a_score", ""),
                "engine_b_score": payload.get("engine_b_score", ""),
            }
        )
    csv_path = OUTPUT / "test_set_for_app.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(output_rows[0]) if output_rows else ["md5"])
        writer.writeheader()
        writer.writerows(output_rows)
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "独立测试集"
    if output_rows:
        sheet.append(list(output_rows[0]))
        for row in output_rows:
            sheet.append(list(row.values()))
    workbook.save(OUTPUT / "test_set_for_app.xlsx")


def save_curve(path: Path, history: dict[str, Any], title: str) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.figure(figsize=(8, 5))
    plt.plot(history["validation_0"]["logloss"], label="Train LogLoss")
    plt.plot(history["validation_1"]["logloss"], label="Validation LogLoss")
    plt.xlabel("Boosting round")
    plt.ylabel("LogLoss")
    plt.title(title)
    plt.legend()
    plt.grid(alpha=0.25)
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def write_runtime_manifest(
    model_dir: Path,
    thresholds: dict[str, Any],
    metrics: dict[str, Any],
) -> None:
    manifest = build_xgboost_manifest(
        model_dir=model_dir,
        database_path=DB_PATH,
        agents={agent: FEATURES[agent] for agent in AGENTS},
        fusion_features=[f"{agent}_prob" for agent in AGENTS],
        wec_features=[
            "engine_a_prob",
            "engine_b_prob",
            "engine_c_prob",
            "engine_score_gap",
            "engine_disagreement",
        ],
        thresholds=thresholds,
        metrics=metrics,
        model_version="xgb-runtime-v1",
    )
    (model_dir / "runtime_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )


def model_split(group_id: str) -> str:
    bucket = int(hashlib.sha1(group_id.encode()).hexdigest()[:8], 16) % 100
    if bucket < 60:
        return "train"
    if bucket < 70:
        return "stack"
    if bucket < 85:
        return "val"
    return "test"


def weak_model_split(group_id: str) -> str:
    bucket = int(hashlib.sha1(group_id.encode()).hexdigest()[:8], 16) % 100
    return "train" if bucket < 85 else "stack"


def normalize_name(value: Any) -> str:
    return re.sub(r"[\s._\-·]+", "", str(value or "").lower())


def clean_text(value: Any) -> str:
    return str(value or "").strip()


def clean_hash(value: Any) -> str:
    return re.sub(r"[^0-9a-f]", "", str(value or "").lower())


def prepare(force: bool = False) -> dict[str, Any]:
    conn = connect()
    try:
        report = {}
        genuine_count = conn.execute("SELECT COUNT(*) FROM genuine_apps").fetchone()[0]
        engine_count = conn.execute("SELECT COUNT(*) FROM engine_all").fetchone()[0]
        if force or not genuine_count:
            report.update(import_genuine(conn))
        else:
            report["genuine_reused"] = genuine_count
        if force or not engine_count:
            report.update(import_engines(conn))
        else:
            report["engine_rows_reused"] = engine_count
        report["sample_sources"] = build_samples(conn)
        report["total_samples"] = conn.execute("SELECT COUNT(*) FROM xgb_samples").fetchone()[0]
        report["splits"] = dict(
            conn.execute("SELECT split,COUNT(*) FROM xgb_samples GROUP BY split").fetchall()
        )
    finally:
        conn.close()
    (OUTPUT / "prepare_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="XGBoost 四智能体、融合、WEC 和阈值训练")
    parser.add_argument("command", choices=("prepare", "train", "all"))
    parser.add_argument("--force", action="store_true", help="强制重新解析 SQL 和两个引擎大表")
    parser.add_argument("--dataset-manifest")
    args = parser.parse_args()
    result = {}
    if args.command in {"prepare", "all"}:
        result["prepare"] = prepare(force=args.force)
    if args.command in {"train", "all"}:
        if not args.dataset_manifest:
            parser.error("--dataset-manifest is required for train/all")
        require_training_clearance(Path(args.dataset_manifest))
        result["train"] = train()
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
