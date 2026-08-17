from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

VALID_LABELS = {"malicious", "benign"}
MD5_PATTERN = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
RESERVED_SAMPLE_FIELD_PATTERN = re.compile(
    r'"(?:id|sample_id|md5)"\s*:\s*"([0-9A-Fa-f]{32})(?=[":])',
    re.IGNORECASE,
)
SYSTEM_PROMPT = (
    "你是MalApp恶意应用研判助手。只能依据给定字段和证据作答，不得补造事实；"
    "输出一个简洁、合法的JSON对象，字段为verdict、risk_level、confidence、evidence_refs、review_required。"
)


@dataclass(frozen=True)
class TrainingCorpusTargets:
    sft_core: int = 5000
    sft_expansion: int = 5000
    dpo: int = 3000
    rag: int = 2000
    agent_success: int = 1000
    agent_fault_recovery: int = 400
    calibration: int = 800


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def normalize_md5(value: Any) -> str:
    text = str(value or "").strip().upper()
    return text if re.fullmatch(r"[0-9A-F]{32}", text) else ""


def clean_text(value: Any, limit: int = 500) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    if text.lower() in {"", "nan", "none", "null", "unknown", "未知"}:
        return ""
    return text[:limit]


def safe_json_loads(value: Any, default: Any = None) -> Any:
    if value in {None, ""}:
        return default
    try:
        return json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError, json.JSONDecodeError):
        return default


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def extract_md5s_from_text(text: str) -> set[str]:
    return {match.group(1).upper() for match in MD5_PATTERN.finditer(text or "")}


def _scan_reserved_file(path: Path) -> set[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if path.suffix.lower() == ".txt":
            return extract_md5s_from_text(text)
        # Evaluation payloads contain certificate hashes and retrieved evidence.
        # Only sample identity fields define a training boundary; reserving every
        # 32-hex token would incorrectly exclude unrelated APPs sharing evidence.
        return {
            match.group(1).upper()
            for match in RESERVED_SAMPLE_FIELD_PATTERN.finditer(text)
        }
    except OSError:
        return set()


def collect_reserved_ids(data_dir: Path, project_root: Path) -> tuple[set[str], list[dict[str, Any]]]:
    """Collect hard evaluation boundaries without reserving diagnostic/replay-only data."""
    wanted_names = {
        "expert_gold_holdout.jsonl",
        "model_release_holdout.jsonl",
        "model_schema_challenges.jsonl",
        "fresh_expert_holdout_candidates.jsonl",
        "rag_retrieval_eval.jsonl",
        "evidence_faithfulness_eval.jsonl",
        "agent_trace_eval.jsonl",
        "agent_fault_eval.jsonl",
        "agent_ablation_eval.jsonl",
        "end_to_end_release_holdout.jsonl",
        "end_to_end_challenge_eval.jsonl",
        "challenge_candidates.jsonl",
        "expert_core_candidates.jsonl",
        "rag_retrieval_candidates.jsonl",
        "review_state.json",
    }
    candidates: list[tuple[Path, str]] = []
    evaluation_dir = data_dir / "evaluation"
    if evaluation_dir.exists():
        # Only the current active suite is a hard boundary. Historical suites are
        # diagnostics that must be re-baselined after training; unioning every
        # historical sample would eventually make all production traces unusable.
        five_layer_dir = evaluation_dir / "five_layer"
        active_suite = None
        if five_layer_dir.exists():
            suites = [path for path in five_layer_dir.iterdir() if path.is_dir()]
            if suites:
                active_suite = max(suites, key=lambda path: path.stat().st_mtime_ns)
        if active_suite is not None:
            for path in active_suite.rglob("*"):
                if path.is_file() and path.name in wanted_names:
                    candidates.append((path, f"active_suite:{path.name}"))

        permanent_roots = (
            evaluation_dir / "datasets",
            evaluation_dir / "gold_expansion",
        )
        for root in permanent_roots:
            if not root.exists():
                continue
            for path in root.rglob("*"):
                if path.is_file() and path.name in wanted_names:
                    candidates.append((path, f"permanent_evaluation:{path.name}"))
    generated_dir = project_root / "generated_datasets"
    if generated_dir.exists():
        for path in generated_dir.rglob("*_ids.txt"):
            if "strict_untrained" in path.name:
                candidates.append((path, "strict_untrained_generated_set"))

    reserved: set[str] = set()
    inventory: list[dict[str, Any]] = []
    seen_paths: set[Path] = set()
    for path, category in sorted(candidates, key=lambda item: str(item[0]).lower()):
        resolved = path.resolve()
        if resolved in seen_paths:
            continue
        seen_paths.add(resolved)
        ids = _scan_reserved_file(path)
        reserved.update(ids)
        inventory.append(
            {
                "category": category,
                "relative_name": path.name,
                "id_count": len(ids),
            }
        )
    return reserved, inventory


def _connect_readonly(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA query_only = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _quality_rank(record: dict[str, Any]) -> int:
    source = record.get("label_tier")
    rich = bool(record.get("evidence_quality") == "enriched")
    base = 40 if source == "manual_review_import" else 25
    return base + (15 if rich else 0) + min(int(record.get("evidence_field_count") or 0), 10)


def group_key(record: dict[str, Any]) -> str:
    sample = record.get("input") or {}
    options = (
        ("cert", sample.get("cert_sha256") or sample.get("cert_md5")),
        ("pkg", sample.get("package_name")),
        ("family", sample.get("fraud_family")),
        ("app", sample.get("app_name")),
    )
    for prefix, raw in options:
        normalized = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "", str(raw or "").lower())
        if len(normalized) >= 4:
            return f"{prefix}:{stable_hash(normalized)[:20]}"
    return f"md5:{record['md5']}"


def _engine_score(value: Any) -> float | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(score):
        return None
    return round(score, 4)


def _feature_subset(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "package_name",
        "app_name",
        "app_type",
        "platform",
        "signature_status",
        "certificate_fingerprint",
        "cert_md5",
        "cert_sha1",
        "cert_sha256",
        "certificate_owner",
        "certificate_developer",
        "permissions",
        "plugins",
        "sdk_list",
        "packer",
        "code_fuscator",
        "unshell_info",
        "fake_app",
        "impersonation_flag",
        "official_app_name",
        "fraud_category_big",
        "fraud_category_small",
        "fraud_family",
        "control_url",
        "download_url",
        "domains",
        "ips",
        "domain_count",
        "ip_count",
    )
    result: dict[str, Any] = {}
    for key in allowed:
        value = payload.get(key)
        if isinstance(value, list):
            cleaned = [clean_text(item, 160) for item in value]
            cleaned = [item for item in cleaned if item][:30]
            if cleaned:
                result[key] = cleaned
        elif isinstance(value, dict):
            compact = {str(k): clean_text(v, 160) for k, v in list(value.items())[:30] if clean_text(v, 160)}
            if compact:
                result[key] = compact
        else:
            text = clean_text(value, 800)
            if text:
                result[key] = text
    return result


def load_labeled_samples(db_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    conn = _connect_readonly(db_path)
    try:
        manual_any = {
            normalize_md5(row[0])
            for row in conn.execute("SELECT md5 FROM manual_labels")
            if normalize_md5(row[0])
        }
        labels: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            """
            SELECT md5, label, source_file, conflict_type, raw_json
            FROM manual_labels
            WHERE label IN ('malicious', 'benign')
            """
        ):
            md5 = normalize_md5(row["md5"])
            if not md5:
                continue
            raw = safe_json_loads(row["raw_json"], {}) or {}
            labels[md5] = {
                "md5": md5,
                "label": row["label"],
                "label_source": f"manual_labels:{clean_text(row['source_file'], 180)}",
                "label_tier": "manual_review_import",
                "source_detail": clean_text(row["conflict_type"], 180),
                "raw_label": raw,
            }
        for row in conn.execute(
            """
            SELECT md5, label, source_sheet, app_name, fraud_type, fraud_subtype, raw_json
            FROM app_md5_labels
            WHERE label IN ('malicious', 'benign')
            """
        ):
            md5 = normalize_md5(row["md5"])
            if not md5 or md5 in manual_any:
                continue
            labels[md5] = {
                "md5": md5,
                "label": row["label"],
                "label_source": f"app_md5_labels:{clean_text(row['source_sheet'], 120)}",
                "label_tier": "curated_source_reference",
                "source_detail": "curated malicious/benign source sheet",
                "raw_label": {
                    **(safe_json_loads(row["raw_json"], {}) or {}),
                    "app_name": row["app_name"],
                    "fraud_type": row["fraud_type"],
                    "fraud_subtype": row["fraud_subtype"],
                },
            }

        feature_map: dict[str, dict[str, Any]] = {}
        for row in conn.execute(
            """
            SELECT md5, source, normalized_json, priority_score
            FROM sample_features
            ORDER BY priority_score DESC, created_at DESC
            """
        ):
            md5 = normalize_md5(row["md5"])
            if md5 not in labels or md5 in feature_map:
                continue
            feature_map[md5] = {
                "source": clean_text(row["source"], 160),
                "payload": safe_json_loads(row["normalized_json"], {}) or {},
            }

        engine_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in conn.execute(
            """
            SELECT md5, engine, sha1, sha256, package_name, app_name, app_type,
                   detect_type, score, virus_name, description, control_url,
                   download_url, platform, fraud_category_big, fraud_category_small,
                   fraud_family, impersonation_flag, official_app_name, cert_md5,
                   cert_sha256, cert_owner, sdk_list, fake_app
            FROM engine_detections
            """
        ):
            md5 = normalize_md5(row["md5"])
            if md5 not in labels:
                continue
            observation = {
                "engine": clean_text(row["engine"], 40),
                "detect_type": clean_text(row["detect_type"], 100),
                "score": _engine_score(row["score"]),
                "virus_name": clean_text(row["virus_name"], 160),
                "description": clean_text(row["description"], 500),
            }
            observation = {key: value for key, value in observation.items() if value not in {None, ""}}
            engine_map[md5].append(observation)
            meta = labels[md5].setdefault("engine_meta", {})
            for key in (
                "sha1",
                "sha256",
                "package_name",
                "app_name",
                "app_type",
                "control_url",
                "download_url",
                "platform",
                "fraud_category_big",
                "fraud_category_small",
                "fraud_family",
                "impersonation_flag",
                "official_app_name",
                "cert_md5",
                "cert_sha256",
                "cert_owner",
                "sdk_list",
                "fake_app",
            ):
                if not meta.get(key) and clean_text(row[key], 2000):
                    meta[key] = clean_text(row[key], 2000)

        records: list[dict[str, Any]] = []
        for md5, label_record in labels.items():
            raw = label_record.get("raw_label") or {}
            meta = label_record.get("engine_meta") or {}
            features = _feature_subset((feature_map.get(md5) or {}).get("payload") or {})
            sample = {
                "md5": md5,
                "app_name": clean_text(
                    meta.get("app_name") or features.get("app_name") or raw.get("app_name") or raw.get("appName"), 300
                ),
                "package_name": clean_text(meta.get("package_name") or features.get("package_name"), 300),
                "sha1": clean_text(meta.get("sha1"), 64),
                "sha256": clean_text(meta.get("sha256"), 80),
                "app_type": clean_text(meta.get("app_type") or features.get("app_type"), 160),
                "platform": clean_text(meta.get("platform") or features.get("platform"), 80),
                "fraud_category_big": clean_text(
                    meta.get("fraud_category_big") or features.get("fraud_category_big") or raw.get("fraud_type") or raw.get("fraudGaType"), 200
                ),
                "fraud_category_small": clean_text(
                    meta.get("fraud_category_small") or features.get("fraud_category_small") or raw.get("fraud_subtype") or raw.get("fraudGaSubType"), 200
                ),
                "fraud_family": clean_text(meta.get("fraud_family") or features.get("fraud_family"), 200),
                "cert_md5": clean_text(meta.get("cert_md5") or features.get("cert_md5"), 64),
                "cert_sha256": clean_text(meta.get("cert_sha256") or features.get("cert_sha256"), 80),
                "cert_owner": clean_text(meta.get("cert_owner") or features.get("certificate_owner"), 300),
                "official_app_name": clean_text(meta.get("official_app_name") or features.get("official_app_name"), 300),
                "impersonation_flag": clean_text(meta.get("impersonation_flag") or features.get("impersonation_flag"), 80),
                "fake_app": clean_text(meta.get("fake_app") or features.get("fake_app"), 80),
                "control_url": clean_text(meta.get("control_url") or features.get("control_url"), 600),
                "download_url": clean_text(meta.get("download_url") or features.get("download_url"), 600),
                "sdk_list": clean_text(meta.get("sdk_list") or features.get("sdk_list"), 1500),
            }
            sample = {key: value for key, value in sample.items() if value}
            observations = sorted(engine_map.get(md5) or [], key=lambda item: item.get("engine", ""))
            feature_payload = {
                key: value
                for key, value in features.items()
                if key not in sample and key not in {"md5", "sample_id", "app_name", "package_name"}
            }
            field_count = len(sample) - 1 + len(feature_payload) + sum(len(item) for item in observations)
            record = {
                "md5": md5,
                "label": label_record["label"],
                "label_source": label_record["label_source"],
                "label_tier": label_record["label_tier"],
                "source_detail": label_record["source_detail"],
                "input": sample,
                "engine_observations": observations,
                "feature_evidence": feature_payload,
                "feature_source": (feature_map.get(md5) or {}).get("source", ""),
                "evidence_quality": "enriched" if observations or len(feature_payload) >= 3 else "minimal",
                "evidence_field_count": field_count,
            }
            record["group_id"] = group_key(record)
            record["quality_rank"] = _quality_rank(record)
            records.append(record)

        stats = {
            "manual_rows": sum(1 for row in records if row["label_tier"] == "manual_review_import"),
            "curated_source_rows": sum(1 for row in records if row["label_tier"] == "curated_source_reference"),
            "enriched_rows": sum(1 for row in records if row["evidence_quality"] == "enriched"),
            "label_distribution": dict(Counter(row["label"] for row in records)),
        }
        return records, stats
    finally:
        conn.close()


def stable_stratified_select(
    records: Iterable[dict[str, Any]],
    target: int,
    label_weights: dict[str, float],
    seed: str,
    max_per_group: int = 1,
) -> list[dict[str, Any]]:
    pool = list(records)
    if target <= 0 or not pool:
        return []
    total_weight = sum(max(0.0, value) for value in label_weights.values()) or 1.0
    quotas = {
        label: int(round(target * max(0.0, weight) / total_weight))
        for label, weight in label_weights.items()
    }
    while sum(quotas.values()) > target:
        largest = max(quotas, key=quotas.get)
        quotas[largest] -= 1
    while sum(quotas.values()) < target:
        smallest = min(quotas, key=quotas.get)
        quotas[smallest] += 1

    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    group_counts: Counter[str] = Counter()
    for label, quota in quotas.items():
        candidates = [row for row in pool if row.get("label") == label]
        candidates.sort(
            key=lambda row: (
                -int(row.get("quality_rank") or 0),
                stable_hash(f"{seed}|{label}|{row.get('group_id')}|{row.get('md5')}"),
            )
        )
        for row in candidates:
            if len([item for item in selected if item.get("label") == label]) >= quota:
                break
            md5 = row.get("md5") or row.get("id")
            group = row.get("group_id") or str(md5)
            if md5 in selected_ids or group_counts[group] >= max_per_group:
                continue
            selected.append(row)
            selected_ids.add(str(md5))
            group_counts[group] += 1

    if len(selected) < target:
        remaining = [row for row in pool if str(row.get("md5") or row.get("id")) not in selected_ids]
        remaining.sort(
            key=lambda row: (
                -int(row.get("quality_rank") or 0),
                stable_hash(f"{seed}|fill|{row.get('group_id')}|{row.get('md5') or row.get('id')}"),
            )
        )
        for row in remaining:
            md5 = str(row.get("md5") or row.get("id"))
            group = row.get("group_id") or md5
            if group_counts[group] >= max_per_group:
                continue
            selected.append(row)
            selected_ids.add(md5)
            group_counts[group] += 1
            if len(selected) >= target:
                break
    return selected


def _standard_answer(record: dict[str, Any]) -> dict[str, Any]:
    label = record["label"]
    refs: list[str] = []
    for item in record.get("engine_observations") or []:
        engine = item.get("engine")
        if engine:
            refs.append(f"engine:{engine}")
    for key in ("fraud_category_big", "fraud_category_small", "fraud_family", "package_name", "cert_sha256"):
        if (record.get("input") or {}).get(key):
            refs.append(f"field:{key}")
    refs = list(dict.fromkeys(refs))[:8]
    confidence = 0.92 if record.get("label_tier") == "manual_review_import" else 0.86
    if record.get("evidence_quality") == "minimal":
        confidence = min(confidence, 0.75)
    return {
        "verdict": label,
        "risk_level": "high" if label == "malicious" else "low",
        "confidence": confidence,
        "evidence_refs": refs,
        "review_required": bool(record.get("evidence_quality") == "minimal"),
    }


def build_sft_row(record: dict[str, Any], split: str) -> dict[str, Any]:
    user_payload = {
        "sample": record.get("input") or {},
        "engine_observations": record.get("engine_observations") or [],
        "feature_evidence": record.get("feature_evidence") or {},
    }
    return {
        "id": f"sft-{record['md5']}",
        "sample_id": record["md5"],
        "group_id": record["group_id"],
        "split": split,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False, separators=(",", ":"))},
            {"role": "assistant", "content": json.dumps(_standard_answer(record), ensure_ascii=False, separators=(",", ":"))},
        ],
        "label": record["label"],
        "label_source": record["label_source"],
        "label_tier": record["label_tier"],
        "evidence_quality": record["evidence_quality"],
        "training_allowed": True,
        "final_frozen_test_eligible": False,
    }


def build_calibration_row(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"cal-{record['md5']}",
        "sample_id": record["md5"],
        "group_id": record["group_id"],
        "input": {
            "sample": record.get("input") or {},
            "engine_observations": record.get("engine_observations") or [],
            "feature_evidence": record.get("feature_evidence") or {},
        },
        "expected_label": record["label"],
        "label_source": record["label_source"],
        "label_tier": record["label_tier"],
        "intended_use": "threshold_and_calibration_development_only",
        "training_allowed": False,
        "final_frozen_test_eligible": False,
    }


def _load_reward_index(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for row in conn.execute(
        "SELECT report_id, reward, components_json, created_at FROM reward_records ORDER BY created_at ASC"
    ):
        result[row["report_id"]] = {
            "reward": float(row["reward"]),
            "components": safe_json_loads(row["components_json"], {}) or {},
            "created_at": row["created_at"],
        }
    return result


def load_trace_candidates(
    db_path: Path,
    labels_by_md5: dict[str, dict[str, Any]],
    blocked_ids: set[str],
    blocked_groups: set[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    conn = _connect_readonly(db_path)
    try:
        rewards = _load_reward_index(conn)
        latest: dict[str, sqlite3.Row] = {}
        for row in conn.execute(
            "SELECT trace_id, report_id, md5, created_at, payload_json FROM agent_traces ORDER BY created_at ASC"
        ):
            md5 = normalize_md5(row["md5"])
            if md5:
                latest[md5] = row

        dpo: list[dict[str, Any]] = []
        success: list[dict[str, Any]] = []
        for md5, row in latest.items():
            reference = labels_by_md5.get(md5)
            if not reference or md5 in blocked_ids or reference["group_id"] in blocked_groups:
                continue
            trace = safe_json_loads(row["payload_json"], {}) or {}
            decision = trace.get("decision") or {}
            verdict = clean_text(decision.get("verdict"), 40)
            explanation = trace.get("llm_explanation") or {}
            rejected_summary = clean_text(
                explanation.get("overall_summary") or explanation.get("message") or decision.get("verdict_label"), 2000
            )
            chosen = _standard_answer(reference)
            rejected = {
                "verdict": verdict or "missing",
                "risk_level": decision.get("risk_level"),
                "confidence": decision.get("confidence") or decision.get("final_confidence"),
                "summary": rejected_summary,
                "key_evidence": (decision.get("key_evidence") or [])[:8],
            }
            reasons = []
            if verdict != reference["label"]:
                reasons.append("verdict_mismatch")
            if len(rejected_summary) > 500:
                reasons.append("verbosity")
            if not rejected_summary:
                reasons.append("missing_summary")
            dpo.append(
                {
                    "id": f"dpo-{row['trace_id']}",
                    "sample_id": md5,
                    "group_id": reference["group_id"],
                    "prompt": {
                        "system": SYSTEM_PROMPT,
                        "sample": trace.get("sample") or reference.get("input") or {},
                        "agent_outputs": trace.get("agent_outputs") or [],
                    },
                    "chosen": chosen,
                    "rejected": rejected,
                    "candidate_reasons": reasons or ["conciseness_and_schema_review"],
                    "reference_label": reference["label"],
                    "label_source": reference["label_source"],
                    "preference_status": "requires_human_pair_review",
                    "training_allowed": False,
                }
            )

            agent_outputs = trace.get("agent_outputs") or []
            agents = {clean_text(item.get("agent"), 80) for item in agent_outputs if isinstance(item, dict)}
            error_text = " ".join(
                clean_text(value, 500).lower()
                for value in (
                    (trace.get("execution") or {}).get("error"),
                    (trace.get("debate") or {}).get("error"),
                    (trace.get("debate") or {}).get("runtime_error"),
                )
                if value
            )
            reward = rewards.get(row["report_id"]) or {}
            structurally_successful = (
                {"static_analysis", "threat_intel", "impersonation", "business_label"}.issubset(agents)
                and verdict == reference["label"]
                and not any(token in error_text for token in ("failed", "timeout", "exception", "schema"))
                and float(reward.get("reward") or 0.0) >= 0.75
            )
            if structurally_successful:
                success.append(
                    {
                        "id": f"agent-success-{row['trace_id']}",
                        "trace_id": row["trace_id"],
                        "report_id": row["report_id"],
                        "sample_id": md5,
                        "group_id": reference["group_id"],
                        "trajectory": {
                            "sample": trace.get("sample") or {},
                            "input_snapshot": trace.get("input_snapshot") or {},
                            "agent_outputs": agent_outputs,
                            "debate": trace.get("debate") or {},
                            "decision": decision,
                            "execution": trace.get("execution") or {},
                        },
                        "expected_label": reference["label"],
                        "label_source": reference["label_source"],
                        "reward": reward.get("reward"),
                        "reward_components": reward.get("components") or {},
                        "trajectory_tier": "label_aligned_structural_success_silver",
                        "training_allowed": True,
                        "human_reward_available": False,
                    }
                )
        return dpo, success
    finally:
        conn.close()


def select_generic(rows: list[dict[str, Any]], target: int, seed: str, key: str = "id") -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: stable_hash(f"{seed}|{row.get(key)}"))[: max(0, target)]


def build_dpo_generation_queue(
    source_rows: list[dict[str, Any]],
    existing_pair_ids: set[str],
    target: int,
) -> list[dict[str, Any]]:
    candidates = [row for row in source_rows if row["md5"] not in existing_pair_ids]
    selected = stable_stratified_select(
        candidates,
        target,
        {"malicious": 0.6, "benign": 0.4},
        "malapp-dpo-generation-v1",
        max_per_group=2,
    )
    rows = []
    for record in selected:
        rows.append(
            {
                "id": f"dpo-generate-{record['md5']}",
                "sample_id": record["md5"],
                "group_id": record["group_id"],
                "prompt": {
                    "system": SYSTEM_PROMPT,
                    "sample": record.get("input") or {},
                    "engine_observations": record.get("engine_observations") or [],
                    "feature_evidence": record.get("feature_evidence") or {},
                },
                "reference_label": record["label"],
                "label_source": record["label_source"],
                "required_models": ["model_a", "model_b"],
                "status": "requires_rejected_response_generation_then_human_pair_review",
                "training_allowed": False,
            }
        )
    return rows


def build_agent_success_generation_queue(
    source_rows: list[dict[str, Any]],
    existing_success_ids: set[str],
    target: int,
) -> list[dict[str, Any]]:
    candidates = [row for row in source_rows if row["md5"] not in existing_success_ids]
    selected = stable_stratified_select(
        candidates,
        target,
        {"malicious": 0.6, "benign": 0.4},
        "malapp-agent-success-generation-v1",
        max_per_group=1,
    )
    rows = []
    for record in selected:
        rows.append(
            {
                "id": f"agent-generate-{record['md5']}",
                "sample_id": record["md5"],
                "group_id": record["group_id"],
                "input": {
                    "sample": record.get("input") or {},
                    "engine_observations": record.get("engine_observations") or [],
                    "feature_evidence": record.get("feature_evidence") or {},
                },
                "expected_label": record["label"],
                "label_source": record["label_source"],
                "required_agents": [
                    "static_analysis",
                    "threat_intel",
                    "impersonation",
                    "business_label",
                ],
                "acceptance_criteria": {
                    "all_agent_schemas_valid": True,
                    "final_verdict_matches_reference": True,
                    "reward_min": 0.75,
                    "no_runtime_error": True,
                    "checkpoint_saved": True,
                },
                "status": "requires_full_agent_execution_and_validation",
                "training_allowed": False,
            }
        )
    return rows


FAULT_CATALOG = (
    ("static_analysis", "transient_failure", "retry_once_then_resume_from_checkpoint"),
    ("threat_intel", "timeout", "cancel_timeout_then_retry_with_bounded_backoff"),
    ("impersonation", "malformed_output", "schema_repair_then_revalidate"),
    ("business_label", "tool_unavailable", "degrade_to_rule_evidence_and_mark_degraded"),
    ("orchestrator", "checkpoint_corruption", "rollback_to_previous_checkpoint_then_resume"),
)


def build_fault_recovery_queue(success_rows: list[dict[str, Any]], target: int) -> list[dict[str, Any]]:
    if not success_rows or target <= 0:
        return []
    base = select_generic(success_rows, len(success_rows), "fault-recovery-base")
    rows: list[dict[str, Any]] = []
    for index in range(target):
        item = base[index % len(base)]
        agent, fault_type, recovery = FAULT_CATALOG[index % len(FAULT_CATALOG)]
        rows.append(
            {
                "id": f"fault-recovery-{item['trace_id']}-{index:04d}",
                "base_trace_id": item["trace_id"],
                "sample_id": item["sample_id"],
                "group_id": item["group_id"],
                "fault_injection": {
                    "agent": agent,
                    "fault_type": fault_type,
                    "occurrence": 1,
                    "injection_point": "after_checkpoint_before_agent_commit",
                },
                "expected_recovery": {
                    "action": recovery,
                    "no_duplicate_report": True,
                    "checkpoint_persisted": True,
                    "final_verdict": item["expected_label"],
                    "terminal_status": "completed_or_degraded",
                },
                "status": "requires_isolated_execution",
                "training_allowed": False,
                "becomes_trainable_when": "fault_was_observed_and_recovery_result_was_verified",
            }
        )
    return rows


def _rag_query(doc: dict[str, Any]) -> str:
    title = clean_text(doc.get("title"), 220)
    content = clean_text(doc.get("content"), 700)
    md5s = sorted(extract_md5s_from_text(f"{title} {content}"))
    if doc.get("source_type") == "malapp_structured_sample":
        identifiers = [f"MD5 {md5s[0]}" if md5s else "", title]
        return "检索与该APP样本、家族、IOC和研判依据最相关的知识：" + "；".join(item for item in identifiers if item)
    return f"检索能够解释“{title}”的权威依据、适用条件和相关威胁情报。"


def load_rag_candidates(
    rag_db_path: Path,
    blocked_ids: set[str],
    target: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    conn = _connect_readonly(rag_db_path)
    try:
        docs = [dict(row) for row in conn.execute(
            "SELECT doc_id, source_type, source_name, title, content, metadata_json FROM rag_documents"
        )]
    finally:
        conn.close()
    eligible = []
    excluded = 0
    for doc in docs:
        discovered = extract_md5s_from_text(
            f"{doc.get('title', '')} {doc.get('content', '')} {doc.get('metadata_json', '')}"
        )
        if discovered & blocked_ids:
            excluded += 1
            continue
        eligible.append(doc)
    eligible.sort(key=lambda doc: stable_hash(f"rag|{doc['doc_id']}"))
    selected = eligible[: max(0, target)]
    by_type: dict[str, list[str]] = defaultdict(list)
    all_ids = [doc["doc_id"] for doc in eligible]
    for doc in eligible:
        by_type[doc.get("source_type") or "unknown"].append(doc["doc_id"])

    rows = []
    for doc in selected:
        negative_pool = [item for item in by_type[doc.get("source_type") or "unknown"] if item != doc["doc_id"]]
        if len(negative_pool) < 4:
            negative_pool.extend(item for item in all_ids if item != doc["doc_id"] and item not in negative_pool)
        negatives = sorted(negative_pool, key=lambda value: stable_hash(f"{doc['doc_id']}|{value}"))[:4]
        rows.append(
            {
                "id": f"rag-train-{stable_hash(doc['doc_id'])[:20]}",
                "query": _rag_query(doc),
                "positive_doc_ids": [doc["doc_id"]],
                "hard_negative_doc_ids": negatives,
                "source_type": doc.get("source_type"),
                "source_name": clean_text(doc.get("source_name"), 240),
                "positive_title": clean_text(doc.get("title"), 300),
                "annotation_tier": "silver_exact_document_link",
                "expert_relevant_doc_ids": [],
                "expert_notes": "",
                "expert_review_status": "pending",
                "training_allowed_for_retriever_warm_start": True,
                "release_metric_eligible": False,
            }
        )
    return rows, {
        "corpus_documents": len(docs),
        "eligible_documents": len(eligible),
        "excluded_by_reserved_sample": excluded,
        "source_type_distribution": dict(Counter(doc.get("source_type") or "unknown" for doc in docs)),
    }


def _file_fingerprint(path: Path) -> dict[str, Any]:
    stat = path.stat()
    return {
        "name": path.name,
        "size_bytes": stat.st_size,
        "modified_ns": stat.st_mtime_ns,
        "fingerprint": stable_hash(f"{path.name}|{stat.st_size}|{stat.st_mtime_ns}"),
    }


def _duplicate_count(rows: list[dict[str, Any]], key: str) -> int:
    values = [str(row.get(key) or "") for row in rows]
    return len(values) - len(set(values))


def build_training_corpora(
    data_dir: str | Path,
    project_root: str | Path,
    output_dir: str | Path,
    targets: TrainingCorpusTargets | None = None,
) -> dict[str, Any]:
    targets = targets or TrainingCorpusTargets()
    data_dir = Path(data_dir).expanduser().resolve()
    project_root = Path(project_root).expanduser().resolve()
    output_dir = Path(output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "mvp.db"
    rag_db_path = data_dir / "rag" / "rag_store.db"
    if not db_path.exists():
        raise FileNotFoundError(f"Missing MalApp database: {db_path}")
    if not rag_db_path.exists():
        raise FileNotFoundError(f"Missing RAG database: {rag_db_path}")

    reserved_ids, reserved_inventory = collect_reserved_ids(data_dir, project_root)
    labeled_records, label_stats = load_labeled_samples(db_path)
    labels_by_md5 = {row["md5"]: row for row in labeled_records}
    reserved_groups = {
        row["group_id"] for row in labeled_records if row["md5"] in reserved_ids
    }
    trainable_pool = [
        row for row in labeled_records
        if row["md5"] not in reserved_ids and row["group_id"] not in reserved_groups
    ]

    calibration_pool = [row for row in trainable_pool if row["evidence_quality"] == "enriched"]
    calibration = stable_stratified_select(
        calibration_pool,
        targets.calibration,
        {"malicious": 0.5, "benign": 0.5},
        "malapp-calibration-v1",
        max_per_group=1,
    )
    calibration_ids = {row["md5"] for row in calibration}
    calibration_groups = {row["group_id"] for row in calibration}
    sft_pool = [
        row for row in trainable_pool
        if row["md5"] not in calibration_ids and row["group_id"] not in calibration_groups
    ]
    core = stable_stratified_select(
        sft_pool,
        targets.sft_core,
        {"malicious": 0.6, "benign": 0.4},
        "malapp-sft-core-v1",
        max_per_group=3,
    )
    core_ids = {row["md5"] for row in core}
    expansion_pool = [row for row in sft_pool if row["md5"] not in core_ids]
    expansion = stable_stratified_select(
        expansion_pool,
        targets.sft_expansion,
        {"malicious": 0.6, "benign": 0.4},
        "malapp-sft-expansion-v1",
        max_per_group=3,
    )
    sft_core_rows = [build_sft_row(row, "core") for row in core]
    sft_expansion_rows = [build_sft_row(row, "expansion") for row in expansion]
    sft_all = sft_core_rows + sft_expansion_rows
    sft_enriched = [row for row in sft_all if row["evidence_quality"] == "enriched"]
    calibration_rows = [build_calibration_row(row) for row in calibration]

    dpo_pool, success_pool = load_trace_candidates(
        db_path,
        labels_by_md5,
        reserved_ids | calibration_ids,
        reserved_groups | calibration_groups,
    )
    dpo_rows = select_generic(dpo_pool, targets.dpo, "malapp-dpo-candidates-v1")
    success_rows = select_generic(success_pool, targets.agent_success, "malapp-agent-success-v1")
    dpo_generation_rows = build_dpo_generation_queue(
        core + expansion,
        {row["sample_id"] for row in dpo_rows},
        max(0, targets.dpo - len(dpo_rows)),
    )
    agent_generation_rows = build_agent_success_generation_queue(
        core + expansion,
        {row["sample_id"] for row in success_rows},
        max(0, targets.agent_success - len(success_rows)),
    )
    fault_rows = build_fault_recovery_queue(success_pool, targets.agent_fault_recovery)
    rag_rows, rag_stats = load_rag_candidates(
        rag_db_path,
        reserved_ids | calibration_ids,
        targets.rag,
    )

    files = {
        "sft_core": "sft/sft_core.jsonl",
        "sft_expansion": "sft/sft_expansion.jsonl",
        "sft_all": "sft/sft_train_all.jsonl",
        "sft_enriched_only": "sft/sft_enriched_only.jsonl",
        "dpo_review_queue": "dpo/dpo_review_queue.jsonl",
        "dpo_generation_queue": "dpo/dpo_generation_queue.jsonl",
        "dpo_ready": "dpo/dpo_ready.jsonl",
        "rag_silver": "rag/rag_retrieval_silver.jsonl",
        "rag_gold_ready": "rag/rag_retrieval_gold_ready.jsonl",
        "agent_success": "agent/agent_success.jsonl",
        "agent_success_generation_queue": "agent/agent_success_generation_queue.jsonl",
        "agent_fault_recovery_queue": "agent/agent_fault_recovery_execution_queue.jsonl",
        "calibration": "calibration/calibration_dev.jsonl",
        "reserved_ids": "audit/reserved_eval_ids.jsonl",
    }
    write_jsonl(output_dir / files["sft_core"], sft_core_rows)
    write_jsonl(output_dir / files["sft_expansion"], sft_expansion_rows)
    write_jsonl(output_dir / files["sft_all"], sft_all)
    write_jsonl(output_dir / files["sft_enriched_only"], sft_enriched)
    write_jsonl(output_dir / files["dpo_review_queue"], dpo_rows)
    write_jsonl(output_dir / files["dpo_generation_queue"], dpo_generation_rows)
    write_jsonl(output_dir / files["dpo_ready"], [])
    write_jsonl(output_dir / files["rag_silver"], rag_rows)
    write_jsonl(output_dir / files["rag_gold_ready"], [])
    write_jsonl(output_dir / files["agent_success"], success_rows)
    write_jsonl(output_dir / files["agent_success_generation_queue"], agent_generation_rows)
    write_jsonl(output_dir / files["agent_fault_recovery_queue"], fault_rows)
    write_jsonl(output_dir / files["calibration"], calibration_rows)
    write_jsonl(
        output_dir / files["reserved_ids"],
        ({"sample_id": md5, "reason": "hard_evaluation_boundary"} for md5 in sorted(reserved_ids)),
    )

    counts = {
        "sft_core": len(sft_core_rows),
        "sft_expansion": len(sft_expansion_rows),
        "sft_total": len(sft_all),
        "sft_enriched_only": len(sft_enriched),
        "dpo_review_queue": len(dpo_rows),
        "dpo_generation_queue": len(dpo_generation_rows),
        "dpo_candidate_capacity": len(dpo_rows) + len(dpo_generation_rows),
        "dpo_ready": 0,
        "rag_silver": len(rag_rows),
        "rag_gold_ready": 0,
        "agent_success": len(success_rows),
        "agent_success_generation_queue": len(agent_generation_rows),
        "agent_success_capacity": len(success_rows) + len(agent_generation_rows),
        "agent_fault_recovery_execution_queue": len(fault_rows),
        "agent_fault_recovery_verified": 0,
        "calibration_dev": len(calibration_rows),
        "reserved_eval_ids": len(reserved_ids),
        "reserved_groups": len(reserved_groups),
    }
    target_map = asdict(targets)
    gaps = {
        "sft_core": max(0, targets.sft_core - counts["sft_core"]),
        "sft_recommended_total": max(0, targets.sft_core + targets.sft_expansion - counts["sft_total"]),
        "dpo_human_approved": targets.dpo,
        "dpo_pair_generation": max(0, targets.dpo - counts["dpo_candidate_capacity"]),
        "rag_expert_approved": targets.rag,
        "agent_success_verified": max(0, targets.agent_success - counts["agent_success"]),
        "agent_success_generation": max(0, targets.agent_success - counts["agent_success_capacity"]),
        "agent_fault_recovery_verified": targets.agent_fault_recovery,
        "calibration": max(0, targets.calibration - counts["calibration_dev"]),
    }
    calibration_groups_actual = {row["group_id"] for row in calibration_rows}
    sft_groups = {row["group_id"] for row in sft_all}
    dpo_groups = {row["group_id"] for row in dpo_rows}
    agent_groups = {row["group_id"] for row in success_rows}
    dpo_generation_groups = {row["group_id"] for row in dpo_generation_rows}
    agent_generation_groups = {row["group_id"] for row in agent_generation_rows}
    quality = {
        "generated_at": now_iso(),
        "checks": {
            "reserved_id_overlap_sft": len({row["sample_id"] for row in sft_all} & reserved_ids),
            "reserved_id_overlap_dpo": len({row["sample_id"] for row in dpo_rows} & reserved_ids),
            "reserved_id_overlap_dpo_generation": len({row["sample_id"] for row in dpo_generation_rows} & reserved_ids),
            "reserved_id_overlap_agent": len({row["sample_id"] for row in success_rows} & reserved_ids),
            "reserved_id_overlap_agent_generation": len({row["sample_id"] for row in agent_generation_rows} & reserved_ids),
            "calibration_group_overlap_sft": len(calibration_groups_actual & sft_groups),
            "calibration_group_overlap_dpo": len(calibration_groups_actual & dpo_groups),
            "calibration_group_overlap_dpo_generation": len(calibration_groups_actual & dpo_generation_groups),
            "calibration_group_overlap_agent": len(calibration_groups_actual & agent_groups),
            "calibration_group_overlap_agent_generation": len(calibration_groups_actual & agent_generation_groups),
            "duplicate_sft_sample_ids": _duplicate_count(sft_all, "sample_id"),
            "duplicate_dpo_ids": _duplicate_count(dpo_rows, "id"),
            "duplicate_dpo_generation_ids": _duplicate_count(dpo_generation_rows, "id"),
            "duplicate_agent_trace_ids": _duplicate_count(success_rows, "trace_id"),
            "duplicate_agent_generation_ids": _duplicate_count(agent_generation_rows, "id"),
            "duplicate_fault_recovery_ids": _duplicate_count(fault_rows, "id"),
            "duplicate_rag_ids": _duplicate_count(rag_rows, "id"),
        },
        "distributions": {
            "sft_labels": dict(Counter(row["label"] for row in sft_all)),
            "sft_label_tiers": dict(Counter(row["label_tier"] for row in sft_all)),
            "sft_evidence_quality": dict(Counter(row["evidence_quality"] for row in sft_all)),
            "calibration_labels": dict(Counter(row["expected_label"] for row in calibration_rows)),
            "rag_source_types": dict(Counter(row.get("source_type") or "unknown" for row in rag_rows)),
        },
        "readiness": {
            "sft": "source-supervised and provenance-tagged; suitable for staged PEFT after spot-check",
            "dpo": "saved-output pairs plus generation queue; human pair preference is required before DPO",
            "rag": "silver exact-link pairs for retriever warm-start; expert approval required for release metrics",
            "agent_success": "label-aligned structural silver trajectories plus an isolated execution queue for the gap",
            "agent_fault_recovery": "execution specifications only; not trajectories until isolated replay succeeds",
            "calibration": "development-only; never merge into SFT/DPO or final frozen test",
        },
        "gaps": gaps,
    }
    all_checks_pass = all(value == 0 for value in quality["checks"].values())
    quality["all_leakage_and_duplicate_checks_passed"] = all_checks_pass
    write_json(output_dir / "quality_report.json", quality)

    manifest = {
        "schema_version": "malapp-training-corpus-v1",
        "build_id": output_dir.name,
        "generated_at": now_iso(),
        "targets": target_map,
        "counts": counts,
        "gaps": gaps,
        "source_inventory": {
            "mvp_db": _file_fingerprint(db_path),
            "rag_db": _file_fingerprint(rag_db_path),
            "labels": label_stats,
            "rag": rag_stats,
            "reserved_boundaries": reserved_inventory,
        },
        "leakage_policy": {
            "hard_reserved_ids_excluded": True,
            "near_duplicate_group_exclusion": True,
            "calibration_group_excluded_from_training": True,
            "diagnostic_and_production_replay_baselines_must_be_regenerated_after_training": True,
        },
        "files": files,
        "quality_report": "quality_report.json",
        "quality_gate_passed": all_checks_pass,
        "important_limitations": [
            "human_reviews表当前为0条，DPO ready保持为空，禁止把自动偏好候选直接当作专家偏好。",
            "RAG当前没有专家批准的相关性标注，银标可用于检索器预热，不能用于发布门禁指标。",
            "故障恢复文件是待执行注入任务，不是已经验证的恢复轨迹。",
            "SFT同时包含人工审核导入标签和来源参考标签，训练时应先使用core并做抽样复核。",
        ],
    }
    write_json(output_dir / "manifest.json", manifest)
    readme = f"""# MalApp 训练数据构造包\n\n构建时间：{manifest['generated_at']}\n\n## 结果\n\n- SFT核心集：{counts['sft_core']} 条；扩展集：{counts['sft_expansion']} 条；合计：{counts['sft_total']} 条；其中证据富集：{counts['sft_enriched_only']} 条。\n- DPO已有候选对：{counts['dpo_review_queue']} 对；待生成回答：{counts['dpo_generation_queue']} 条；专家批准可训练：0 对。\n- RAG银标：{counts['rag_silver']} 条；专家金标：0 条。\n- Agent已验证成功轨迹：{counts['agent_success']} 条；待运行：{counts['agent_success_generation_queue']} 条。\n- 故障恢复执行队列：{counts['agent_fault_recovery_execution_queue']} 条；已验证轨迹：0 条。\n- 校准/阈值开发集：{counts['calibration_dev']} 条。\n\n## 使用顺序\n\n1. 首轮保守训练优先使用 `sft/sft_enriched_only.jsonl`，抽检通过后再扩展到 `sft_core.jsonl`。\n2. 先运行 `dpo/dpo_generation_queue.jsonl` 补齐模型回答，再逐对确认 chosen/rejected 并移动到 `dpo_ready.jsonl`。\n3. `rag/rag_retrieval_silver.jsonl` 只用于检索器预热；发布评测必须使用另行冻结的专家标注查询。\n4. 先运行 `agent/agent_success_generation_queue.jsonl`，再运行故障恢复隔离注入并验证。\n5. `calibration/calibration_dev.jsonl` 只用于温度缩放、阈值和拒答策略，禁止参与训练。\n\n所有硬冻结评测ID与同组近重复样本均已排除；完整校验见 `quality_report.json`。\n"""
    (output_dir / "README.md").write_text(readme, encoding="utf-8")
    return manifest
