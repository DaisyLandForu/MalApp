from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malapp.agents.base import AgentResult, EvidenceBlock
from malapp.agents.domain import (
    BusinessLabelAgent,
    ImpersonationAgent,
    StaticAnalysisAgent,
    ThreatIntelAgent,
)
from malapp.agents.evidence_layers import (
    build_raw_evidence_layer,
    build_structured_evidence_layer,
)
from malapp.agents.output import validate_and_repair_evidence_blocks
from malapp.agents.static_features import analyze_apk_from_sample, public_static_feedback
from malapp.config.paths import DEFAULTS_DIR, PROJECT_ROOT, resolve_data_dir
from malapp.inference.local_qwen import local_qwen_enabled
from malapp.orchestration.debate import run_debate
from malapp.orchestration.decision import collaborative_decision
from malapp.orchestration.degradation import apply_degradation_policy, evaluate_degradation, merge_unavailable_evidence
from malapp.orchestration.pipeline import PipelineStateMachine
from malapp.orchestration.planner import orchestration_mode, tool_runtime_enabled
from malapp.rag import rag_context_for_sample

ROOT = PROJECT_ROOT
DATA_DIR = resolve_data_dir()
DB_PATH = DATA_DIR / "mvp.db"
REPORT_SCHEMA_VERSION = "agent-runtime-pipeline-v6.1-decision-provenance"

VERDICT_LABELS = {
    "malicious": "恶意",
    "suspicious": "可疑",
    "benign": "良性",
}

RISK_LEVEL_LABELS = {
    "high": "高风险",
    "medium": "中风险",
    "low": "低风险",
}


IOC_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def persist_observability_metrics(report: dict[str, Any]) -> None:
    """Keep judgement delivery independent from metrics storage failures."""
    try:
        from malapp.observability.metrics import record_run_metrics

        metric = record_run_metrics(report)
        report.setdefault("execution", {})["metrics_record"] = {
            "run_id": metric["run_id"],
            "agent_count": metric["agent_count"],
            "model_call_count": metric["model_call_count"],
        }
    except Exception as exc:
        report.setdefault("execution", {})["metrics_error"] = str(exc)


def attach_decision_provenance(report: dict[str, Any]) -> None:
    from malapp.observability.provenance import build_decision_provenance

    report.pop("decision_provenance", None)
    report.setdefault("decision", {}).pop("provenance_id", None)
    report.setdefault("execution", {}).pop("provenance_id", None)
    provenance = build_decision_provenance(report)
    report["decision_provenance"] = provenance
    report.setdefault("decision", {})["provenance_id"] = provenance["provenance_id"]
    report.setdefault("execution", {})["provenance_id"] = provenance["provenance_id"]


def build_xgb_fast_path_debate(xgb_result: dict[str, Any]) -> dict[str, Any]:
    score = float(xgb_result.get("probability", 0.5))
    verdict = str(xgb_result.get("verdict") or "suspicious")
    risk_level = {"malicious": "high", "suspicious": "medium", "benign": "low"}.get(
        verdict, "medium"
    )
    verdict_text = "恶意" if verdict == "malicious" else "良性"
    summary = (
        f"XGBoost 概率为 {score:.4f}，已落在学习得到的{verdict_text}高置信区间；"
        "本样本直接使用快速裁决，未调用本地千问辩论。"
    )
    return {
        "execution_mode": "xgb_fast_path",
        "skip_reason": "high_confidence_xgboost",
        "model_a": {
            "score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "arguments": ["高置信 XGBoost 快速通道未调用模型甲。"],
            "final_summary": "本样本未调用模型甲，避免不必要的大模型推理。",
        },
        "model_b": {
            "score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "arguments": ["高置信 XGBoost 快速通道未调用模型乙。"],
            "final_summary": "本样本未调用模型乙；只有可疑样本才进入双模型辩论。",
        },
        "stages": [],
        "cross_examination": [],
        "debate_rounds": 0,
        "convergence": {
            "stop_reason": "xgboost_high_confidence",
            "max_rounds": 0,
            "history": [],
        },
        "memory": {"evidence_summary": [], "stage_summaries": []},
        "metrics": {
            "token_usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
            },
            "latency_ms": 0,
            "stage_latency_ms": {},
        },
        "providers": {
            "model_a": {"backend": "not_invoked", "model": ""},
            "model_b": {"backend": "not_invoked", "model": ""},
        },
        "arbiter": {
            "score": score,
            "raw_score": score,
            "verdict": verdict,
            "risk_level": risk_level,
            "rationale": summary,
            "final_summary": summary,
            "logic_trace": {
                "positions": [],
                "turning_points": [],
                "summary": summary,
            },
            "calibration": {
                "source": "xgboost_runtime",
                "thresholds": xgb_result.get("thresholds", {}),
            },
        },
        "xgb": xgb_result,
    }


def load_json(path: Path) -> Any:
    source = path
    if not source.exists():
        try:
            source = DEFAULTS_DIR / path.resolve().relative_to(DATA_DIR)
        except ValueError:
            source = path
    return json.loads(source.read_text(encoding="utf-8"))


def save_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS judgements (
                id TEXT PRIMARY KEY,
                sample_id TEXT NOT NULL,
                verdict TEXT NOT NULL,
                final_score REAL NOT NULL,
                risk_level TEXT NOT NULL,
                created_at TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_judgements_sample_id ON judgements(sample_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_judgements_created_at ON judgements(created_at)"
        )
        conn.commit()
    finally:
        conn.close()


def insert_report(report: dict[str, Any]) -> None:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO judgements
            (id, sample_id, verdict, final_score, risk_level, created_at, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report["report_id"],
                report["sample"]["sample_id"],
                report["decision"]["verdict"],
                report["decision"]["final_score"],
                report["decision"]["risk_level"],
                report["created_at"],
                json.dumps(report, ensure_ascii=False),
            ),
        )
        conn.commit()
    finally:
        conn.close()
    try:
        from malapp.observability.rewards import init_reward_tables
        from malapp.observability.trace import init_trace_tables

        init_trace_tables()
        init_reward_tables()
    except Exception:
        pass


def list_reports(limit: int = 50) -> list[dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    try:
        rows = conn.execute(
            """
            SELECT payload_json FROM judgements
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return [json.loads(row[0]) for row in rows]


def normalize_sample(raw: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    mapping_path = DATA_DIR / "field_mapping.json"
    bundled_mapping_path = DEFAULTS_DIR / "field_mapping.json"
    mapping = (
        load_json(mapping_path)
        if mapping_path.exists()
        else load_json(bundled_mapping_path)
        if bundled_mapping_path.exists()
        else {}
    )
    normalized: dict[str, Any] = {}
    unmapped: list[str] = []

    for key, value in raw.items():
        standard = mapping.get(key)
        if standard:
            normalized[standard] = value
        else:
            normalized[key] = value
            unmapped.append(key)

    if "sample_id" not in normalized:
        seed = normalized.get("md5") or normalized.get("sha256") or json.dumps(raw, sort_keys=True, ensure_ascii=False)
        normalized["sample_id"] = hashlib.sha1(str(seed).encode("utf-8")).hexdigest()[:12]

    from malapp.application.engine_c_admission import ensure_ab_inputs

    normalized["ab_input_mode"] = ensure_ab_inputs(
        normalized,
        production=os.getenv("MALAPP_PROFILE", "demo").strip().lower() == "production",
    )
    normalized.setdefault("engine_a_label", score_to_label(normalized["engine_a_score"]))
    normalized.setdefault("engine_b_label", score_to_label(normalized["engine_b_score"]))
    from malapp.data_import.preprocess import derive_engine_fields

    derive_engine_fields(normalized)
    return normalized, unmapped


def extract_iocs(sample: dict[str, Any]) -> list[dict[str, Any]]:
    network_fields = (
        "control_url",
        "download_url",
        "callback_url",
        "landing_url",
        "control_mailbox",
        "control_phone",
        "urls",
        "lt_urls",
        "sub_urls",
        "dynamic_nets",
        "domains",
        "top_domains",
        "domain",
        "top_domain",
        "ips",
        "ip",
        "threat_intel_records",
        "intelligence_records",
    )
    text = json.dumps(
        {key: sample.get(key) for key in network_fields if sample.get(key) not in ("", None, [], {})},
        ensure_ascii=False,
    )
    indicators = []
    seen = set()
    for ioc_type, pattern in IOC_PATTERNS.items():
        for match in pattern.findall(text):
            key = (ioc_type, match)
            if key in seen:
                continue
            seen.add(key)
            indicators.append({"type": ioc_type, "value": match, "confidence": 0.7})
    return indicators


def score_to_label(score: float | int | str) -> str:
    try:
        numeric = float(score)
    except (TypeError, ValueError):
        numeric = 50
    if numeric >= 70:
        return "malicious"
    if numeric >= 45:
        return "suspicious"
    return "benign"



AGENT_EVIDENCE_RULES = {
    "static_analysis": (
        ("signature_anomaly", ("签名", "证书"), ("signature_status", "certificate_fingerprint", "cert_sha1", "cert_sha256")),
        ("packer_or_obfuscation", ("加固", "壳", "混淆"), ("packer", "code_fuscator", "unshell_info")),
        ("permission_risk", ("权限",), ("permissions",)),
        ("sdk_risk", ("sdk",), ("sdk_list", "plugins")),
        ("engine_static_conflict", ("引擎", "评分差"), ("engine_a_score", "engine_b_score", "engine_a_label", "engine_b_label")),
    ),
    "threat_intel": (
        ("control_infrastructure", ("控制", "c2"), ("control_url", "control_mailbox", "control_phone")),
        ("download_infrastructure", ("下载", "投递"), ("download_url", "lt_urls")),
        ("network_indicator", ("网络", "域名", "ip", "指标"), ("domains", "ips", "top_domains", "dynamic_nets")),
        ("malware_family", ("病毒", "家族", "黑产"), ("virus_name", "virus_description", "fraud_family")),
    ),
    "impersonation": (
        ("declared_impersonation", ("仿冒", "盗版"), ("fake_app", "impersonation_flag", "rebuild_type")),
        ("official_asset_reference", ("正版", "相似度"), ("official_app_name", "official_pkg", "official_md5", "brand_similarity")),
        ("name_obfuscation", ("应用名称", "包名", "敏感词"), ("app_name", "package_name")),
    ),
    "business_label": (
        ("fraud_category", ("涉诈", "欺诈", "业务标签"), ("fraud_flag", "fraud_category_big", "fraud_category_small", "fraud_family")),
        ("harm_category", ("危害", "病毒", "恶意"), ("risk_type", "virus_name", "virus_description")),
        ("app_name_semantics", ("应用名称", "业务语义"), ("app_name",)),
    ),
}

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "md5": ("md5", "file_md5"),
    "sha256": ("sha256", "file_sha256"),
    "package_name": ("package_name", "packagename", "pkg_name", "appid"),
    "app_name": ("app_name", "appname", "appname_unify", "name"),
    "signature_status": ("signature_status", "sign_status"),
    "certificate_fingerprint": ("certificate_fingerprint", "cert_fingerprint", "sign_md5", "sign_sha1", "sign_sha256"),
    "cert_sha1": ("cert_sha1", "sign_sha1"),
    "cert_sha256": ("cert_sha256", "sign_sha256"),
    "sdk_list": ("sdk_list", "sdks", "third_sdk", "third_party_sdk"),
    "permissions": ("permissions", "permission_list", "android_permissions"),
    "packer": ("packer", "shell", "jiagu", "unshell_info", "code_fuscator"),
    "control_url": ("control_url", "controlUrl", "c2_url", "c2", "url"),
    "download_url": ("download_url", "downloadUrl"),
    "control_mailbox": ("control_mailbox", "controlMailbox", "mailbox", "email"),
    "control_phone": ("control_phone", "controlPhone", "phone"),
    "domains": ("domains", "domain", "top_domains", "top_domain"),
    "ips": ("ips", "ip"),
    "threat_intel_records": ("threat_intel_records", "intelligence_records", "ioc_records"),
    "fraud_family": ("fraud_family", "family", "black_family", "fraud_name"),
    "fake_app": ("fake_app", "fakeApp", "impersonation_flag", "is_fake_app"),
    "official_app_name": ("official_app_name", "genuine_app_name", "genuine_name"),
    "official_pkg": ("official_pkg", "genuine_pkg", "genuine_package"),
    "official_md5": ("official_md5", "genuine_md5"),
    "official_icon": ("official_icon", "genuine_icon", "icon_base64"),
    "brand_similarity": ("brand_similarity", "icon_similarity", "name_similarity"),
    "virus_name": ("virus_name", "virus", "malware_name"),
    "risk_score": ("risk_score", "score", "engine_score", "source_risk_score"),
    "fraud_category_big": ("fraud_category_big", "fraud_big", "app_type"),
    "fraud_category_small": ("fraud_category_small", "fraud_small", "app_subtype", "app_thirdtype"),
    "harm_type": ("harm_type", "risk_type", "damage_type"),
    "version_status": ("version_status", "variant_status", "rebuild_type", "app_version"),
}


def first_value(sample: dict[str, Any], logical_field: str) -> Any:
    for key in FIELD_ALIASES.get(logical_field, (logical_field,)):
        value = sample.get(key)
        if value not in ("", None, [], {}):
            return value
    return None


def first_field_name(sample: dict[str, Any], logical_field: str) -> str:
    for key in FIELD_ALIASES.get(logical_field, (logical_field,)):
        if sample.get(key) not in ("", None, [], {}):
            return key
    return logical_field


def has_any_feature(sample: dict[str, Any], logical_fields: tuple[str, ...]) -> bool:
    return any(first_value(sample, field) not in ("", None, [], {}) for field in logical_fields)


def to_text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value or "").strip()


def to_list(value: Any) -> list[Any]:
    if value in ("", None, [], {}):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        if stripped.startswith("["):
            try:
                parsed = json.loads(stripped)
                return parsed if isinstance(parsed, list) else [parsed]
            except json.JSONDecodeError:
                pass
        return [item.strip() for item in re.split(r"[,，;；\s]+", stripped) if item.strip()]
    return [value]


def bool_positive(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return to_text(value).lower() in {"1", "true", "yes", "y", "是", "命中", "存在", "疑似", "仿冒"}


def numeric_value(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def make_evidence_item(
    evidence_type: str,
    description: str,
    source_fields: list[str],
    sample: dict[str, Any],
    strength: float,
    direction: str = "supports_malicious",
) -> dict[str, Any]:
    return {
        "evidence_type": evidence_type,
        "source_fields": source_fields,
        "source_values": [
            f"{field}={compact_evidence_value(sample.get(field))}"
            for field in source_fields
            if sample.get(field) not in ("", None, [], {})
        ][:6],
        "direction": direction,
        "strength": clamp(strength),
        "description": description,
    }


def missing_feature_block(agent: str, claim: str, missing_fields: list[str]) -> EvidenceBlock:
    readable = "、".join(missing_fields)
    return EvidenceBlock(
        agent=agent,
        claim=claim,
        evidence=[f"缺少 {readable} 特征，当前智能体无法给出可靠判断。"],
        confidence=0.0,
        missing_fields=missing_fields,
        score=0.0,
        evidence_items=[
            {
                "evidence_type": "missing_feature",
                "source_fields": missing_fields,
                "source_values": [],
                "direction": "insufficient",
                "strength": 0.0,
                "description": f"缺少 {readable} 特征。",
            }
        ],
        status="insufficient_evidence",
        rule_score=0.0,
    )


def label_claim(score: float, dimension: str) -> str:
    if score >= 0.7:
        return f"{dimension}较高。"
    if score >= 0.45:
        return f"{dimension}中等。"
    return f"{dimension}较低。"


def static_analysis_agent(sample: dict[str, Any]) -> EvidenceBlock:
    required = ("signature_status", "certificate_fingerprint", "package_name", "sdk_list", "permissions", "packer")
    if not has_any_feature(sample, required):
        return missing_feature_block("static_analysis", "缺少签名、包名、SDK 或加固特征，无法完成静态可信度判断。", list(required))

    evidence: list[str] = []
    evidence_items: list[dict[str, Any]] = []
    missing = [field for field in required if first_value(sample, field) in ("", None, [], {})]
    risk = 0.08

    signature = to_text(first_value(sample, "signature_status")).lower()
    cert = first_value(sample, "certificate_fingerprint")
    if signature in {"tampered", "mismatch", "invalid", "篡改", "异常", "无效", "不一致"}:
        text = "证书签名存在篡改、无效或不一致风险。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("signature_anomaly", text, [first_field_name(sample, "signature_status")], sample, 0.82))
        risk += 0.36
    elif signature in {"missing", "缺失", "无签名"}:
        text = "未发现有效证书签名信息，静态可信度降低。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("signature_missing", text, [first_field_name(sample, "signature_status")], sample, 0.72))
        risk += 0.28
    elif signature in {"valid", "normal", "正常", "一致"} or cert:
        text = "签名状态或证书指纹可用，暂未发现明确签名异常。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("signature_normal", text, [first_field_name(sample, "signature_status"), first_field_name(sample, "certificate_fingerprint")], sample, 0.35, "supports_benign"))
        risk += 0.02

    packer = first_value(sample, "packer")
    packer_text = to_text(packer).lower()
    if bool_positive(packer) or any(word in packer_text for word in ("packer", "shell", "jiagu", "加固", "壳", "混淆")):
        text = "识别到加固、壳或混淆特征，可能影响静态解析完整性。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("packer_or_obfuscation", text, [first_field_name(sample, "packer")], sample, 0.68))
        risk += 0.18

    permissions = [to_text(item).lower() for item in to_list(first_value(sample, "permissions"))]
    risky_permissions = sorted(p for p in permissions if any(term in p for term in ("sms", "contact", "overlay", "install", "accessibility", "phone", "location")))
    if risky_permissions:
        text = f"发现高风险 Android 权限：{', '.join(risky_permissions[:6])}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("permission_risk", text, [first_field_name(sample, "permissions")], sample, min(0.9, 0.35 + 0.08 * len(risky_permissions))))
        risk += min(0.24, 0.06 * len(risky_permissions))

    sdk_values = [to_text(item).lower() for item in to_list(first_value(sample, "sdk_list"))]
    risky_sdks = [sdk for sdk in sdk_values if any(term in sdk for term in ("ad", "push", "track", "analytics", "pay", "risk", "malware"))]
    if risky_sdks:
        text = f"第三方 SDK 清单中存在潜在风险 SDK：{', '.join(risky_sdks[:5])}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("sdk_risk", text, [first_field_name(sample, "sdk_list")], sample, min(0.85, 0.32 + 0.08 * len(risky_sdks))))
        risk += min(0.18, 0.05 * len(risky_sdks))

    if not evidence:
        text = "已完成签名、加固和 SDK 维度检查，未发现明确静态高危信号。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("static_baseline", text, [], sample, 0.28, "supports_benign"))

    score = clamp(risk)
    confidence = clamp(max(0.35, min(0.92, score + 0.18 + 0.04 * len(evidence))))
    return EvidenceBlock("static_analysis", label_claim(score, "静态可信度风险"), evidence, confidence, missing, score, evidence_items)


def threat_intel_agent(sample: dict[str, Any], iocs: list[dict[str, Any]]) -> EvidenceBlock:
    required = ("control_url", "download_url", "control_mailbox", "control_phone", "domains", "ips", "threat_intel_records", "fraud_family")
    if not iocs and not has_any_feature(sample, required):
        return missing_feature_block("threat_intel", "缺少域名、IP、控制地址、邮箱、手机号或情报命中记录，无法完成情报溯源判断。", list(required))

    evidence: list[str] = []
    evidence_items: list[dict[str, Any]] = []
    missing = [field for field in required if first_value(sample, field) in ("", None, [], {})]
    risk = 0.06

    suspicious_terms = ("c2", "bot", "fraud", "phish", "malware", "black", "risk", "wallet", "loan", "钓鱼", "诈骗", "黑产")
    source_map = {"control_url": "控制端地址", "download_url": "下载地址", "control_mailbox": "控制邮箱", "control_phone": "控制手机号"}
    for logical_field, label in source_map.items():
        value = to_text(first_value(sample, logical_field)).lower()
        if value and any(term in value for term in suspicious_terms):
            text = f"{label}包含高风险关键词或疑似黑产基础设施特征。"
            evidence.append(text)
            evidence_items.append(make_evidence_item("control_infrastructure", text, [first_field_name(sample, logical_field)], sample, 0.78))
            risk += 0.24

    if iocs:
        counts: dict[str, int] = {}
        for item in iocs:
            kind = str(item.get("type", "indicator"))
            counts[kind] = counts.get(kind, 0) + 1
        text = "共提取 " + "、".join(f"{count} 个{kind}" for kind, count in sorted(counts.items())) + " 威胁指标。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("network_indicator", text, [], sample, min(0.88, 0.36 + 0.05 * len(iocs))))
        risk += min(0.28, 0.045 * len(iocs))

    intel_records = to_list(first_value(sample, "threat_intel_records"))
    if intel_records:
        text = f"本地情报库命中 {len(intel_records)} 条威胁记录。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("threat_intel_hit", text, [first_field_name(sample, "threat_intel_records")], sample, 0.86))
        risk += min(0.32, 0.12 * len(intel_records))

    family = to_text(first_value(sample, "fraud_family"))
    if family:
        text = f"样本关联到黑产或反诈家族：{family}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("malware_family", text, [first_field_name(sample, "fraud_family")], sample, 0.74))
        risk += 0.2

    if not evidence:
        text = "当前可用网络与情报字段未命中明确威胁记录。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("threat_intel_clear", text, [], sample, 0.25, "supports_benign"))

    score = clamp(risk)
    confidence = clamp(max(0.34, min(0.94, score + 0.16 + 0.03 * len(evidence))))
    return EvidenceBlock("threat_intel", label_claim(score, "情报关联风险"), evidence, confidence, missing, score, evidence_items)


def impersonation_agent(sample: dict[str, Any]) -> EvidenceBlock:
    required = ("fake_app", "app_name", "package_name", "official_app_name", "official_pkg", "official_md5", "official_icon", "brand_similarity")
    analysis = sample.get("impersonation_analysis") if isinstance(sample.get("impersonation_analysis"), dict) else {}
    if not analysis and not has_any_feature(sample, required):
        return missing_feature_block("impersonation", "缺少仿冒标记、应用名称、包名或正版应用特征，无法完成仿冒研判。", list(required))

    evidence: list[str] = []
    evidence_items: list[dict[str, Any]] = []
    missing = [field for field in required if first_value(sample, field) in ("", None, [], {})]
    risk = 0.05

    assessment = analysis.get("assessment", {}) if isinstance(analysis.get("assessment"), dict) else {}
    visual = analysis.get("visual_similarity", {}) if isinstance(analysis.get("visual_similarity"), dict) else {}
    semantic = analysis.get("semantic_distance", {}) if isinstance(analysis.get("semantic_distance"), dict) else {}
    asset_match = analysis.get("official_asset_match", {}) if isinstance(analysis.get("official_asset_match"), dict) else {}
    for missing_field in assessment.get("missing_fields", []) if isinstance(assessment.get("missing_fields"), list) else []:
        if missing_field not in missing:
            missing.append(missing_field)

    impersonation_probability = numeric_value(assessment.get("impersonation_probability"))
    if impersonation_probability is not None:
        probability = clamp(impersonation_probability)
        text = f"预处理仿冒模型综合正版资产、视觉相似度和语义编辑距离，给出仿冒恶意概率 {probability:.2f}。"
        evidence.append(text)
        evidence_items.append(
            {
                "evidence_type": "impersonation_probability",
                "source_fields": ["impersonation_analysis.assessment.impersonation_probability"],
                "source_values": [f"impersonation_probability={probability:.4f}"],
                "direction": "supports_malicious" if probability >= 0.5 else "supports_benign",
                "strength": probability,
                "description": text,
            }
        )
        risk = max(risk, probability)

    best_asset = asset_match.get("best_match") if isinstance(asset_match.get("best_match"), dict) else {}
    if best_asset:
        match_score = clamp(numeric_value(best_asset.get("match_score")) or 0.0)
        brand = to_text(best_asset.get("brand") or best_asset.get("package_name") or best_asset.get("app_name"))
        text = f"正版应用库匹配到最接近资产：{brand or '未命名资产'}，匹配分 {match_score:.2f}。"
        evidence.append(text)
        evidence_items.append(
            {
                "evidence_type": "official_asset_match",
                "source_fields": ["official_app_assets", "impersonation_analysis.official_asset_match"],
                "source_values": [f"brand={brand}", f"match_score={match_score:.4f}"],
                "direction": "supports_malicious" if match_score >= 0.55 else "context",
                "strength": match_score,
                "description": text,
            }
        )
        risk = max(risk, match_score)

    visual_best = visual.get("best_match") if isinstance(visual.get("best_match"), dict) else {}
    visual_score = clamp(numeric_value(visual_best.get("icon_similarity")) or 0.0)
    if visual_score >= 0.7:
        text = f"样本图标或图标文字与正版资产高度相似，相似度 {visual_score:.2f}。"
        evidence.append(text)
        evidence_items.append(
            {
                "evidence_type": "visual_similarity",
                "source_fields": ["icon_hash", "icon_text", "official_app_assets"],
                "source_values": [f"icon_similarity={visual_score:.4f}"],
                "direction": "supports_malicious",
                "strength": visual_score,
                "description": text,
            }
        )
        risk = max(risk, 0.72 + 0.18 * visual_score)

    semantic_best = semantic.get("best_match") if isinstance(semantic.get("best_match"), dict) else {}
    semantic_score = clamp(numeric_value(semantic_best.get("combined_similarity")) or 0.0)
    tamper_tags = semantic_best.get("tamper_tags") if isinstance(semantic_best.get("tamper_tags"), list) else []
    if semantic_score >= 0.65 or tamper_tags:
        tag_text = "、".join(str(item) for item in tamper_tags[:4]) or "名称/包名相似"
        text = f"应用名称或包名与正版资产存在语义编辑相似，分数 {semantic_score:.2f}，疑似手法：{tag_text}。"
        evidence.append(text)
        evidence_items.append(
            {
                "evidence_type": "semantic_edit_distance",
                "source_fields": ["app_name", "package_name", "official_app_assets"],
                "source_values": [f"combined_similarity={semantic_score:.4f}", f"tamper_tags={tag_text}"],
                "direction": "supports_malicious",
                "strength": max(semantic_score, 0.66),
                "description": text,
            }
        )
        risk = max(risk, 0.68 + 0.16 * semantic_score)

    if bool_positive(first_value(sample, "fake_app")):
        text = "样本存在 fakeApp/仿冒应用标记。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("declared_impersonation", text, [first_field_name(sample, "fake_app")], sample, 0.84))
        risk += 0.32

    app_name = to_text(first_value(sample, "app_name"))
    package_name = to_text(first_value(sample, "package_name"))
    official_name = to_text(first_value(sample, "official_app_name"))
    official_pkg = to_text(first_value(sample, "official_pkg"))
    if official_name or official_pkg:
        text = f"已加载正版应用基准：名称 {official_name or '缺失'}，包名 {official_pkg or '缺失'}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("official_asset_reference", text, [first_field_name(sample, "official_app_name"), first_field_name(sample, "official_pkg")], sample, 0.48, "context"))
        risk += 0.04

    similarity = numeric_value(first_value(sample, "brand_similarity"))
    if similarity is not None:
        normalized = similarity if similarity <= 1 else similarity / 100
        text = f"与正版应用图标、名称或包名的相似度为 {normalized:.2f}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("brand_similarity", text, [first_field_name(sample, "brand_similarity")], sample, normalized))
        risk += 0.26 if normalized >= 0.75 else 0.14 if normalized >= 0.45 else 0.03

    sensitive_words = {"bank": "银行", "wallet": "钱包", "pay": "支付", "loan": "贷款", "secure": "安全", "finance": "金融", "银行": "银行", "钱包": "钱包", "支付": "支付", "贷款": "贷款"}
    name_pkg = f"{app_name} {package_name}".lower()
    hit_words = sorted({label for key, label in sensitive_words.items() if key in name_pkg})
    if hit_words:
        text = f"应用名或包名包含敏感业务词：{', '.join(hit_words)}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("name_obfuscation", text, [first_field_name(sample, "app_name"), first_field_name(sample, "package_name")], sample, 0.52))
        risk += min(0.18, 0.06 * len(hit_words))

    if official_pkg and package_name and official_pkg != package_name and official_pkg.split(".")[-1:] == package_name.split(".")[-1:]:
        text = "包名与正版包名不完全一致，但尾部命名相近，存在克隆或变种可能。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("package_edit_distance", text, [first_field_name(sample, "package_name"), first_field_name(sample, "official_pkg")], sample, 0.66))
        risk += 0.16

    if not evidence:
        text = "当前字段未发现足够强的仿冒证据。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("impersonation_clear", text, [], sample, 0.22, "supports_benign"))

    score = clamp(risk)
    confidence = clamp(max(0.32, min(0.93, score + 0.18 + 0.03 * len(evidence))))
    return EvidenceBlock("impersonation", label_claim(score, "仿冒风险"), evidence, confidence, missing, score, evidence_items)


def business_label_agent(sample: dict[str, Any]) -> EvidenceBlock:
    required = ("virus_name", "risk_score", "fraud_family", "fraud_category_big", "fraud_category_small", "harm_type", "version_status", "app_name")
    if not has_any_feature(sample, required):
        return missing_feature_block("business_label", "缺少病毒名称、分数、涉诈家族、危害类型或版本状态，无法完成业务打标。", list(required))

    evidence: list[str] = []
    evidence_items: list[dict[str, Any]] = []
    missing = [field for field in required if first_value(sample, field) in ("", None, [], {})]
    labels: list[str] = []
    risk = 0.05

    virus_name = to_text(first_value(sample, "virus_name"))
    family = to_text(first_value(sample, "fraud_family"))
    category_big = to_text(first_value(sample, "fraud_category_big"))
    category_small = to_text(first_value(sample, "fraud_category_small"))
    harm_type = to_text(first_value(sample, "harm_type"))
    version_status = to_text(first_value(sample, "version_status"))
    risk_score = numeric_value(first_value(sample, "risk_score"))
    haystack = f"{virus_name} {family} {category_big} {category_small} {harm_type}".lower()

    if any(term in haystack for term in ("fraud", "phish", "scam", "loan", "诈骗", "钓鱼", "贷款", "金融")):
        labels.append("涉诈应用")
        risk += 0.26
    if any(term in haystack for term in ("trojan", "spy", "stealer", "盗取", "短信", "通讯录", "隐私")):
        labels.append("隐私窃取或木马")
        risk += 0.22
    if bool_positive(first_value(sample, "fake_app")) or "仿冒" in haystack:
        labels.append("仿冒品牌")
        risk += 0.18

    if category_big or category_small:
        text = f"建议涉诈分类：{category_big or '未给出大类'} / {category_small or '未给出小类'}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("fraud_category", text, [first_field_name(sample, "fraud_category_big"), first_field_name(sample, "fraud_category_small")], sample, 0.72))
        risk += 0.12

    if harm_type:
        text = f"建议危害类型：{harm_type}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("harm_category", text, [first_field_name(sample, "harm_type")], sample, 0.68))
        risk += 0.1

    if family:
        text = f"业务侧关联家族或团伙：{family}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("fraud_family", text, [first_field_name(sample, "fraud_family")], sample, 0.76))
        risk += 0.16

    if risk_score is not None:
        normalized = risk_score if risk_score <= 1 else risk_score / 100
        text = f"上游风险分数为 {normalized:.2f}，用于业务侧优先级参考。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("risk_score", text, [first_field_name(sample, "risk_score")], sample, normalized))
        risk += min(0.18, normalized * 0.18)

    if version_status:
        text = f"版本状态：{version_status}。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("version_status", text, [first_field_name(sample, "version_status")], sample, 0.45, "context"))

    if labels:
        label_text = f"推断出的业务标签：{', '.join(dict.fromkeys(labels))}。"
        evidence.append(label_text)
        evidence_items.append(make_evidence_item("business_tags", label_text, [], sample, 0.74))

    if not evidence:
        text = "当前字段不足以推断明确业务标签。"
        evidence.append(text)
        evidence_items.append(make_evidence_item("business_label_missing", text, [], sample, 0.2, "insufficient"))

    score = clamp(risk)
    confidence = clamp(max(0.32, min(0.94, score + 0.16 + 0.03 * len(evidence))))
    return EvidenceBlock("business_label", label_claim(score, "业务影响风险"), evidence, confidence, missing, score, evidence_items)


AGENT_EVIDENCE_RULES = {
    "static_analysis": (
        ("signature_anomaly", ("签名", "证书"), ("signature_status", "certificate_fingerprint", "cert_sha1", "cert_sha256")),
        ("packer_or_obfuscation", ("加固", "壳", "混淆"), ("packer", "code_fuscator", "unshell_info")),
        ("permission_risk", ("权限",), ("permissions",)),
        ("sdk_risk", ("sdk", "SDK"), ("sdk_list", "plugins")),
        ("engine_static_conflict", ("引擎", "评分差"), ("engine_a_score", "engine_b_score", "engine_a_label", "engine_b_label")),
    ),
    "threat_intel": (
        ("control_infrastructure", ("控制", "C2", "c2"), ("control_url", "control_mailbox", "control_phone")),
        ("download_infrastructure", ("下载", "投递"), ("download_url", "lt_urls")),
        ("network_indicator", ("网络", "域名", "IP", "ip", "指标"), ("domains", "ips", "top_domains", "dynamic_nets")),
        ("malware_family", ("病毒", "家族", "黑产"), ("virus_name", "virus_description", "fraud_family")),
    ),
    "impersonation": (
        ("declared_impersonation", ("仿冒", "盗版"), ("fake_app", "impersonation_flag", "rebuild_type")),
        ("official_asset_reference", ("正版", "相似度"), ("official_app_name", "official_pkg", "official_md5", "brand_similarity")),
        ("name_obfuscation", ("应用名称", "包名", "敏感词"), ("app_name", "package_name")),
    ),
    "business_label": (
        ("fraud_category", ("涉诈", "诈骗", "业务标签"), ("fraud_flag", "fraud_category_big", "fraud_category_small", "fraud_family")),
        ("harm_category", ("危害", "病毒", "恶意"), ("risk_type", "virus_name", "virus_description")),
        ("app_name_semantics", ("应用名称", "业务语义"), ("app_name",)),
    ),
}


def add_structured_evidence(
    blocks: list[EvidenceBlock],
    sample: dict[str, Any],
) -> list[EvidenceBlock]:
    from dataclasses import replace

    result = []
    for block in blocks:
        if block.evidence_items:
            result.append(block)
            continue
        items = []
        rules = AGENT_EVIDENCE_RULES.get(block.agent, ())
        for description in block.evidence:
            lowered = str(description).lower()
            evidence_type = "context"
            source_fields: tuple[str, ...] = ()
            for candidate_type, terms, fields in rules:
                if any(term.lower() in lowered for term in terms):
                    evidence_type = candidate_type
                    source_fields = fields
                    break
            values = [
                f"{field}={compact_evidence_value(sample.get(field))}"
                for field in source_fields
                if sample.get(field) not in ("", None, [], {})
            ]
            direction = (
                "supports_malicious"
                if block.score >= 0.55 and not any(term in lowered for term in ("未发现", "较低", "正常"))
                else "supports_benign"
                if any(term in lowered for term in ("未发现", "较低", "正常"))
                else "context"
            )
            items.append(
                {
                    "evidence_type": evidence_type,
                    "source_fields": list(source_fields),
                    "source_values": values[:6],
                    "direction": direction,
                    "strength": round(float(block.score), 4),
                    "description": str(description),
                }
            )
        result.append(replace(block, evidence_items=items))
    return result


def apply_xgb_agent_scores(
    blocks: list[EvidenceBlock],
    xgb_result: dict[str, Any] | None,
) -> list[EvidenceBlock]:
    """Attach learned priors without overwriting observable Agent evidence.

    ``EvidenceBlock.score`` is the malicious probability supported by the
    block's concrete evidence.  The old implementation replaced it with the
    XGBoost domain prior, which could produce contradictory cards such as
    "impersonation probability 0" together with "high impersonation risk".
    Keeping ``ml_prior`` separate also prevents the same XGBoost signal from
    being counted once in every Agent and again in final fusion.
    """
    if not xgb_result:
        return blocks
    from dataclasses import replace

    agent_scores = xgb_result.get("agent_scores") or {}
    if not isinstance(agent_scores, dict):
        return blocks
    result: list[EvidenceBlock] = []
    for block in blocks:
        if block.agent not in agent_scores:
            result.append(block)
            continue
        try:
            learned_score = clamp(float(agent_scores[block.agent]))
        except (TypeError, ValueError):
            result.append(block)
            continue
        evidence_items = list(block.evidence_items)
        evidence_items.append(
            {
                "evidence_type": "xgboost_domain_probability",
                "source_fields": ["xgb_agent_scores", block.agent],
                "source_values": [f"xgb_score={learned_score:.4f}"],
                "direction": "model_prior",
                "strength": learned_score,
                "description": (
                    f"领域机器学习先验恶意概率为 {learned_score:.3f}；"
                    "该值仅供交叉核验，不覆盖当前Agent的事实证据结论。"
                ),
            }
        )
        result.append(
            replace(
                block,
                evidence_items=evidence_items,
                rule_score=(
                    block.rule_score
                    if block.rule_score is not None
                    else clamp(float(block.score))
                ),
                ml_prior=learned_score,
            )
        )
    return result


def add_evidence_conflict_markers(blocks: list[EvidenceBlock]) -> list[EvidenceBlock]:
    """Mark cases where learned ML prior and concrete domain evidence disagree.

    XGBoost is a learned prior, not an automatic override.  When it points in a
    different direction from the rule/tool evidence, we keep both signals and
    add an explicit conflict item so model A/B must discuss the disagreement.
    """
    from dataclasses import replace

    result: list[EvidenceBlock] = []
    for block in blocks:
        ml_item = _primary_ml_prior_item(block.evidence_items)
        if not ml_item:
            result.append(block)
            continue
        ml_score = _safe_float(ml_item.get("strength"), block.score)
        concrete = [
            item
            for item in block.evidence_items
            if isinstance(item, dict) and not _is_ml_prior_item(item) and item.get("evidence_type") != "missing_feature"
        ]
        malicious_strength = sum(_safe_float(item.get("strength"), 0.0) for item in concrete if item.get("direction") == "supports_malicious")
        benign_strength = sum(_safe_float(item.get("strength"), 0.0) for item in concrete if item.get("direction") == "supports_benign")
        benign_items = [item for item in concrete if item.get("direction") == "supports_benign"]
        missing_pressure = len(block.missing_fields) >= 3

        conflict_reason = ""
        trust_hint = ""
        if ml_score >= 0.70 and (benign_strength >= 0.20 or (benign_items and malicious_strength < 0.25)):
            conflict_reason = (
                f"机器学习先验恶意概率为 {ml_score:.3f}，但该领域存在偏良性或证据不足的领域证据；"
                "不能直接用机器学习概率覆盖领域证据。"
            )
            trust_hint = "需要模型甲乙复核：若良性证据来自强字段，应降低结论；若良性只是字段缺失导致，应保留可疑或恶意倾向。"
        elif ml_score <= 0.30 and malicious_strength >= 0.45:
            conflict_reason = (
                f"机器学习先验恶意概率为 {ml_score:.3f}，但该领域存在较强恶意领域证据；"
                "需要检查机器学习是否漏报。"
            )
            trust_hint = "需要模型甲乙复核：优先解释强恶意证据是否能独立支撑风险。"
        elif ml_score >= 0.70 and missing_pressure and malicious_strength < 0.30:
            conflict_reason = (
                f"机器学习先验恶意概率为 {ml_score:.3f}，但该领域关键字段缺失且具体恶意证据不足；"
                "需要在机器学习先验和当前可见领域证据之间做取舍。"
            )
            trust_hint = "需要模型甲乙复核：结合字段缺口与其他智能体证据，判断应保留恶意倾向、降为可疑，还是补充字段后再判。"

        if not conflict_reason:
            result.append(block)
            continue

        top_concrete = sorted(concrete, key=lambda item: _safe_float(item.get("strength"), 0.0), reverse=True)[:3]
        conflict_item = {
            "evidence_type": "evidence_conflict",
            "source_fields": ["xgb_agent_scores", block.agent]
            + sorted({field for item in top_concrete for field in item.get("source_fields", []) if field})[:4],
            "source_values": [
                f"ml_prior={ml_score:.4f}",
                f"domain_malicious_strength={malicious_strength:.4f}",
                f"domain_benign_strength={benign_strength:.4f}",
                f"missing_fields={len(block.missing_fields)}",
            ],
            "direction": "context",
            "strength": clamp(abs(ml_score - max(malicious_strength, 1.0 - min(benign_strength, 1.0))) if top_concrete else ml_score),
            "description": conflict_reason,
            "trust_hint": trust_hint,
            "debate_question": (
                f"{agent_public_name(block.agent)} 中机器学习先验与领域证据冲突，"
                "模型甲乙需要判断应优先相信具体证据、机器学习先验，还是标为可疑并补充字段。"
            ),
        }
        result.append(replace(block, evidence_items=[conflict_item] + list(block.evidence_items)))
    return result


def _is_ml_prior_item(item: dict[str, Any]) -> bool:
    source_fields = {str(field) for field in item.get("source_fields", [])}
    return item.get("evidence_type") == "xgboost_domain_probability" or "xgb_agent_scores" in source_fields


def _primary_ml_prior_item(items: list[dict[str, Any]]) -> dict[str, Any] | None:
    priors = [item for item in items if isinstance(item, dict) and _is_ml_prior_item(item)]
    if not priors:
        return None
    return max(priors, key=lambda item: _safe_float(item.get("strength"), 0.0))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def agent_public_name(agent: str) -> str:
    return {
        "static_analysis": "静态分析智能体",
        "threat_intel": "情报溯源智能体",
        "impersonation": "仿冒研判智能体",
        "business_label": "业务打标智能体",
    }.get(agent, agent)


def claim_dimension(agent: str) -> str:
    return {
        "static_analysis": "静态可信度风险",
        "threat_intel": "情报关联风险",
        "impersonation": "仿冒风险",
        "business_label": "业务影响风险",
    }.get(agent, "领域风险")


def valid_md5(value: Any) -> bool:
    text = str(value or "").strip()
    return len(text) == 32 and all(ch in "0123456789abcdefABCDEF" for ch in text)


def evidence_coverage(block: EvidenceBlock) -> float:
    source_fields = {
        field
        for item in block.evidence_items
        if isinstance(item, dict)
        for field in item.get("source_fields", [])
        if field
    }
    known = len(source_fields) + len(block.evidence)
    missing = len(block.missing_fields)
    if known + missing <= 0:
        return 0.5
    return clamp(known / (known + missing))


def evidence_direction_consistency(items: list[dict[str, Any]]) -> float:
    malicious = 0.0
    benign = 0.0
    for item in items:
        try:
            strength = clamp(float(item.get("strength", 0)))
        except (TypeError, ValueError):
            strength = 0.0
        direction = str(item.get("direction") or "")
        if direction == "supports_malicious":
            malicious += strength
        elif direction == "supports_benign":
            benign += strength
    total = malicious + benign
    if total <= 0:
        return 0.5
    return clamp(abs(malicious - benign) / total)


def calibrated_agent_confidence(score: float, coverage: float, consistency: float, missing_count: int) -> float:
    certainty = max(score, 1.0 - score)
    confidence = 0.6 * certainty + 0.25 * coverage + 0.15 * consistency
    if missing_count >= 5:
        confidence *= 0.75
    elif missing_count >= 3:
        confidence *= 0.85
    return clamp(confidence)


def compact_evidence_value(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
    return text[:240]


def clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def run_agents(
    sample: dict[str, Any],
    iocs: list[dict[str, Any]],
    *,
    run_id: str,
) -> tuple[list[EvidenceBlock], dict[str, Any], list[AgentResult]]:
    from malapp.inference.expert import ExpertModelProvider
    from malapp.orchestration.investigation import run_investigation

    expert_provider = ExpertModelProvider()
    agents = [
        StaticAnalysisAgent(static_analysis_agent, expert_provider),
        ThreatIntelAgent(threat_intel_agent, expert_provider),
        ImpersonationAgent(impersonation_agent, expert_provider),
        BusinessLabelAgent(business_label_agent, expert_provider),
    ]
    return run_investigation(
        sample,
        iocs,
        run_id=run_id,
        agents=agents,
        expert_provider=expert_provider,
    )


def debate(evidence_blocks: list[EvidenceBlock], config: dict[str, Any] | None = None) -> dict[str, Any]:
    return run_debate(evidence_blocks, config)

def build_static_feedback(sample: dict[str, Any], evidence_blocks: list[EvidenceBlock]) -> dict[str, Any]:
    static_block = next((block for block in evidence_blocks if block.agent == "static_analysis"), None)
    return {
        "score": sample.get("static_trust", {}).get("score"),
        "level": sample.get("static_trust", {}).get("level"),
        "claim": static_block.claim if static_block else "",
        "evidence": static_block.evidence if static_block else [],
        "signature_status": sample.get("signature_status", "unknown"),
        "packer_matches": sample.get("packer_matches", []),
        "sdk_risk": sample.get("sdk_risk", {}),
        "anomalies": sample.get("static_trust", {}).get("anomalies", []),
    }


def cached_report_usable(
    cached: dict[str, Any] | None,
    *,
    require_learned_agent_scores: bool,
    has_valid_md5_for_xgb: bool,
    require_model_signature: bool = False,
    orchestration_mode_name: str | None = None,
) -> bool:
    if not cached:
        return False
    expected_mode = orchestration_mode_name or orchestration_mode()
    cached_mode = str(
        (cached.get("execution") or {}).get("orchestration_mode") or "v0_fixed"
    )
    if cached_mode != expected_mode:
        return False
    cached_tools = bool((cached.get("execution") or {}).get("tool_runtime_enabled"))
    if cached_tools != tool_runtime_enabled():
        return False
    cache_has_learned_agent_scores = any(
        item.get("evidence_type") == "xgboost_domain_probability"
        for block in cached.get("evidence_blocks", [])
        for item in block.get("evidence_items", [])
        if isinstance(item, dict)
    )
    if require_model_signature:
        try:
            from malapp.inference.settings import model_cache_signature

            if cached.get("execution", {}).get("model_cache_signature") != model_cache_signature():
                return False
        except Exception:
            return False
    return bool(
        cached.get("report_schema_version") == REPORT_SCHEMA_VERSION
        and (not require_learned_agent_scores or cache_has_learned_agent_scores)
        and (has_valid_md5_for_xgb or not cache_has_learned_agent_scores)
        and cached.get("preprocess", {}).get("threat_intelligence")
        and cached.get("preprocess", {}).get("impersonation_analysis")
        and cached.get("preprocess", {}).get("business_label_analysis")
        and cached.get("preprocess", {}).get("agent_output_validation")
        and cached.get("preprocess", {}).get("agent_runtime")
        and cached.get("decision", {}).get("decision_trace")
    )


def mark_history_reused(
    report: dict[str, Any],
    source: str,
    *,
    run_id: str,
    pipeline: PipelineStateMachine,
) -> dict[str, Any]:
    reused = copy.deepcopy(report)
    previous_run_id = reused.get("run_id") or reused.get("execution", {}).get("run_id")
    previous_pipeline = reused.get("execution", {}).get("pipeline")
    previous_created_at = reused.get("created_at")
    reused["run_id"] = run_id
    reused["created_at"] = utc_now()
    reused["cache_hit"] = True
    reused["cache_source"] = source
    reused.setdefault("execution", {})
    reused["execution"]["run_id"] = run_id
    reused["execution"]["history_reused"] = True
    reused["execution"]["history_reuse_source"] = source
    reused["execution"]["cached_artifact_run_id"] = previous_run_id
    reused["execution"]["cached_artifact_created_at"] = previous_created_at
    reused["execution"]["cached_artifact_pipeline"] = previous_pipeline
    reused["execution"]["pipeline"] = pipeline.snapshot()
    reused.setdefault("preprocess", {})["agent_runtime"] = {
        "run_id": run_id,
        "request_id": run_id,
        "status": "skipped",
        "skip_reason": "history_cache_hit",
        "agents": {},
    }
    reused.setdefault("debate", {})["run_id"] = run_id
    reused["debate"]["model_calls"] = []
    return reused


def build_engine_c_skipped_report(
    sample: dict[str, Any],
    *,
    unmapped: list[str],
    evaluation_metadata: dict[str, Any],
    evaluation_config: dict[str, Any],
    entrypoint: str,
    pipeline: PipelineStateMachine,
    admission: Any,
    decision_params: dict[str, Any],
) -> dict[str, Any]:
    """Build the upstream A/B result whenever the original Engine C gate stays closed."""
    from malapp.application.engine_c_admission import direct_ab_consensus_decision
    from malapp.data_import.preprocess import set_cached_report
    from malapp.governance.runtime import save_runtime_snapshot
    from malapp.inference.settings import model_cache_signature

    decision = direct_ab_consensus_decision(sample, admission, decision_params)
    runtime_snapshot = save_runtime_snapshot(
        decision_params=decision_params,
        data_dir=DATA_DIR,
        admission=admission.to_dict(),
        evidence_envelope=None,
        expert_runtime=None,
        debate_conformance="not_executed",
        wec_policy=decision["fusion"],
    )
    report = {
        "run_id": pipeline.run_id,
        "report_id": hashlib.sha1(
            json.dumps(sample, sort_keys=True, ensure_ascii=False).encode("utf-8")
        ).hexdigest()[:16],
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "created_at": utc_now(),
        "runtime_snapshot": runtime_snapshot,
        "sample": sample,
        "engine_c": {**admission.to_dict(), "executed": False, "score_c": None},
        "preprocess": {
            "unmapped_fields": unmapped,
            "agent_runtime": {
                "run_id": pipeline.run_id,
                "request_id": pipeline.run_id,
                "status": "skipped",
                "skip_reason": "engine_c_not_admitted",
                "agents": {},
            },
        },
        "evidence_blocks": [],
        "evidence_layers": {
            "raw_evidence": {},
            "structured_evidence_blocks": [],
            "canonical_evidence_envelope": None,
            "llm_explanation": {"status": "skipped", "agent_explanations": []},
            "rag_context": {"enabled": False, "ready": False, "items": [], "skip_reason": "engine_c_not_admitted"},
        },
        "debate": {
            "run_id": pipeline.run_id,
            "execution_mode": "skipped",
            "skip_reason": "engine_c_not_admitted",
            "debate_conformance": "not_executed",
            "arbiter": None,
            "stages": [],
            "model_calls": [],
        },
        "decision": decision,
        "degradation": {"status": "healthy", "reasons": []},
        "next_steps": [],
        "execution": {
            "run_id": pipeline.run_id,
            "orchestrator": "agent_runtime",
            "orchestration_mode": orchestration_mode(),
            "tool_runtime_enabled": tool_runtime_enabled(),
            "entrypoint": entrypoint,
            "service_pipeline": "malapp.agent-runtime.v2",
            "history_reused": False,
            "model_cache_signature": model_cache_signature(),
            "runtime_snapshot_id": runtime_snapshot["snapshot_id"],
            "evaluation_config": evaluation_config,
            "evaluation_variant": os.getenv("MALAPP_EVAL_VARIANT", "production"),
            "pipeline": pipeline.snapshot(),
        },
        "evaluation_metadata": evaluation_metadata,
    }
    init_db()
    attach_decision_provenance(report)
    insert_report(report)
    persist_observability_metrics(report)
    try:
        from malapp.observability.trace import save_agent_trace

        trace = save_agent_trace(report)
        report["execution"]["agent_trace_id"] = trace.get("trace_id")
        insert_report(report)
    except Exception as exc:
        report["execution"]["agent_trace_error"] = str(exc)
    set_cached_report(sample, report)
    return report


def execute_judgement(raw_sample: dict[str, Any], *, entrypoint: str = "internal") -> dict[str, Any]:
    """Run the one authoritative judgement pipeline for every transport."""
    from malapp.data_import.preprocess import (
        build_feature_packages,
        get_cached_report,
        get_latest_cached_report_by_md5,
        load_feature_context,
        set_cached_report,
    )

    pipeline = PipelineStateMachine()
    run_id = pipeline.run_id
    pipeline.start("NORMALIZE", raw_sample)
    try:
        raw_sample = dict(raw_sample)
        evaluation_config = (
            dict(raw_sample.pop("evaluation_config"))
            if isinstance(raw_sample.get("evaluation_config"), dict)
            else {}
        )
        evaluation_variant = os.getenv("MALAPP_EVAL_VARIANT", "production").strip()
        if evaluation_config and (
            entrypoint != "internal" or evaluation_variant in {"", "production"}
        ):
            raise ValueError(
                "evaluation_config is restricted to the isolated evaluation runner"
            )
        md5 = str(raw_sample.get("md5") or raw_sample.get("sample_id") or "").upper().strip()
        if md5:
            feature_context = load_feature_context(md5)
            feature_context.update(
                {key: value for key, value in raw_sample.items() if value not in ("", None) and value != []}
            )
            raw_sample = feature_context
        evaluation_fields = {
            "gold_label",
            "human_label",
            "label_source",
            "sample_weight",
            "xgb_probability",
            "xgb_verdict",
        }
        evaluation_metadata = {
            key: raw_sample.get(key)
            for key in evaluation_fields
            if raw_sample.get(key) not in ("", None)
        }
        try:
            from malapp.inference.xgboost import enrich_sample as enrich_xgb_sample

            raw_sample = enrich_xgb_sample(raw_sample)
        except Exception:
            pass
        for key in evaluation_fields:
            raw_sample.pop(key, None)
        raw_sample.pop("filepath", None)
        normalized, unmapped = normalize_sample(raw_sample)
        from malapp.application.engine_c_admission import EngineCAdmissionPolicy
        from malapp.orchestration.decision import load_decision_params, merge_params

        decision_params = load_decision_params()
        if isinstance(normalized.get("decision_params"), dict):
            decision_params = merge_params(decision_params, normalized["decision_params"])
        admission = EngineCAdmissionPolicy(decision_params).decide(normalized)
        if not admission.execute:
            pipeline.skip(
                "NORMALIZE",
                "engine_c_not_admitted",
                {"reason": admission.reason.value, "sample_id": normalized["sample_id"]},
            )
            for stage in pipeline.snapshot()["stage_order"][1:]:
                pipeline.skip(stage, "engine_c_not_admitted", {"reason": admission.reason.value})
            return build_engine_c_skipped_report(
                normalized,
                unmapped=unmapped,
                evaluation_metadata=evaluation_metadata,
                evaluation_config=evaluation_config,
                entrypoint=entrypoint,
                pipeline=pipeline,
                admission=admission,
                decision_params=decision_params,
            )
        pipeline.complete(
            "NORMALIZE",
            {"sample_id": normalized["sample_id"], "admission_reason": admission.reason.value},
            output_data={"sample_id": normalized["sample_id"], "unmapped_fields": unmapped},
        )
    except Exception as exc:
        if pipeline.snapshot()["by_name"]["NORMALIZE"]["status"] == "started":
            pipeline.fail("NORMALIZE", exc)
        raise

    pipeline.start("STATIC_EXTRACTION", normalized)
    try:
        apk_analysis: dict[str, Any] = {}
        apk_extracted, full_apk_analysis = analyze_apk_from_sample(normalized)
        if full_apk_analysis:
            apk_analysis = public_static_feedback(full_apk_analysis)
            apk_extracted["apk_analysis"] = apk_analysis
            apk_extracted.update(
                {
                    key: value
                    for key, value in normalized.items()
                    if key not in {"apk_base64", "apk_path", "apk_file"}
                    and value not in ("", None)
                    and value != []
                }
            )
            normalized, extracted_unmapped = normalize_sample(apk_extracted)
            unmapped = sorted(set(unmapped + extracted_unmapped))
        iocs = extract_iocs(normalized)
        static_package, network_package = build_feature_packages(normalized)
        pipeline.complete(
            "STATIC_EXTRACTION",
            {"apk_analyzed": bool(full_apk_analysis), "ioc_count": len(iocs)},
            output_data={"sample_id": normalized["sample_id"], "iocs": iocs},
        )
    except Exception as exc:
        pipeline.fail("STATIC_EXTRACTION", exc)
        raise

    cache_sample = dict(normalized)
    cached = get_cached_report(cache_sample)
    xgb_mode = str(evaluation_config.get("xgb_mode") or "full").strip().lower()
    xgb_mode = {
        "none": "off",
        "no_xgb": "off",
        "agent": "agent_only",
        "agent_xgb_only": "agent_only",
        "fusion_only": "fusion",
    }.get(xgb_mode, xgb_mode)
    if xgb_mode not in {"off", "agent_only", "fusion", "full"}:
        raise ValueError(f"unsupported evaluation xgb_mode: {xgb_mode}")
    has_valid_md5_for_xgb = valid_md5(normalized.get("md5") or normalized.get("sample_id"))
    xgb_cache_required = xgb_mode != "off" and has_valid_md5_for_xgb and str(os.getenv("MALAPP_USE_XGB", "1")).lower() in {
        "1",
        "true",
        "yes",
        "y",
    }
    cached_source = ""
    if cached_report_usable(
        cached,
        require_learned_agent_scores=xgb_cache_required,
        has_valid_md5_for_xgb=has_valid_md5_for_xgb,
    ):
        cached_source = "strict_sample_cache"
    elif str(os.getenv("MALAPP_MD5_REPORT_CACHE", "1")).lower() in {"1", "true", "yes", "y"} and has_valid_md5_for_xgb:
        cached = get_latest_cached_report_by_md5(normalized.get("md5") or normalized.get("sample_id"))
        if cached_report_usable(
            cached,
            require_learned_agent_scores=xgb_cache_required,
            has_valid_md5_for_xgb=has_valid_md5_for_xgb,
            require_model_signature=True,
        ):
            cached_source = "md5_report_cache"
    if cached_source and cached:
        for stage in ("AGENT_EXECUTION", "RAG_RETRIEVAL", "XGB_INFERENCE", "DEBATE", "FINAL_DECISION", "PERSIST"):
            pipeline.skip(stage, "history_cache_hit", {"cache_source": cached_source})
        reused = mark_history_reused(
            cached,
            cached_source,
            run_id=run_id,
            pipeline=pipeline,
        )
        reused.setdefault("execution", {})["entrypoint"] = entrypoint
        attach_decision_provenance(reused)
        persist_observability_metrics(reused)
        try:
            from malapp.observability.trace import save_agent_trace

            trace = save_agent_trace(reused)
            reused["execution"]["agent_trace_id"] = trace.get("trace_id")
            insert_report(reused)
        except Exception as exc:
            reused["execution"]["agent_trace_error"] = str(exc)
        return reused

    pipeline.start("AGENT_EXECUTION", {"sample_id": normalized["sample_id"], "iocs": iocs})
    try:
        evidence_blocks, agent_runtime, agent_results = run_agents(normalized, iocs, run_id=run_id)
        artifacts = {
            key: value
            for result in agent_results
            for key, value in result.artifacts.items()
            if key not in {"expert_review", "tool_observations", "tool_execution"}
        }
        threat_intelligence = artifacts.get("threat_intelligence", {})
        impersonation_analysis = artifacts.get("impersonation_analysis", {})
        business_label_analysis = artifacts.get("business_label_analysis", {})
        normalized.update(artifacts)
        evidence_blocks, agent_output_validation = validate_and_repair_evidence_blocks(evidence_blocks)
        evidence_blocks = add_structured_evidence(evidence_blocks, normalized)
        degradation_policy = merge_unavailable_evidence(
            evaluate_degradation(agent_results),
            (agent_runtime.get("investigation") or {}).get("evidence_gate"),
        )
        agent_metadata = {
            "runtime_status": agent_runtime["status"],
            "agent_statuses": {
                name: state["status"] for name, state in agent_runtime["agents"].items()
            },
            "artifact_keys": sorted(artifacts),
        }
        degradation_codes = [item["code"] for item in degradation_policy["reasons"]]
        if degradation_codes:
            pipeline.degrade("AGENT_EXECUTION", degradation_codes, agent_metadata)
        else:
            pipeline.complete(
                "AGENT_EXECUTION",
                agent_metadata,
                output_data={"results": agent_runtime.get("results"), "artifact_keys": sorted(artifacts)},
            )
    except Exception as exc:
        pipeline.fail("AGENT_EXECUTION", exc)
        raise

    raw_evidence_layer = build_raw_evidence_layer(
        normalized,
        iocs=iocs,
        static_feature_package=static_package,
        network_ioc_package=network_package,
        threat_intelligence=threat_intelligence,
        impersonation_analysis=impersonation_analysis,
        business_label_analysis=business_label_analysis,
        apk_analysis=apk_analysis,
    )

    pipeline.start(
        "RAG_RETRIEVAL",
        {"sample_id": normalized["sample_id"], "evidence_agents": [block.agent for block in evidence_blocks]},
    )
    try:
        rag_context = rag_context_for_sample(
            normalized,
            evidence_blocks,
            raw_evidence_layer,
            top_k=int(os.getenv("MALAPP_RAG_TOP_K", "6") or "6"),
        )
        pipeline.complete(
            "RAG_RETRIEVAL",
            {
                "enabled": bool(rag_context.get("enabled")),
                "result_count": len(rag_context.get("items", [])),
                "rag_snapshot_id": rag_context.get("rag_snapshot_id"),
            },
            output_data={"rag_snapshot_id": rag_context.get("rag_snapshot_id"), "items": rag_context.get("items", [])},
        )
    except Exception as exc:
        rag_context = {"enabled": False, "ready": False, "query": "", "items": [], "error": str(exc)}
        pipeline.degrade("RAG_RETRIEVAL", ["rag_retrieval_failed"], {"error": str(exc)})

    pipeline.start("XGB_INFERENCE", {"sample_id": normalized["sample_id"], "md5": normalized.get("md5")})
    xgb_result = None
    if xgb_mode == "off":
        pipeline.skip("XGB_INFERENCE", "evaluation_xgb_off")
    else:
        try:
            from malapp.inference.xgboost import predict as predict_xgb

            xgb_result = predict_xgb(normalized)
            if xgb_result is None:
                pipeline.skip("XGB_INFERENCE", "xgboost_unavailable_or_disabled")
            else:
                pipeline.complete(
                    "XGB_INFERENCE",
                    {"verdict": xgb_result.get("verdict"), "evaluation_mode": xgb_mode},
                    output_data=xgb_result,
                )
        except Exception as exc:
            pipeline.degrade("XGB_INFERENCE", ["xgboost_inference_failed"], {"error": str(exc)})
    if xgb_mode in {"agent_only", "full"} and valid_md5(normalized.get("md5")):
        evidence_blocks = apply_xgb_agent_scores(evidence_blocks, xgb_result)
    xgb_for_fusion = xgb_result if xgb_mode in {"fusion", "full"} else None
    evidence_blocks = add_evidence_conflict_markers(evidence_blocks)
    structured_evidence_layer = build_structured_evidence_layer(evidence_blocks)
    from malapp.agents.evidence_contract import build_evidence_envelope

    evidence_envelope = build_evidence_envelope(
        normalized["sample_id"], evidence_blocks, agent_results
    ).to_dict()

    debate_config = (
        dict(normalized.get("debate_model_config"))
        if isinstance(normalized.get("debate_model_config"), dict)
        else {}
    )
    # build_provider accepts only a non-production rule fixture from this
    # object; endpoints and credentials remain deployment-only configuration.
    debate_evidence: list[Any] = list(evidence_blocks)
    if xgb_for_fusion:
        debate_config["xgb_prior"] = xgb_for_fusion
    debate_config["rag_context"] = rag_context
    debate_config["sample_id"] = normalized["sample_id"]
    debate_config["run_id"] = run_id
    debate_config["canonical_evidence_envelope"] = evidence_envelope
    from malapp.inference.expert import explanation_layer

    llm_explanation = explanation_layer(agent_results, agent_runtime["expert_runtime"])
    if llm_explanation.get("agent_explanations"):
        debate_config["llm_agent_reviews"] = llm_explanation.get("agent_explanations")
    if local_qwen_enabled():
        debate_config.setdefault(
            "max_attack_rounds",
            int(os.getenv("MALAPP_QWEN_MAX_DEBATE_ROUNDS", "1")),
        )
        debate_config.setdefault("min_attack_rounds", 1)
    # Production keeps the full debate by default. Evaluation runs may request
    # the shorter XGBoost-guided verification path without changing production
    # behaviour or embedding experiment controls in model prompts.
    debate_mode = str(evaluation_config.get("debate_mode") or "full").strip().lower()
    debate_config["evaluation_mode"] = debate_mode
    debate_config["verification_mode"] = debate_mode in {
        "verification",
        "short",
        "initial_only",
    }

    pipeline.start(
        "DEBATE",
        {
            "evidence_snapshot_id": evidence_envelope.get("evidence_snapshot_id"),
            "evidence_ids": evidence_envelope.get("evidence_ids"),
        },
    )
    try:
        debate_result = debate(debate_evidence, debate_config)
        pipeline.complete(
            "DEBATE",
            {"execution_mode": debate_result.get("execution_mode", "full_debate")},
            output_data={
                "arbiter": debate_result.get("arbiter"),
                "model_calls": debate_result.get("model_calls", []),
            },
        )
    except Exception as exc:
        pipeline.fail("DEBATE", exc)
        raise

    pipeline.start(
        "FINAL_DECISION",
        {
            "arbiter": debate_result.get("arbiter"),
            "agent_scores": {block.agent: block.score for block in evidence_blocks},
            "xgb": xgb_result,
        },
    )
    try:
        decision = collaborative_decision(
            normalized,
            debate_result,
            evidence_blocks,
            normalized.get("decision_params") if isinstance(normalized.get("decision_params"), dict) else None,
            xgb_result=xgb_for_fusion,
            auto_predict_xgb=False,
        )
        decision = apply_degradation_policy(decision, degradation_policy)
        if degradation_policy["status"] == "degraded":
            pipeline.degrade(
                "FINAL_DECISION",
                [item["code"] for item in degradation_policy["reasons"]],
                {"verdict": decision["verdict"], "review_required": decision["review_required"]},
            )
        else:
            pipeline.complete(
                "FINAL_DECISION",
                {"verdict": decision["verdict"]},
                output_data=decision,
            )
    except Exception as exc:
        pipeline.fail("FINAL_DECISION", exc)
        raise

    from malapp.governance.runtime import save_runtime_snapshot
    from malapp.inference.settings import model_cache_signature

    pipeline.start(
        "PERSIST",
        {"sample_id": normalized["sample_id"], "runtime_snapshot_pending": True},
    )
    runtime_snapshot = save_runtime_snapshot(
        debate_result=debate_result,
        xgb_result=xgb_result,
        rag_context=rag_context,
        decision_params=decision.get("parameters"),
        data_dir=DATA_DIR,
        admission=admission.to_dict(),
        evidence_envelope=evidence_envelope,
        expert_runtime=agent_runtime.get("expert_runtime"),
        debate_conformance=debate_result.get("debate_conformance"),
        wec_policy=decision.get("wec"),
    )
    report = {
        "run_id": run_id,
        "report_id": hashlib.sha1(json.dumps(normalized, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()[:16],
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "created_at": utc_now(),
        "rag_snapshot_id": rag_context.get("rag_snapshot_id"),
        "runtime_snapshot": runtime_snapshot,
        "sample": normalized,
        "engine_c": {**admission.to_dict(), "executed": True, "score_c": decision["engine_scores"]["engine_c"]},
        "preprocess": {
            "unmapped_fields": unmapped,
            "iocs": iocs,
            "static_feature_package": static_package,
            "network_ioc_package": network_package,
            "apk_analysis": apk_analysis,
            "static_feedback": build_static_feedback(normalized, evidence_blocks),
            "threat_intelligence": threat_intelligence,
            "impersonation_analysis": impersonation_analysis,
            "business_label_analysis": business_label_analysis,
            "agent_output_validation": agent_output_validation,
            "agent_runtime": agent_runtime,
        },
        "evidence_blocks": [asdict(block) for block in evidence_blocks],
        "evidence_layers": {
            "raw_evidence": raw_evidence_layer,
            "structured_evidence_blocks": structured_evidence_layer,
            "canonical_evidence_envelope": evidence_envelope,
            "llm_explanation": llm_explanation,
            "rag_context": rag_context,
        },
        "debate": debate_result,
        "decision": decision,
        "degradation": degradation_policy,
        "next_steps": [
            "将当前规则占位智能体替换为真实 APK 解析、IOC 情报、品牌相似度和业务标签工具。",
            "将模型甲/模型乙适配到本地 vLLM、Ollama 或 OpenAI-compatible 模型接口。",
            "补充已标注样本，用于校准 WEC 阈值和动态权重。",
        ],
        "execution": {
            "run_id": run_id,
            "orchestrator": "agent_runtime",
            "orchestration_mode": orchestration_mode(),
            "tool_runtime_enabled": tool_runtime_enabled(),
            "entrypoint": entrypoint,
            "service_pipeline": "malapp.agent-runtime.v2",
            "history_reused": False,
            "model_cache_signature": model_cache_signature(),
            "rag_snapshot_id": rag_context.get("rag_snapshot_id"),
            "runtime_snapshot_id": runtime_snapshot["snapshot_id"],
            "evaluation_config": evaluation_config,
            "evaluation_variant": os.getenv("MALAPP_EVAL_VARIANT", "production"),
            "pipeline": pipeline.snapshot(),
        },
        "evaluation_metadata": evaluation_metadata,
    }
    try:
        insert_report(report)
        pipeline.complete(
            "PERSIST",
            {"report_id": report["report_id"]},
            output_data={"report_id": report["report_id"], "runtime_snapshot_id": runtime_snapshot["snapshot_id"]},
        )
        report["execution"]["pipeline"] = pipeline.snapshot()
    except Exception as exc:
        pipeline.fail("PERSIST", exc)
        raise
    attach_decision_provenance(report)
    persist_observability_metrics(report)
    try:
        from malapp.observability.trace import save_agent_trace

        trace = save_agent_trace(report)
        report.setdefault("execution", {})["agent_trace_id"] = trace.get("trace_id")
    except Exception as exc:
        report.setdefault("execution", {})["agent_trace_error"] = str(exc)
    try:
        from malapp.observability.rewards import save_reward_for_report

        reward_record = save_reward_for_report(report)
        report.setdefault("execution", {})["reward"] = reward_record
    except Exception as exc:
        report.setdefault("execution", {})["reward_error"] = str(exc)
    insert_report(report)
    set_cached_report(cache_sample, report)
    return report


def judge(raw_sample: dict[str, Any]) -> dict[str, Any]:
    """Convenience wrapper that still enters the authoritative service."""
    from malapp.application.contracts import JudgementRequest
    from malapp.application.service import get_judgement_service

    request = JudgementRequest.from_payload(raw_sample, source="internal")
    return get_judgement_service().judge(request)
