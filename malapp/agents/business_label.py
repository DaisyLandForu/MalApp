from __future__ import annotations

import re
from datetime import datetime
from typing import Any

TECH_SCENE_RULES = [
    {
        "label": "金融诈骗-虚假贷款类",
        "risk": 0.86,
        "terms": ("loan", "credit", "borrow", "贷款", "借款", "额度", "放款", "ssl证书自签", "自签", "fake loan"),
        "technical_points": ("self_signed_certificate", "fake_loan_site", "loan_keyword"),
    },
    {
        "label": "金融诈骗-虚假钱包/支付类",
        "risk": 0.82,
        "terms": ("wallet", "pay", "bank", "crypto", "钱包", "支付", "银行", "币", "secure wallet"),
        "technical_points": ("wallet_keyword", "payment_keyword", "brand_impersonation"),
    },
    {
        "label": "钓鱼仿冒-账号窃取类",
        "risk": 0.78,
        "terms": ("phish", "login", "account", "verify", "钓鱼", "登录", "账号", "验证码"),
        "technical_points": ("phishing_keyword", "credential_collection"),
    },
    {
        "label": "隐私窃取-短信通讯录类",
        "risk": 0.74,
        "terms": ("read_sms", "send_sms", "contacts", "phone_state", "短信", "通讯录"),
        "technical_points": ("sms_permission", "contacts_permission", "device_identifier_collection"),
    },
    {
        "label": "远控木马-C2回传类",
        "risk": 0.84,
        "terms": ("c2", "bot", "trojan", "command", "control_url", "回传", "远控", "木马"),
        "technical_points": ("c2_indicator", "remote_control"),
    },
]

CHAIN_STAGES = [
    {
        "stage": "诱导安装",
        "tags": ("仿冒品牌", "虚假贷款", "应用名敏感词", "外联虚假贷款网站"),
        "terms": ("loan", "wallet", "bank", "pay", "fake_app", "phish", "download_url"),
    },
    {
        "stage": "获取权限",
        "tags": ("敏感权限申请", "短信/通讯录/悬浮窗权限"),
        "terms": ("read_sms", "send_sms", "contacts", "system_alert_window", "accessibility", "read_phone_state"),
    },
    {
        "stage": "窃取信息",
        "tags": ("设备标识采集", "短信/联系人采集", "账号凭据采集"),
        "terms": ("phone_state", "contacts", "sms", "credential", "login", "账号", "验证码"),
    },
    {
        "stage": "回传C2",
        "tags": ("C2通信", "域名/IP外联", "情报黑库命中"),
        "terms": ("c2", "control_url", "callback", "botnet", "malicious", "blacklist"),
    },
]


def analyze_business_label(sample: dict[str, Any]) -> dict[str, Any]:
    return compose_business_analysis(
        translate_technical_features(sample),
        build_harm_chain(sample),
        determine_variant(sample),
        missing_fields(sample),
    )


def compose_business_analysis(
    scene: dict[str, Any],
    chain: dict[str, Any],
    variant: dict[str, Any],
    missing: list[str] | None = None,
) -> dict[str, Any]:
    score = max(float(scene.get("risk_score") or 0), float(chain.get("risk_score") or 0), float(variant.get("risk_score") or 0))
    evidence = []
    labels = list(scene.get("labels") or [])
    if labels:
        evidence.append(f"技术特征映射到业务场景：{', '.join(labels)}。")
    stages = list(chain.get("stages") or [])
    if stages:
        evidence.append("恶意行为危害动链：" + " -> ".join(stage["stage"] for stage in stages) + "。")
    variant_label = str(variant.get("variant_label") or "unknown")
    if variant_label != "unknown":
        variant_name = {
            "high_confidence_variant": "高可信变种",
            "possible_variant": "疑似变种",
            "unknown": "暂未确认变种",
        }.get(variant_label, "暂未确认变种")
        evidence.append(f"变种判定：{variant_name}，依据 {', '.join(variant.get('evidence') or [])}。")
    if not evidence:
        evidence.append("当前样本未能映射到明确业务场景。")
    return {
        "technical_scene_translation": scene,
        "harm_chain": chain,
        "variant_assessment": variant,
        "summary": {
            "risk_score": round(score, 4),
            "business_labels": sorted(set(labels + list(chain.get("business_harm_labels") or []) + list(variant.get("labels") or []))),
            "claim": label_claim(score),
            "evidence": evidence,
            "confidence": confidence(scene, chain, variant),
        },
        "evidence_block": {
            "agent": "business_label",
            "claim": label_claim(score),
            "evidence": evidence,
            "confidence": confidence(scene, chain, variant),
            "score": round(score, 4),
            "missing_fields": list(missing or []),
        },
    }


def translate_technical_features(sample: dict[str, Any]) -> dict[str, Any]:
    haystack = sample_text(sample)
    labels = []
    matched_rules = []
    risk = 0.15
    for rule in TECH_SCENE_RULES:
        matched_terms = [term for term in rule["terms"] if term.lower() in haystack]
        if matched_terms:
            labels.append(rule["label"])
            risk = max(risk, rule["risk"])
            matched_rules.append(
                {
                    "business_label": rule["label"],
                    "technical_points": list(rule["technical_points"]),
                    "matched_terms": matched_terms,
                    "risk": rule["risk"],
                }
            )
    cert_status = str(sample.get("certificate_status") or sample.get("ssl_certificate") or "").lower()
    if "self" in cert_status or "自签" in cert_status:
        labels.append("金融诈骗-虚假贷款类")
        matched_rules.append(
            {
                "business_label": "金融诈骗-虚假贷款类",
                "technical_points": ["self_signed_certificate"],
                "matched_terms": [cert_status],
                "risk": 0.86,
            }
        )
        risk = max(risk, 0.86)
    return {"labels": sorted(set(labels)), "matched_rules": matched_rules, "risk_score": round(risk, 4)}


def build_harm_chain(sample: dict[str, Any]) -> dict[str, Any]:
    haystack = sample_text(sample)
    stages = []
    for stage in CHAIN_STAGES:
        matched = [term for term in stage["terms"] if term.lower() in haystack]
        if matched:
            stages.append({"stage": stage["stage"], "labels": list(stage["tags"]), "matched_terms": matched})
    risk = min(1.0, 0.2 + 0.18 * len(stages))
    if len(stages) >= 3:
        risk = max(risk, 0.78)
    return {
        "stages": stages,
        "business_harm_labels": sorted({tag for stage in stages for tag in stage["labels"]}),
        "risk_score": round(risk, 4),
        "complete_chain": len(stages) >= 4,
    }


def determine_variant(sample: dict[str, Any]) -> dict[str, Any]:
    version_name = str(sample.get("version_name") or sample.get("app_version") or "").strip()
    package_name = str(sample.get("package_name") or "").strip()
    cert_to = str(sample.get("certificate_valid_to") or sample.get("cert_valid_to") or "").strip()
    update_events = normalize_updates(sample.get("version_history") or sample.get("release_history") or sample.get("observed_versions"))
    evidence = []
    risk = 0.1
    labels = []
    if version_name and re.search(r"(beta|test|debug|v?\d+\.\d+\.\d+\.\d+|patch|hotfix)", version_name, re.I):
        evidence.append("版本号命名呈现测试/补丁/多段变种特征")
        labels.append("版本命名异常")
        risk = max(risk, 0.45)
    if package_name and re.search(r"(\.update|\.patch|\.clone|\.wallet\d+|\.v\d+)$", package_name, re.I):
        evidence.append("包名包含 update/patch/clone/数字尾缀等变种模式")
        labels.append("包名变种")
        risk = max(risk, 0.5)
    if cert_to and is_expired_or_short_cert(cert_to):
        evidence.append("证书有效期异常或已过期")
        labels.append("证书有效期异常")
        risk = max(risk, 0.55)
    if len(update_events) >= 3:
        evidence.append("观察到高频版本更新")
        labels.append("高频更新变种")
        risk = max(risk, 0.62)
    if not evidence:
        evidence.append("未发现明确变种模式")
    variant_label = "high_confidence_variant" if risk >= 0.62 else "possible_variant" if risk >= 0.45 else "unknown"
    return {
        "variant_label": variant_label,
        "risk_score": round(risk, 4),
        "labels": labels,
        "evidence": evidence,
        "version_name": version_name,
        "update_event_count": len(update_events),
    }


def normalize_updates(value: Any) -> list[Any]:
    if isinstance(value, list):
        return [item for item in value if item]
    if isinstance(value, str) and value.strip():
        return [item for item in re.split(r"[,;，；\n\r]+", value) if item.strip()]
    return []


def is_expired_or_short_cert(value: str) -> bool:
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(value[:19], fmt)
            return dt.year < 2026
        except ValueError:
            continue
    return any(term in value.lower() for term in ("expired", "short", "invalid", "过期"))


def sample_text(sample: dict[str, Any]) -> str:
    fields = (
        "app_name",
        "package_name",
        "virus_name",
        "fraud_family",
        "fraud_type_info",
        "fraud_name",
        "fraud_category",
        "fraud_category_big",
        "fraud_category_small",
        "permissions",
        "api_calls",
        "control_url",
        "download_url",
        "control_mailbox",
        "control_phone",
        "risk_type",
        "virus_description",
    )
    return " ".join(str(sample.get(field) or "") for field in fields).lower()


def label_claim(score: float) -> str:
    if score >= 0.75:
        return "业务危害风险较高。"
    if score >= 0.45:
        return "业务危害风险中等。"
    return "业务危害风险较低。"


def confidence(scene: dict[str, Any], chain: dict[str, Any], variant: dict[str, Any]) -> float:
    value = 0.35
    value += min(0.25, len(scene["matched_rules"]) * 0.08)
    value += min(0.25, len(chain["stages"]) * 0.06)
    value += 0.1 if variant["variant_label"] != "unknown" else 0
    return round(min(0.98, value), 4)


def missing_fields(sample: dict[str, Any]) -> list[str]:
    missing = []
    if not any(sample.get(key) for key in ("virus_name", "fraud_family", "permissions", "control_url", "download_url")):
        missing.append("technical_features")
    if not any(sample.get(key) for key in ("version_name", "release_history", "observed_versions", "certificate_valid_to")):
        missing.append("variant_features")
    return missing
