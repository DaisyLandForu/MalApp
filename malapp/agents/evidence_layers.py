from __future__ import annotations

import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from typing import Any

from malapp.agents.skill_context import build_agent_skill_context
from malapp.inference.local_qwen import parse_model_json
from malapp.orchestration.debate import build_provider, compact_rag_context, compact_text

AGENT_ORDER = ["static_analysis", "threat_intel", "impersonation", "business_label"]


def build_raw_evidence_layer(
    sample: dict[str, Any],
    *,
    iocs: list[dict[str, Any]],
    static_feature_package: dict[str, Any],
    network_ioc_package: dict[str, Any],
    threat_intelligence: dict[str, Any],
    impersonation_analysis: dict[str, Any],
    business_label_analysis: dict[str, Any],
    apk_analysis: dict[str, Any],
) -> dict[str, Any]:
    """Collect immutable tool/raw feature outputs before EvidenceBlock scoring."""
    return {
        "sample_keys": {
            "sample_id": sample.get("sample_id"),
            "md5": sample.get("md5"),
            "sha1": sample.get("sha1"),
            "sha256": sample.get("sha256"),
            "app_name": sample.get("app_name"),
            "package_name": sample.get("package_name"),
        },
        "static": {
            "signature_status": sample.get("signature_status"),
            "certificate_fingerprint": sample.get("certificate_fingerprint"),
            "packer": sample.get("packer"),
            "permissions": sample.get("permissions") or [],
            "sdk_list": sample.get("sdk_list") or [],
            "apk_analysis": apk_analysis,
            "feature_package": static_feature_package,
        },
        "network": {
            "control_url": sample.get("control_url"),
            "download_url": sample.get("download_url"),
            "control_mailbox": sample.get("control_mailbox"),
            "control_phone": sample.get("control_phone"),
            "domains": sample.get("domains") or [],
            "ips": sample.get("ips") or [],
            "iocs": iocs,
            "feature_package": network_ioc_package,
        },
        "threat_intel": threat_intelligence,
        "impersonation": {
            "fake_app": sample.get("fake_app"),
            "official_app_name": sample.get("official_app_name"),
            "official_pkg": sample.get("official_pkg"),
            "official_md5": sample.get("official_md5"),
            "brand_similarity": sample.get("brand_similarity"),
            "analysis": impersonation_analysis,
        },
        "business": {
            "fraud_category_big": sample.get("fraud_category_big"),
            "fraud_category_small": sample.get("fraud_category_small"),
            "harm_type": sample.get("harm_type"),
            "fraud_family": sample.get("fraud_family"),
            "risk_score": sample.get("risk_score"),
            "version_status": sample.get("version_status"),
            "analysis": business_label_analysis,
        },
    }


def build_structured_evidence_layer(evidence_blocks: list[Any]) -> list[dict[str, Any]]:
    """Return stable program-generated EvidenceBlocks."""
    return [
        asdict(block) if hasattr(block, "__dataclass_fields__") else dict(block)
        for block in evidence_blocks
    ]


def build_llm_explanation_layer(
    evidence_blocks: list[Any],
    config: dict[str, Any] | None = None,
    raw_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call model A once per agent and ask it to review only raw feature packets."""
    config = config or {}
    provider = build_provider("model_a", config)
    if provider.backend == "rule":
        return {
            "status": "model_unavailable",
            "provider": provider.public_config(),
            "message": "未配置可用的大模型，未生成四个智能体的大模型独立判断。",
            "agent_explanations": [],
            "overall_summary": "",
        }

    raw_contexts = _raw_contexts_for_agents(raw_evidence or {})
    rag_context = compact_rag_context(config.get("rag_context"), item_limit=4, content_limit=180)
    for context in raw_contexts:
        context["rag_context"] = rag_context
        context["skill_context"] = build_agent_skill_context(str(context.get("agent") or ""), "agent_review")
    started = time.perf_counter()
    explanations: list[dict[str, Any]] = []
    failures: list[str] = []
    metrics = {"prompt_tokens": 0, "completion_tokens": 0, "latency_ms": 0}

    max_workers = max(1, min(int(os.getenv("MALAPP_AGENT_REVIEW_WORKERS", "4") or "4"), len(raw_contexts) or 1))
    if max_workers == 1:
        for context in raw_contexts:
            agent = str(context.get("agent") or "")
            try:
                item, generated = _call_single_agent_review(provider, context)
                metrics["prompt_tokens"] += int(generated.get("prompt_tokens", 0) or 0)
                metrics["completion_tokens"] += int(generated.get("completion_tokens", 0) or 0)
                metrics["latency_ms"] += int(generated.get("latency_ms", 0) or 0)
                explanations.append(item)
            except Exception as exc:
                failures.append(f"{agent}: {exc}")
    else:
        by_agent: dict[str, dict[str, Any]] = {}
        with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="agent-review") as executor:
            futures = {
                executor.submit(_call_single_agent_review, provider, context): str(context.get("agent") or "")
                for context in raw_contexts
            }
            for future in as_completed(futures):
                agent = futures[future]
                try:
                    item, generated = future.result()
                    metrics["prompt_tokens"] += int(generated.get("prompt_tokens", 0) or 0)
                    metrics["completion_tokens"] += int(generated.get("completion_tokens", 0) or 0)
                    metrics["latency_ms"] += int(generated.get("latency_ms", 0) or 0)
                    by_agent[str(item.get("agent") or agent)] = item
                except Exception as exc:
                    failures.append(f"{agent}: {exc}")
        explanations = [
            by_agent[agent]
            for agent in AGENT_ORDER
            if agent in by_agent
        ]

    explanations = _attach_rule_alignment(explanations, evidence_blocks)
    status = "model_generated" if len(explanations) == len(raw_contexts) else (
        "model_partial" if explanations else "model_failed"
    )
    return {
        "status": status,
        "provider": provider.public_config(),
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "parallel_workers": max_workers,
        "token_usage": {
            "prompt_tokens": metrics["prompt_tokens"],
            "completion_tokens": metrics["completion_tokens"],
        },
        "message": "；".join(failures),
        "agent_explanations": explanations,
        "overall_summary": _overall_summary_from_explanations(explanations),
    }


def _call_single_agent_review(provider: Any, context: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    agent = str(context.get("agent") or "")
    system_prompt, user_prompt = _build_single_agent_review_prompt(context)
    generated = provider.generate(system_prompt, user_prompt, max_tokens=900)
    parsed = _parse_single_agent_review_json(generated.get("raw_text", ""), agent)
    if not parsed:
        repair = provider.generate(
            "你是 JSON 修复器。只输出一个合法 JSON 对象，不要解释，不要 Markdown。",
            _build_single_agent_repair_prompt(agent, generated.get("raw_text", ""), context),
            max_tokens=750,
        )
        generated = _merge_generation_metrics(generated, repair)
        parsed = _parse_single_agent_review_json(repair.get("raw_text", ""), agent)
    if not parsed:
        parsed = _recover_single_agent_review_from_raw(agent, generated.get("raw_text", ""))
    if not parsed:
        raise ValueError("模型未返回可解析的智能体独立判断")
    return parsed, generated


def _build_single_agent_review_prompt(context: dict[str, Any]) -> tuple[str, str]:
    agent = str(context.get("agent") or "")
    role = _agent_role_prompt(agent)
    rag_context = context.get("rag_context") if isinstance(context.get("rag_context"), dict) else {}
    skill_context = context.get("skill_context") if isinstance(context.get("skill_context"), dict) else {}
    raw_features = dict(context)
    raw_features.pop("rag_context", None)
    raw_features.pop("skill_context", None)
    schema = {
        "agent": agent,
        "review_verdict": "恶意/可疑/良性",
        "review_reason": "只基于原始特征的独立判断",
        "trust_assessment": "字段充分/字段不足/存在冲突",
        "causal_reasoning": "字段组合如何支撑判断",
        "feature_links": ["字段A与字段B之间的交叉印证或矛盾"],
        "summary": "一句话总结该智能体独立判断",
        "evidence_chain": ["原始字段 -> 特征关系 -> 领域结论"],
        "contradictions": ["原始字段内部矛盾或证据缺口"],
        "missing_impact": "缺失字段对判断的影响",
    }
    system_prompt = (
        f"你是{role['name']}。{role['task']}"
        "你只能根据本次输入的 AgentRawFeatures 独立判断。"
        "禁止参考 XGBoost、机器学习概率、规则分数、融合分数、EvidenceBlock 或其他智能体结论。"
        "必须使用中文，只输出一个合法 JSON 对象，不要 Markdown，不要思考过程，不要反问。"
        "输出时要把英文特征名、业务标签和枚举值尽量翻译成中文，必要时用括号保留原字段名。"
        "引用字段时必须使用中文引号，例如“上游风险分数”“技术场景标签”；"
        "不要直接输出 source_、technical_scene_translation、analysis.、assessment. 等英文或路径式字段名。"
        "中文句子使用中文逗号、句号，不要在中文逗号后添加多余空格。"
    )
    user_prompt = (
        f"智能体名称：{agent}\n"
        f"核心职责：{role['task']}\n"
        f"重点字段：{role['fields']}\n\n"
        "请输出该智能体的大模型独立判断。要求：\n"
        "1. review_verdict 只能写 恶意、可疑 或 良性。\n"
        "2. review_reason 要说明根据哪些原始字段得出结论。\n"
        "3. causal_reasoning 要写字段组合之间的逻辑，不要复读字段。\n"
        "4. evidence_chain 至少两条，必须引用输入中的具体字段或值。\n"
        "5. contradictions 写证据不足、字段缺失或内部矛盾；没有明确矛盾也要说明缺口。\n"
        "6. 字段名和标签必须尽量中文化，例如 control_url 写成“控制端地址”，fraud_family 写成“涉诈家族”。\n"
        "7. 引用具体字段时统一写成“中文字段名”，不要直接输出下划线字段名、source_ 前缀或 analysis.xxx 路径。\n"
        "8. 中文标点要规范：逗号后不要多余空格，字段和值之间用“为”。\n"
        "9. 不要出现 question、answer、think、xgboost、规则分数、机器学习概率。\n\n"
        f"JSON schema 示例：{json.dumps(schema, ensure_ascii=False, separators=(',', ':'))}\n"
        "RAGContext 使用要求：只作为相似案例、黑产家族、正版资产和研判规范参考；"
        "不得把 RAG 中的事实当成当前样本命中事实。\n"
        "SkillContext 使用要求：这是当前智能体的职责、字段边界和输出重点，只用于约束解释范围。\n"
        f"SkillContext={json.dumps(skill_context, ensure_ascii=False, separators=(',', ':'))}\n"
        f"RAGContext={json.dumps(rag_context, ensure_ascii=False, separators=(',', ':'))}\n"
        f"AgentRawFeatures={json.dumps(raw_features, ensure_ascii=False, separators=(',', ':'))}"
    )
    return system_prompt, user_prompt


def _build_single_agent_repair_prompt(agent: str, raw_text: str, context: dict[str, Any]) -> str:
    schema = {
        "agent": agent,
        "review_verdict": "恶意/可疑/良性",
        "review_reason": "",
        "trust_assessment": "",
        "causal_reasoning": "",
        "feature_links": [],
        "summary": "",
        "evidence_chain": [],
        "contradictions": [],
        "missing_impact": "",
    }
    return (
        "请把下面的模型输出修复成合法 JSON。不要解释，不要 Markdown。\n"
        f"必须使用这个 schema：{json.dumps(schema, ensure_ascii=False, separators=(',', ':'))}\n"
        f"agent 必须等于 {agent}。review_verdict 只能是 恶意、可疑、良性。\n"
        "如果原文缺字段，请根据 AgentRawFeatures 补齐，但不要编造不存在的事实。\n\n"
        f"模型原文：{compact_text(raw_text, 2500)}\n"
        f"AgentRawFeatures={json.dumps(context, ensure_ascii=False, separators=(',', ':'))}"
    )


def _agent_role_prompt(agent: str) -> dict[str, str]:
    roles = {
        "static_analysis": {
            "name": "静态分析智能体",
            "task": "验证签名一致性，识别加固、二次打包、混淆、权限与 SDK 风险。",
            "fields": "md5、sha1、sha256、app_name、package_name、signature_status、certificate_fingerprint、packer、permissions、sdk_list、apk_analysis",
        },
        "threat_intel": {
            "name": "情报溯源智能体",
            "task": "挖掘控制端、下载地址、邮箱、手机号、域名、IP、IOC 与黑产家族关联。",
            "fields": "control_url、download_url、control_mailbox、control_phone、domains、ips、iocs、threat_intel、fraud_family",
        },
        "impersonation": {
            "name": "仿冒研判智能体",
            "task": "对比正版应用名称、包名、MD5、品牌相似度和 fake_app 字段，判断仿冒风险。",
            "fields": "fake_app、official_app_name、official_pkg、official_md5、brand_similarity、impersonation_analysis",
        },
        "business_label": {
            "name": "业务打标智能体",
            "task": "把技术特征翻译成反诈业务标签，判断涉诈分类、危害类型、家族与版本状态。",
            "fields": "fraud_category_big、fraud_category_small、harm_type、fraud_family、risk_score、version_status",
        },
    }
    return roles.get(
        agent,
        {
            "name": agent or "领域智能体",
            "task": "根据本领域原始特征完成独立判断。",
            "fields": "AgentRawFeatures",
        },
    )


def _parse_single_agent_review_json(raw_text: str, agent: str) -> dict[str, Any]:
    cleaned = _clean_model_text(raw_text)
    data = parse_model_json(cleaned)
    if isinstance(data, dict):
        if isinstance(data.get("agent_explanations"), list):
            for item in data["agent_explanations"]:
                if isinstance(item, dict) and str(item.get("agent") or "").strip() == agent:
                    normalized = _normalize_explanations([item])
                    return normalized[0] if normalized else {}
        if str(data.get("agent") or "").strip() in {"", agent}:
            data["agent"] = agent
            normalized = _normalize_explanations([data])
            return normalized[0] if normalized else {}
    return {}


def _parse_agent_review_json(raw_text: str) -> dict[str, Any]:
    cleaned = _clean_model_text(raw_text)
    data = parse_model_json(cleaned)
    if isinstance(data, dict) and "agent_explanations" in data:
        return data
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        value = None
    if isinstance(value, list):
        return {"agent_explanations": value, "overall_summary": ""}
    return data if isinstance(data, dict) else {}


def _clean_model_text(text: Any) -> str:
    value = str(text or "")
    value = re.sub(r"<think>[\s\S]*?</think>", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"</?think>", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"(?im)^\s*(question|answer|analysis|final)\s*[:：]\s*", "", value)
    value = value.replace("```json", "```")
    return value.strip()


def _merge_generation_metrics(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    return {
        "raw_text": second.get("raw_text", ""),
        "latency_ms": int(first.get("latency_ms", 0) or 0) + int(second.get("latency_ms", 0) or 0),
        "prompt_tokens": int(first.get("prompt_tokens", 0) or 0) + int(second.get("prompt_tokens", 0) or 0),
        "completion_tokens": int(first.get("completion_tokens", 0) or 0) + int(second.get("completion_tokens", 0) or 0),
    }


def _normalize_explanations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        agent = str(item.get("agent") or "").strip()
        if agent not in set(AGENT_ORDER):
            continue
        result.append(
            {
                "agent": agent,
                "review_verdict": _clean_display_text(item.get("review_verdict"), 20),
                "review_reason": _clean_display_text(item.get("review_reason"), 360),
                "rule_alignment": _clean_display_text(item.get("rule_alignment"), 20),
                "rule_difference": _clean_display_text(item.get("rule_difference"), 320),
                "trust_assessment": _clean_display_text(item.get("trust_assessment"), 100),
                "conflict_resolution": _clean_display_text(item.get("conflict_resolution"), 360),
                "causal_reasoning": _clean_display_text(item.get("causal_reasoning"), 520),
                "feature_links": _clean_text_list(item.get("feature_links"), 260, 4),
                "summary": _clean_display_text(item.get("summary"), 300),
                "evidence_chain": _clean_text_list(item.get("evidence_chain"), 300, 5),
                "contradictions": _clean_text_list(item.get("contradictions"), 260, 4),
                "missing_impact": _clean_display_text(item.get("missing_impact"), 300),
            }
        )
    return result


def _clean_text_list(value: Any, length: int, limit: int) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    result = []
    for entry in value:
        text = _clean_display_text(entry, length)
        if text:
            result.append(text)
    return result[:limit]


def _clean_display_text(value: Any, limit: int) -> str:
    text = compact_text(value, limit)
    text = re.sub(r"<\/?think>", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(question|answer|analysis|final)\s*[:：]\s*", "", text, flags=re.IGNORECASE)
    text = _translate_terms_for_display(text)
    text = text.replace("；；", "；").replace("。。", "。").replace("，，", "，")
    text = text.replace("。 。", "。").replace("， ，", "，").replace("； ；", "；")
    text = re.sub(r"\s+", " ", text).strip()
    return text.strip(" ；，。")


def _translate_terms_for_display(text: str) -> str:
    replacements = {
        "technical_scene_translation": "技术场景翻译",
        "business_harm_labels": "业务危害标签",
        "matched_rules": "命中规则",
        "harm_chain": "危害链",
        "stages": "阶段",
        "labels": "标签",
        "source": "来源",
        "assessment": "评估结果",
        "claim": "结论",
        "visual_similarity": "视觉相似度",
        "sample_icon_available": "样本图标可用性",
        "official_asset_match": "正版资产匹配",
        "asset_count": "资产数量",
        "fake_app": "仿冒应用标记",
        "control_url": "控制端地址",
        "download_url": "下载地址",
        "control_mailbox": "控制邮箱",
        "control_phone": "控制手机号",
        "domains": "域名",
        "ips": "IP 地址",
        "threat_intel_records": "威胁情报记录",
        "fraud_family": "涉诈家族",
        "fraud_category_big": "涉诈大类",
        "fraud_category_small": "涉诈小类",
        "harm_type": "危害类型",
        "risk_score": "上游风险分数",
        "signature_status": "签名状态",
        "certificate_fingerprint": "证书指纹",
        "packer": "加固/混淆",
        "permissions": "权限列表",
        "sdk_list": "SDK 清单",
        "official_app_name": "正版应用名称",
        "official_pkg": "正版包名",
        "official_md5": "正版 MD5",
        "brand_similarity": "品牌相似度",
        "impersonation_probability": "仿冒概率",
        "supports_malicious": "支持恶意判断",
        "supports_benign": "支持良性判断",
        "insufficient": "证据不足",
        "False": "否",
        "True": "是",
    }
    for key, label in replacements.items():
        text = text.replace(key, label)
    return text


def _recover_single_agent_review_from_raw(agent: str, raw_text: str) -> dict[str, Any]:
    text = _clean_display_text(raw_text, 900)
    if not text:
        return {}
    verdict = "可疑"
    if re.search(r"恶意|高风险|malicious", text, re.IGNORECASE):
        verdict = "恶意"
    elif re.search(r"良性|低风险|benign", text, re.IGNORECASE):
        verdict = "良性"
    elif re.search(r"可疑|中风险|suspicious", text, re.IGNORECASE):
        verdict = "可疑"
    sentences = [s.strip(" ，。；;") for s in re.split(r"[。；;\n]+", text) if s.strip()]
    reason = "。".join(sentences[:2]) or text
    return {
        "agent": agent,
        "review_verdict": verdict,
        "review_reason": compact_text(reason, 320),
        "trust_assessment": "模型返回了自然语言判断，程序已从文本中恢复展示字段。",
        "causal_reasoning": compact_text(reason, 420),
        "feature_links": [],
        "summary": compact_text(reason, 260),
        "evidence_chain": [compact_text(s, 220) for s in sentences[:3]] or [compact_text(text, 220)],
        "contradictions": ["模型未按协议返回完整 JSON，结构化字段由程序从模型原文中恢复。"],
        "missing_impact": "由于模型输出格式不完整，证据链细节可能不如标准 JSON 完整。",
    }


def _attach_rule_alignment(
    explanations: list[dict[str, Any]],
    evidence_blocks: list[Any],
) -> list[dict[str, Any]]:
    structured = build_structured_evidence_layer(evidence_blocks)
    by_agent = {str(block.get("agent") or ""): block for block in structured}
    for item in explanations:
        block = by_agent.get(str(item.get("agent") or ""))
        if not block:
            item["rule_alignment"] = ""
            item["rule_difference"] = ""
            item["conflict_resolution"] = ""
            continue
        model_verdict = _canonical_verdict(item.get("review_verdict"))
        rule_score = _safe_float(block.get("score"))
        rule_verdict = _rule_verdict_from_score(rule_score)
        item["rule_verdict"] = _zh_verdict(rule_verdict)
        item["rule_score"] = round(rule_score, 4)
        if not model_verdict:
            item["rule_alignment"] = "部分一致"
            item["rule_difference"] = "大模型未给出可解析的恶意、可疑或良性结论，需要模型甲乙继续复核。"
            item["conflict_resolution"] = "后续辩论应重点检查该领域原始特征是否缺失、字段含义是否不清或样本信息是否不足。"
        elif model_verdict != rule_verdict:
            item["rule_alignment"] = "冲突"
            item["rule_difference"] = (
                f"大模型仅根据该领域原始特征判断为{_zh_verdict(model_verdict)}，"
                f"规则/工具判断为{_zh_verdict(rule_verdict)}。"
            )
            item["conflict_resolution"] = (
                "差异可能来自字段缺失、原始特征与机器学习先验权重不一致，"
                "后续模型甲乙需要结合四个智能体的独立判断和规则证据重新取舍。"
            )
        else:
            item["rule_alignment"] = "一致"
            item["rule_difference"] = ""
            item["conflict_resolution"] = ""
    return explanations


def _overall_summary_from_explanations(explanations: list[dict[str, Any]]) -> str:
    if not explanations:
        return ""
    parts = []
    for item in explanations:
        role = _agent_role_prompt(str(item.get("agent") or "")).get("name", item.get("agent", ""))
        verdict = item.get("review_verdict") or "未定"
        summary = item.get("summary") or item.get("review_reason") or ""
        parts.append(f"{role}判断为{verdict}：{compact_text(summary, 80)}")
    return "；".join(parts)


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _rule_verdict_from_score(score: float) -> str:
    if score >= 0.85:
        return "malicious"
    if score >= 0.6:
        return "suspicious"
    return "benign"


def _canonical_verdict(value: Any) -> str:
    text = str(value or "").strip().lower()
    if "恶意" in text or "malicious" in text:
        return "malicious"
    if "可疑" in text or "suspicious" in text:
        return "suspicious"
    if "良性" in text or "benign" in text:
        return "benign"
    return ""


def _zh_verdict(value: str) -> str:
    return {
        "malicious": "恶意",
        "suspicious": "可疑",
        "benign": "良性",
    }.get(value, value or "未知")


def _select_explanation_items(items: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    conflicts: list[dict[str, Any]] = []
    concrete: list[dict[str, Any]] = []
    ml_priors: list[dict[str, Any]] = []
    for item in items:
        evidence_type = str(item.get("evidence_type") or "")
        source_fields = {str(field) for field in item.get("source_fields", [])}
        if evidence_type == "evidence_conflict":
            conflicts.append(item)
        elif evidence_type == "xgboost_domain_probability" or "xgb_agent_scores" in source_fields:
            ml_priors.append(item)
        else:
            concrete.append(item)
    conflicts = sorted(conflicts, key=lambda item: float(item.get("strength") or 0), reverse=True)
    concrete = sorted(concrete, key=lambda item: float(item.get("strength") or 0), reverse=True)
    ml_priors = sorted(ml_priors, key=lambda item: float(item.get("strength") or 0), reverse=True)
    selected = conflicts[:limit]
    selected.extend(concrete[: max(0, limit - len(selected))])
    if len(selected) < limit and ml_priors:
        selected.append(ml_priors[0])
    return selected[:limit]


def _raw_contexts_for_agents(raw_evidence: dict[str, Any]) -> list[dict[str, Any]]:
    """Build per-agent raw feature packets so the model has its own input."""
    if not isinstance(raw_evidence, dict):
        raw_evidence = {}
    sample_keys = raw_evidence.get("sample_keys") if isinstance(raw_evidence.get("sample_keys"), dict) else {}
    mapping = {
        "static_analysis": raw_evidence.get("static", {}),
        "threat_intel": {
            "network": raw_evidence.get("network", {}),
            "threat_intel": raw_evidence.get("threat_intel", {}),
        },
        "impersonation": raw_evidence.get("impersonation", {}),
        "business_label": raw_evidence.get("business", {}),
    }
    result: list[dict[str, Any]] = []
    for agent in AGENT_ORDER:
        payload = mapping.get(agent, {})
        result.append(
            {
                "agent": agent,
                "sample_keys": _compact_raw_value(sample_keys, 8),
                "raw_features": _compact_raw_value(payload, 28),
            }
        )
    return result


def _compact_raw_value(value: Any, limit: int) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in list(value.items())[:limit]:
            if item in ("", None, [], {}):
                continue
            out[str(key)] = _compact_raw_value(item, max(4, limit // 2))
        return out
    if isinstance(value, list):
        return [_compact_raw_value(item, 6) for item in value[:limit]]
    return compact_text(value, 180)
