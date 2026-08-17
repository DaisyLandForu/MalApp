from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SKILL_DIR = ROOT / "integrations" / "hermes" / "skills"

AGENT_SKILL_MAP = {
    "static_analysis": "malapp-static-analysis",
    "threat_intel": "malapp-threat-intel",
    "impersonation": "malapp-impersonation",
    "business_label": "malapp-business-label",
}

AGENT_SKILL_SUMMARIES: dict[str, dict[str, Any]] = {
    "static_analysis": {
        "skill": "malapp-static-analysis",
        "role": "静态分析智能体",
        "goal": "验证签名一致性、加固或二次打包、权限与 SDK 风险。",
        "inputs": ["MD5/SHA", "包名", "证书指纹", "签名状态", "加固/混淆", "权限", "SDK 清单"],
        "evidence_focus": ["签名异常", "加固或混淆", "高危权限", "SDK 风险"],
        "output_focus": "给出静态可信度、异常项和支撑判断的证据链。",
    },
    "threat_intel": {
        "skill": "malapp-threat-intel",
        "role": "情报溯源智能体",
        "goal": "挖掘 C2、域名、邮箱、手机号、IOC 与黑产家族关联。",
        "inputs": ["控制端地址", "下载地址", "邮箱", "手机号", "域名", "IP", "IOC", "家族标签"],
        "evidence_focus": ["C2/IOC 命中", "黑产家族", "域名/IP 关联", "社交信息关联"],
        "output_focus": "给出情报关联风险、命中来源和家族/团伙关系。",
    },
    "impersonation": {
        "skill": "malapp-impersonation",
        "role": "仿冒研判智能体",
        "goal": "对比正版 APP 资产，判断图标、包名、名称和语义编辑距离风险。",
        "inputs": ["fakeApp 标记", "正版应用名", "正版包名", "正版 MD5", "图标/品牌相似度"],
        "evidence_focus": ["仿冒标记", "正版资产匹配", "名称/包名相似", "图标相似"],
        "output_focus": "给出仿冒置信度、仿冒分类和缺失正版资产影响。",
    },
    "business_label": {
        "skill": "malapp-business-label",
        "role": "业务打标智能体",
        "goal": "把技术证据翻译成反诈业务侧可用标签和危害类型。",
        "inputs": ["涉诈大类", "涉诈小类", "危害类型", "涉诈家族", "上游风险分", "版本状态"],
        "evidence_focus": ["涉诈分类", "危害类型", "家族标签", "业务风险分"],
        "output_focus": "给出业务危害标签、涉诈分类细化和业务风险结论。",
    },
}

SUPERVISOR_SUMMARY = {
    "skill": "malapp-supervisor",
    "role": "研判主管",
    "goal": "把四个领域智能体的 EvidenceBlock 汇总给模型甲乙，并管理初判、质疑、反驳和终审。",
    "policy": [
        "先看结构化证据，再看大模型解释。",
        "发现字段缺失、证据冲突或模型概率与领域证据相反时，必须显式标注矛盾。",
        "最终结论要结合证据强度、字段覆盖率、模型置信度和辩论修正。",
    ],
}

STAGE_PROFILES: dict[str, dict[str, Any]] = {
    "agent_review": {
        "purpose": "领域智能体解释原始特征。",
        "disclosure": "只给当前智能体职责、输入字段和输出重点。",
        "must_do": ["说明字段之间的逻辑关系", "区分命中事实和缺失字段", "不要复制 XGBoost 结论"],
    },
    "initial": {
        "purpose": "模型甲乙独立初判。",
        "disclosure": "给主管原则、四智能体职责摘要和较完整 EvidenceBlock 摘要。",
        "must_do": ["给出独立恶意倾向分", "引用具体智能体证据", "标出证据矛盾或缺口"],
    },
    "directed_attack": {
        "purpose": "针对对方初判定向质疑。",
        "disclosure": "只给对方结论、关键论据、质疑点和高强度证据摘要。",
        "must_do": ["攻击对方真实说过的点", "指出证据不足或逻辑跳跃", "说明质疑成立后结论如何变化"],
    },
    "rebuttal": {
        "purpose": "回应对方质疑并修正己方判断。",
        "disclosure": "只给本方立场、对方质疑、Top 证据和必要缺失字段。",
        "must_do": ["承认或拒绝质疑", "补充一条证据", "说明剩余不确定性"],
    },
    "closing": {
        "purpose": "终审裁决。",
        "disclosure": "只给最终候选结论、辩论修正和关键证据。",
        "must_do": ["融合甲乙结论", "说明采信哪类证据", "输出简短终审 JSON"],
    },
}


def skill_context_enabled() -> bool:
    return os.getenv("MALAPP_SKILL_CONTEXT_ENABLED", "1").strip().lower() not in {"0", "false", "no", "off"}


def compact_text(value: Any, limit: int = 600) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    while "  " in text:
        text = text.replace("  ", " ")
    return text[:limit]


def _load_skill_markdown(skill_name: str, limit: int = 900) -> str:
    if os.getenv("MALAPP_SKILL_CONTEXT_INCLUDE_MARKDOWN", "0").strip().lower() not in {"1", "true", "yes", "on"}:
        return ""
    path = SKILL_DIR / skill_name / "SKILL.md"
    try:
        return compact_text(path.read_text(encoding="utf-8"), limit)
    except Exception:
        return ""


def build_agent_skill_context(agent: str, stage: str = "agent_review") -> dict[str, Any]:
    if not skill_context_enabled():
        return {"enabled": False}
    agent = str(agent or "")
    summary = dict(AGENT_SKILL_SUMMARIES.get(agent, {}))
    if not summary:
        return {"enabled": True, "stage": stage, "profile": STAGE_PROFILES.get(stage, {}), "agent": agent}
    markdown = _load_skill_markdown(str(summary.get("skill") or ""))
    return {
        "enabled": True,
        "stage": stage,
        "profile": STAGE_PROFILES.get(stage, STAGE_PROFILES["agent_review"]),
        "agent": agent,
        "summary": summary,
        "supervisor_hint": {
            "goal": SUPERVISOR_SUMMARY["goal"],
            "policy": SUPERVISOR_SUMMARY["policy"][:2],
        },
        "skill_markdown_excerpt": markdown,
    }


def build_debate_skill_context(
    stage: str,
    evidence: list[dict[str, Any]] | None = None,
    *,
    model_name: str | None = None,
) -> dict[str, Any]:
    if not skill_context_enabled():
        return {"enabled": False}
    stage = str(stage or "initial")
    agents = _agents_from_evidence(evidence)
    if stage in {"initial", "closing"}:
        agent_summaries = [AGENT_SKILL_SUMMARIES[item] for item in (agents or list(AGENT_SKILL_SUMMARIES))]
    else:
        agent_summaries = [_short_agent_summary(item) for item in (agents or list(AGENT_SKILL_SUMMARIES))]
    return {
        "enabled": True,
        "stage": stage,
        "model_name": model_name,
        "profile": STAGE_PROFILES.get(stage, STAGE_PROFILES["initial"]),
        "supervisor": SUPERVISOR_SUMMARY,
        "agent_summaries": agent_summaries,
        "debate_contract": {
            "score": "模型自己的恶意倾向分，不得直接复制 XGBoost 或单个智能体概率。",
            "confidence": "该判断在字段覆盖和证据一致性下的可靠程度。",
            "evidence_refs": "必须引用输入 EvidenceBlock 中真实存在的智能体或证据编号。",
            "contradictions": "只写当前样本证据之间的冲突，不把历史案例当作当前命中事实。",
        },
    }


def compact_skill_context(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or not value.get("enabled"):
        return {"enabled": False}
    data = dict(value)
    if "skill_markdown_excerpt" in data:
        data["skill_markdown_excerpt"] = compact_text(data.get("skill_markdown_excerpt"), 360)
    if isinstance(data.get("agent_summaries"), list):
        data["agent_summaries"] = data["agent_summaries"][:4]
    return data


def _agents_from_evidence(evidence: list[dict[str, Any]] | None) -> list[str]:
    found: list[str] = []
    for item in evidence or []:
        agent = str(item.get("agent") or "")
        if agent in AGENT_SKILL_SUMMARIES and agent not in found:
            found.append(agent)
    return found


def _short_agent_summary(agent: str) -> dict[str, Any]:
    item = AGENT_SKILL_SUMMARIES.get(agent, {})
    return {
        "agent": agent,
        "role": item.get("role"),
        "goal": item.get("goal"),
        "evidence_focus": item.get("evidence_focus", [])[:3],
    }


def skill_context_to_json(value: Any) -> str:
    return json.dumps(compact_skill_context(value), ensure_ascii=False, separators=(",", ":"))
