"""Investigation plan contract, policy validation, and rule planner."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

from malapp.agents.base import AgentResult, EvidenceBlock
from malapp.agents.evidence_contract import AGENT_ORDER
from malapp.inference.expert import EXPERT_ROLES

PLAN_VERSION = "1.0"
MANDATORY_AGENTS = ("static_analysis",)
STATIC_TOOLS = ("apk_metadata", "certificate", "sdk_inventory")
REGISTERED_TOOLS: dict[str, tuple[str, ...]] = {
    name: tuple(config["tool_scope"]) for name, config in EXPERT_ROLES.items()
}
PLANNER_MODES = ("rule", "llm", "hybrid")
ORCHESTRATION_MODES = ("v0_fixed", "v1_planner", "v2_planner_tools")
NETWORK_FIELDS = (
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
IMPERSONATION_FIELDS = (
    "fake_app",
    "official_app_name",
    "official_pkg",
    "official_md5",
    "official_icon",
    "brand_similarity",
    "impersonation_flag",
    "official_app_assets",
    "official_asset_library",
    "icon_hash",
    "icon_text",
    "icon_path",
    "icon_base64",
)
BUSINESS_FIELDS = (
    "fraud_category_big",
    "fraud_category_small",
    "harm_type",
    "fraud_family",
    "anti_fraud_tag",
)


@dataclass(frozen=True)
class AgentPlan:
    enabled: bool
    reason_code: str


@dataclass
class InvestigationPlan:
    plan_version: str = PLAN_VERSION
    plan_id: str = ""
    risk_focus: tuple[str, ...] = ()
    agents: dict[str, AgentPlan] = field(default_factory=dict)
    tool_allowlist: dict[str, tuple[str, ...]] = field(default_factory=dict)
    max_replans: int = 1
    planner_mode: str = "rule"
    fallback: bool = False
    fallback_reason: str = ""
    source: str = "rule"

    def __post_init__(self) -> None:
        if not self.plan_id:
            self.plan_id = f"plan-{uuid.uuid4().hex[:16]}"

    def enabled_agents(self) -> list[str]:
        return [name for name in AGENT_ORDER if self.agents.get(name) and self.agents[name].enabled]

    def tool_names(self, agent: str) -> tuple[str, ...]:
        if agent in self.tool_allowlist:
            return tuple(self.tool_allowlist[agent])
        return tuple(REGISTERED_TOOLS.get(agent, ()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_version": self.plan_version,
            "plan_id": self.plan_id,
            "risk_focus": list(self.risk_focus),
            "agents": {
                name: asdict(self.agents[name]) if name in self.agents else {"enabled": True, "reason_code": "missing"}
                for name in AGENT_ORDER
            },
            "tool_allowlist": {name: list(self.tool_names(name)) for name in AGENT_ORDER},
            "max_replans": self.max_replans,
            "planner_mode": self.planner_mode,
            "fallback": self.fallback,
            "fallback_reason": self.fallback_reason,
            "source": self.source,
        }


class PlanValidationError(ValueError):
    """Raised when a candidate plan fails schema or policy validation."""


def env_enabled(name: str, default: str = "0") -> bool:
    return str(os.getenv(name, default)).strip().lower() in {"1", "true", "yes", "y"}


def planner_enabled() -> bool:
    return env_enabled("MALAPP_PLANNER_ENABLED", "0")


def tool_runtime_enabled() -> bool:
    return env_enabled("MALAPP_TOOL_RUNTIME_ENABLED", "0")


def planner_mode() -> str:
    mode = str(os.getenv("MALAPP_PLANNER_MODE", "rule")).strip().lower() or "rule"
    return mode if mode in PLANNER_MODES else "rule"


def orchestration_mode() -> str:
    explicit = str(os.getenv("MALAPP_ORCHESTRATION_MODE", "")).strip().lower()
    if explicit in ORCHESTRATION_MODES:
        return explicit
    if not planner_enabled():
        return "v0_fixed"
    if tool_runtime_enabled():
        return "v2_planner_tools"
    return "v1_planner"


def default_tool_allowlist() -> dict[str, tuple[str, ...]]:
    return {name: tuple(tools) for name, tools in REGISTERED_TOOLS.items()}


def present(sample: dict[str, Any], key: str) -> bool:
    value = sample.get(key)
    return value not in ("", None, [], {}, ())


def present_any(sample: dict[str, Any], keys: tuple[str, ...]) -> bool:
    return any(present(sample, key) for key in keys)


def has_network_signal(sample: dict[str, Any], iocs: list[dict[str, Any]] | None = None) -> bool:
    return present_any(sample, NETWORK_FIELDS) or bool(iocs)


def has_impersonation_signal(sample: dict[str, Any]) -> bool:
    return present_any(sample, IMPERSONATION_FIELDS)


def has_business_signal(sample: dict[str, Any]) -> bool:
    if present_any(sample, BUSINESS_FIELDS):
        return True
    from malapp.agents.business_label import build_harm_chain, determine_variant, translate_technical_features

    scene = translate_technical_features(sample)
    chain = build_harm_chain(sample)
    variant = determine_variant(sample)
    variant_label = str(variant.get("variant_label") or "unknown")
    return bool(scene.get("labels") or chain.get("stages") or variant_label not in {"", "unknown"})


def planner_context(sample: dict[str, Any], iocs: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Compact planner input. Never pass the raw sample blob."""
    label_a = str(sample.get("engine_a_label") or "")
    label_b = str(sample.get("engine_b_label") or "")
    return {
        "sample_id": str(sample.get("sample_id") or sample.get("md5") or ""),
        "app_name": str(sample.get("app_name") or "")[:80],
        "package_name": str(sample.get("package_name") or "")[:120],
        "signature_status": str(sample.get("signature_status") or ""),
        "has_certificate": present(sample, "certificate_fingerprint") or present(sample, "cert_sha256"),
        "has_network_ioc": has_network_signal(sample, iocs),
        "has_impersonation_signal": has_impersonation_signal(sample),
        "has_business_signal": has_business_signal(sample),
        "ab_disagreement": bool(label_a and label_b and label_a != label_b),
        "risk_category": str(sample.get("fraud_category_big") or sample.get("harm_type") or ""),
        "missing_fields": [
            key
            for key in ("package_name", "signature_status", "control_url", "official_pkg")
            if not present(sample, key)
        ],
    }


def v0_fixed_plan(
    *,
    reason: str = "planner_disabled",
    fallback: bool = False,
    planner_mode_name: str | None = None,
) -> InvestigationPlan:
    agents = {
        name: AgentPlan(enabled=True, reason_code="v0_fixed_fanout" if name != "static_analysis" else "mandatory_static_baseline")
        for name in AGENT_ORDER
    }
    return InvestigationPlan(
        risk_focus=("static_baseline", "network_ioc", "impersonation", "business_label"),
        agents=agents,
        tool_allowlist=default_tool_allowlist(),
        planner_mode=planner_mode_name or planner_mode(),
        fallback=fallback,
        fallback_reason=reason if fallback else "",
        source="v0_fixed",
    )


def validate_plan(raw: dict[str, Any] | InvestigationPlan) -> InvestigationPlan:
    payload = raw.to_dict() if isinstance(raw, InvestigationPlan) else dict(raw or {})
    version = str(payload.get("plan_version") or PLAN_VERSION).strip() or PLAN_VERSION
    if version != PLAN_VERSION:
        raise PlanValidationError(f"unsupported plan_version: {version}")

    agents_raw = payload.get("agents")
    if not isinstance(agents_raw, dict):
        raise PlanValidationError("agents must be an object")

    unknown_agents = sorted(set(agents_raw) - set(AGENT_ORDER))
    if unknown_agents:
        raise PlanValidationError("unknown agents: " + ", ".join(unknown_agents))

    agents: dict[str, AgentPlan] = {}
    for name in AGENT_ORDER:
        item = agents_raw.get(name)
        if not isinstance(item, dict):
            raise PlanValidationError(f"agent plan missing: {name}")
        enabled = strict_bool(item.get("enabled"), f"agents.{name}.enabled")
        reason_code = item.get("reason_code")
        if not isinstance(reason_code, str) or not reason_code.strip():
            raise PlanValidationError(f"reason_code required for {name}")
        reason_code = reason_code.strip()
        if name in MANDATORY_AGENTS and not enabled:
            raise PlanValidationError("static_analysis cannot be disabled")
        agents[name] = AgentPlan(enabled=enabled, reason_code=reason_code)

    allowlist_raw = payload.get("tool_allowlist") if isinstance(payload.get("tool_allowlist"), dict) else {}
    allowlist: dict[str, tuple[str, ...]] = {}
    for name in AGENT_ORDER:
        requested = allowlist_raw.get(name, REGISTERED_TOOLS[name])
        if not isinstance(requested, (list, tuple)):
            raise PlanValidationError(f"tool_allowlist.{name} must be an array")
        tools = tuple(str(item).strip() for item in requested if str(item).strip())
        unknown_tools = [item for item in tools if item not in REGISTERED_TOOLS[name]]
        if unknown_tools:
            raise PlanValidationError(f"unknown tools for {name}: " + ", ".join(unknown_tools))
        if name == "static_analysis":
            missing_static = [item for item in STATIC_TOOLS if item not in tools]
            if missing_static:
                raise PlanValidationError("static tools cannot be dropped: " + ", ".join(missing_static))
            tools = tuple(dict.fromkeys((*STATIC_TOOLS, *tools)))
        allowlist[name] = tools

    risk_focus = payload.get("risk_focus") or []
    if not isinstance(risk_focus, (list, tuple)):
        raise PlanValidationError("risk_focus must be an array")
    max_replans_n = strict_int(payload.get("max_replans", 1), "max_replans")
    if max_replans_n != 1:
        raise PlanValidationError("max_replans must be 1")

    fallback_flag = False
    if "fallback" in payload:
        fallback_flag = strict_bool(payload.get("fallback"), "fallback")

    return InvestigationPlan(
        plan_version=version,
        plan_id=str(payload.get("plan_id") or f"plan-{uuid.uuid4().hex[:16]}"),
        risk_focus=tuple(str(item) for item in risk_focus if str(item).strip()),
        agents=agents,
        tool_allowlist=allowlist,
        max_replans=1,
        planner_mode=str(payload.get("planner_mode") or planner_mode()),
        fallback=fallback_flag,
        fallback_reason=str(payload.get("fallback_reason") or ""),
        source=str(payload.get("source") or "validated"),
    )


def empty_artifact(agent: str, reason_code: str) -> dict[str, Any]:
    return {
        "status": "skipped_by_plan",
        "reason_code": reason_code,
        "agent": agent,
        "skipped": True,
    }


def skipped_by_plan_result(agent: str, reason_code: str) -> AgentResult:
    claim = f"{agent} 已由 Planner 跳过。"
    description = f"skipped_by_plan:{reason_code}"
    block = EvidenceBlock(
        agent=agent,
        claim=claim,
        evidence=[description],
        confidence=0.0,
        missing_fields=["skipped_by_plan"],
        score=0.0,
        evidence_items=[
            {
                "evidence_type": "skipped_by_plan",
                "source_fields": [],
                "source_values": [],
                "direction": "insufficient",
                "strength": 0.0,
                "description": description,
            }
        ],
        status="insufficient_evidence",
        rule_score=0.0,
    )
    artifacts: dict[str, Any] = {}
    if agent == "threat_intel":
        artifacts["threat_intelligence"] = empty_artifact(agent, reason_code)
    elif agent == "impersonation":
        artifacts["impersonation_analysis"] = empty_artifact(agent, reason_code)
    elif agent == "business_label":
        artifacts["business_label_analysis"] = empty_artifact(agent, reason_code)
    return AgentResult(
        agent_name=agent,
        status="skipped",
        score=None,
        evidence=[block],
        confidence=0.0,
        error=description,
        failure_type="skipped_by_plan",
        artifacts=artifacts,
    )


def disabled_agent_names(sample: dict[str, Any]) -> set[str]:
    config = sample.get("agent_runtime_config") if isinstance(sample.get("agent_runtime_config"), dict) else {}
    overrides = config.get("agents") if isinstance(config.get("agents"), dict) else {}
    disabled = set()
    for name, item in overrides.items():
        if isinstance(item, dict) and item.get("enabled") is False:
            disabled.add(str(name))
    return disabled


def apply_disabled_overrides(plan: InvestigationPlan, sample: dict[str, Any]) -> InvestigationPlan:
    disabled = disabled_agent_names(sample)
    if not disabled:
        return plan
    agents = dict(plan.agents)
    for name in disabled:
        if name in agents:
            agents[name] = AgentPlan(enabled=False, reason_code="disabled_agent_override")
    plan.agents = agents
    return plan


def strict_bool(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise PlanValidationError(f"{field} must be a boolean")
    return value


def strict_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PlanValidationError(f"{field} must be an integer")
    return value


def build_rule_plan(sample: dict[str, Any], iocs: list[dict[str, Any]] | None = None) -> InvestigationPlan:
    context = planner_context(sample, iocs)
    risk_focus = ["static_baseline"]
    agents = {
        "static_analysis": AgentPlan(enabled=True, reason_code="mandatory_static_baseline"),
        "threat_intel": AgentPlan(
            enabled=bool(context["has_network_ioc"] or context["ab_disagreement"]),
            reason_code="network_indicator_present" if context["has_network_ioc"] else (
                "ab_disagreement" if context["ab_disagreement"] else "insufficient_network_signal"
            ),
        ),
        "impersonation": AgentPlan(
            enabled=bool(context["has_impersonation_signal"] or context["ab_disagreement"]),
            reason_code="brand_similarity_signal" if context["has_impersonation_signal"] else (
                "ab_disagreement" if context["ab_disagreement"] else "insufficient_impersonation_signal"
            ),
        ),
        "business_label": AgentPlan(
            enabled=bool(context["has_business_signal"] or context["ab_disagreement"]),
            reason_code="business_taxonomy_signal" if context["has_business_signal"] else (
                "ab_disagreement" if context["ab_disagreement"] else "insufficient_business_signal"
            ),
        ),
    }
    if agents["threat_intel"].enabled:
        risk_focus.append("network_ioc")
    if agents["impersonation"].enabled:
        risk_focus.append("impersonation")
    if agents["business_label"].enabled:
        risk_focus.append("business_label")
    plan = InvestigationPlan(
        risk_focus=tuple(risk_focus),
        agents=agents,
        tool_allowlist=default_tool_allowlist(),
        planner_mode="rule",
        source="rule",
    )
    return apply_disabled_overrides(validate_plan(plan), sample)


def enable_agents(plan: InvestigationPlan, names: list[str], reason_code: str) -> InvestigationPlan:
    agents = dict(plan.agents)
    for name in names:
        current = agents.get(name)
        if current is None or current.enabled:
            continue
        if current.reason_code == "disabled_agent_override":
            continue
        agents[name] = AgentPlan(enabled=True, reason_code=reason_code)
    plan.agents = agents
    return plan


def extend_tool_allowlist(plan: InvestigationPlan, agent: str, tools: list[str]) -> InvestigationPlan:
    current = list(plan.tool_names(agent))
    registered = REGISTERED_TOOLS.get(agent, ())
    for name in tools:
        if name in registered and name not in current:
            current.append(name)
    allowlist = dict(plan.tool_allowlist)
    allowlist[agent] = tuple(current)
    plan.tool_allowlist = allowlist
    return plan


def build_investigation_plan(
    sample: dict[str, Any],
    iocs: list[dict[str, Any]] | None = None,
) -> tuple[InvestigationPlan, list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    mode = planner_mode()
    if not planner_enabled():
        plan = apply_disabled_overrides(v0_fixed_plan(reason="planner_disabled", planner_mode_name=mode), sample)
        events.append(plan_event("planner_finished", "disabled", "planner disabled; using V0 fan-out", plan=plan))
        return plan, events

    events.append(plan_event("planner_started", "running", f"planner mode={mode}"))
    try:
        if mode == "llm":
            candidate = sample.get("investigation_plan") if isinstance(sample.get("investigation_plan"), dict) else None
            if not candidate:
                raise PlanValidationError("llm planner produced no structured plan")
            plan = apply_disabled_overrides(validate_plan(candidate), sample)
            plan.source = "llm"
        elif mode == "hybrid":
            candidate = sample.get("investigation_plan") if isinstance(sample.get("investigation_plan"), dict) else None
            if candidate:
                plan = apply_disabled_overrides(validate_plan(candidate), sample)
                plan.source = "hybrid"
            else:
                plan = build_rule_plan(sample, iocs)
                plan.source = "hybrid_rule"
        else:
            plan = build_rule_plan(sample, iocs)
        events.append(plan_event("planner_finished", "completed", "plan validated", plan=plan))
        return plan, events
    except PlanValidationError as exc:
        events.append(plan_event("planner_invalid", "failed", str(exc)))
        fallback = apply_disabled_overrides(
            v0_fixed_plan(reason=str(exc), fallback=True, planner_mode_name=mode),
            sample,
        )
        events.append(plan_event("planner_fallback", "fallback", str(exc), plan=fallback))
        return fallback, events


def plan_event(
    phase: str,
    status: str,
    message: str,
    *,
    plan: InvestigationPlan | None = None,
    agent_name: str = "",
    reason_code: str = "",
    run_id: str = "",
) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "plan_id": plan.plan_id if plan else "",
        "plan_version": plan.plan_version if plan else PLAN_VERSION,
        "agent_name": agent_name,
        "reason_code": reason_code or (plan.fallback_reason if plan else ""),
        "phase": phase,
        "status": status,
        "message": message,
        "orchestration_mode": orchestration_mode(),
    }


def stable_plan_digest(plan: InvestigationPlan) -> str:
    payload = json.dumps(plan.to_dict(), ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
