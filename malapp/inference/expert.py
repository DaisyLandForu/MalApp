"""Shared expert-model provider used inside the four Agent.run boundaries."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from malapp.agents.base import EvidenceBlock
from malapp.orchestration.debate import build_provider

EXPERT_PROMPT_VERSION = "expert-domain-review-v1"
EXPERT_ROLES: dict[str, dict[str, Any]] = {
    "static_analysis": {
        "role_id": "expert-static-v1",
        "prompt_id": "expert-static-analysis-v1",
        "role": "static APK and certificate analyst",
        "feature_scope": ["md5", "sha1", "sha256", "app_name", "package_name", "signature_status", "certificate_fingerprint", "packer", "permissions", "sdk_list", "apk_analysis"],
        "tool_scope": ["apk_metadata", "certificate", "sdk_inventory"],
    },
    "threat_intel": {
        "role_id": "expert-threat-v1",
        "prompt_id": "expert-threat-intelligence-v1",
        "role": "network IOC and threat-family analyst",
        "feature_scope": ["control_url", "download_url", "control_mailbox", "control_phone", "domains", "ips", "threat_intelligence", "fraud_family"],
        "tool_scope": ["ioc_lookup", "network_indicator", "family_correlation"],
    },
    "impersonation": {
        "role_id": "expert-impersonation-v1",
        "prompt_id": "expert-impersonation-v1",
        "role": "official-asset and impersonation analyst",
        "feature_scope": ["fake_app", "app_name", "package_name", "official_app_name", "official_pkg", "official_md5", "brand_similarity", "impersonation_analysis"],
        "tool_scope": ["official_asset_match", "package_similarity", "certificate_comparison"],
    },
    "business_label": {
        "role_id": "expert-business-v1",
        "prompt_id": "expert-business-label-v1",
        "role": "anti-fraud business semantics analyst",
        "feature_scope": ["fraud_category_big", "fraud_category_small", "harm_type", "fraud_family", "risk_score", "version_status", "business_label_analysis"],
        "tool_scope": ["business_taxonomy", "harm_chain", "variant_mapping"],
    },
}


class ExpertModelProvider:
    """One request-shared model identity with domain-specific prompt/tool scopes."""

    def __init__(self, config: dict[str, Any] | None = None):
        self._provider = build_provider("model_a", config or {})

    def review(
        self,
        agent: str,
        sample: dict[str, Any],
        block: EvidenceBlock,
        *,
        extra: dict[str, Any] | None = None,
    ) -> tuple[EvidenceBlock, dict[str, Any]]:
        role = EXPERT_ROLES[agent]
        manifest = self.manifest(agent)
        if self._provider.backend == "rule":
            return _missing_confidence(block), {**manifest, "status": "model_unavailable"}

        from malapp.agents.evidence_layers import _call_single_agent_review

        scoped = {
            key: sample.get(key)
            for key in role["feature_scope"]
            if sample.get(key) not in (None, "", [], {})
        }
        scoped.update(extra or {})
        context = {
            "agent": agent,
            "role": role["role"],
            "tool_scope": list(role["tool_scope"]),
            "feature_scope": list(role["feature_scope"]),
            "raw_features": scoped,
        }
        review, generated = _call_single_agent_review(self._provider, context)
        review["referenced_evidence_ids"] = [block.evidence_id or block.agent]
        review["provider"] = self._provider.public_config()
        review["prompt_version"] = EXPERT_PROMPT_VERSION
        review["role_id"] = role["role_id"]
        review["prompt_id"] = role["prompt_id"]
        review["tool_scope"] = list(role["tool_scope"])
        review["feature_scope"] = list(role["feature_scope"])
        review["metrics"] = {
            key: generated.get(key, 0)
            for key in ("latency_ms", "prompt_tokens", "completion_tokens")
        }
        # The model explains deterministic facts; it cannot append or replace evidence.
        aligned = replace(
            block,
            claim=str(review.get("summary") or review.get("review_reason") or block.claim),
            expert_review=review,
        )
        return _missing_confidence(aligned), {**manifest, "status": "model_generated", "review": review}

    def manifest(self, agent: str | None = None) -> dict[str, Any]:
        value: dict[str, Any] = {
            "identity": self._provider.identity(),
            "expert_model_id": self._provider.model,
            "expert_model_version": self._provider.identity(),
            "provider": self._provider.public_config(),
            "prompt_version": EXPERT_PROMPT_VERSION,
            "expert_prompt_bundle": EXPERT_PROMPT_VERSION,
            "roles": {
                name: {
                    "role_id": config["role_id"],
                    "prompt_id": config["prompt_id"],
                    "role": config["role"],
                    "feature_scope": list(config["feature_scope"]),
                    "tool_scope": list(config["tool_scope"]),
                }
                for name, config in EXPERT_ROLES.items()
            },
        }
        if agent:
            value["agent"] = agent
        return value


def explanation_layer(agent_results: list[Any], provider_manifest: dict[str, Any]) -> dict[str, Any]:
    explanations = []
    statuses = []
    for result in agent_results:
        expert = result.artifacts.get("expert_review") if isinstance(result.artifacts, dict) else None
        if not isinstance(expert, dict):
            continue
        statuses.append(str(expert.get("status") or ""))
        review = expert.get("review")
        if isinstance(review, dict):
            explanations.append(review)
    if explanations and len(explanations) == len(agent_results):
        status = "model_generated"
    elif explanations:
        status = "model_partial"
    else:
        status = "model_unavailable"
    return {
        "status": status,
        "provider": provider_manifest.get("provider", {}),
        "expert_identity": provider_manifest.get("identity"),
        "prompt_version": EXPERT_PROMPT_VERSION,
        "agent_explanations": explanations,
        "overall_summary": "；".join(str(item.get("summary") or "") for item in explanations if item.get("summary")),
        "agent_statuses": statuses,
    }


def _missing_confidence(block: EvidenceBlock) -> EvidenceBlock:
    if block.missing_fields:
        return replace(block, confidence=0.0, status="insufficient_evidence")
    return block
