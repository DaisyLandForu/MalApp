"""Decision provenance graph for reconstructing how a final label was produced."""

from __future__ import annotations

from typing import Any

from malapp.observability.context import safe_digest, sanitized

PROVENANCE_SCHEMA_VERSION = "decision-provenance-v1"
AGENT_NAMES = ("static_analysis", "threat_intel", "impersonation", "business_label")


def build_decision_provenance(report: dict[str, Any]) -> dict[str, Any]:
    run_id = str(report.get("run_id") or (report.get("execution") or {}).get("run_id") or "")
    if not run_id:
        raise ValueError("run_id is required for decision provenance")
    execution = report.get("execution") or {}
    decision = report.get("decision") or {}
    debate = report.get("debate") or {}
    runtime = (report.get("preprocess") or {}).get("agent_runtime") or {}
    runtime_agents = runtime.get("agents") if isinstance(runtime.get("agents"), dict) else {}
    evidence_layers = report.get("evidence_layers") or {}
    envelope = evidence_layers.get("canonical_evidence_envelope") or {}
    evidence_blocks = [item for item in report.get("evidence_blocks", []) if isinstance(item, dict)]
    evidence_by_agent = {
        str(item.get("agent") or ""): item for item in evidence_blocks
    }
    rag = evidence_layers.get("rag_context") or {}
    engine_c = report.get("engine_c") or {}
    history_reused = bool(execution.get("history_reused"))
    engine_c_executed = bool(engine_c.get("executed"))
    engine_c_path_available = engine_c_executed or history_reused
    reused_status = "reused" if history_reused else "completed"

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []

    def add_node(
        node_id: str,
        kind: str,
        status: str,
        output: Any,
        *,
        summary: dict[str, Any] | None = None,
        input_refs: list[str] | None = None,
        artifact_refs: list[dict[str, str]] | None = None,
    ) -> None:
        nodes.append(
            {
                "node_id": node_id,
                "kind": kind,
                "status": status,
                "input_refs": list(input_refs or []),
                "artifact_refs": list(artifact_refs or []),
                "output_digest": safe_digest(output),
                "summary": sanitized(summary or {}),
            }
        )

    def add_edge(source: str, target: str, relation: str) -> None:
        edges.append(
            {
                "edge_id": f"edge-{len(edges) + 1:03d}",
                "source": source,
                "target": target,
                "relation": relation,
            }
        )

    admission_id = "admission"
    add_node(
        admission_id,
        "engine_c_admission",
        "completed",
        engine_c,
        summary={
            "execute_engine_c": engine_c_executed,
            "reason": engine_c.get("reason"),
            "route": engine_c.get("route"),
        },
    )
    for engine in ("a", "b"):
        score = (report.get("sample") or {}).get(f"engine_{engine}_score")
        node_id = f"engine_{engine}_input"
        add_node(
            node_id,
            "upstream_engine_score",
            "completed" if score not in (None, "") else "missing",
            score,
            summary={"engine": engine.upper(), "score": score},
        )

    cache_node_id = "cache_lookup"
    if history_reused:
        add_node(
            cache_node_id,
            "cached_decision_artifact",
            "completed",
            {
                "source": execution.get("history_reuse_source"),
                "cached_run_id": execution.get("cached_artifact_run_id"),
            },
            summary={
                "source": execution.get("history_reuse_source"),
                "cached_run_id": execution.get("cached_artifact_run_id"),
            },
            input_refs=[admission_id],
            artifact_refs=[
                {"type": "run", "id": str(execution.get("cached_artifact_run_id") or "unknown")}
            ],
        )
        add_edge(admission_id, cache_node_id, "selected_cached_artifact")

    agent_node_ids: list[str] = []
    for agent_name in AGENT_NAMES:
        node_id = f"agent_{agent_name}"
        agent_node_ids.append(node_id)
        state = runtime_agents.get(agent_name) if isinstance(runtime_agents.get(agent_name), dict) else {}
        block = evidence_by_agent.get(agent_name) or {}
        if history_reused and block:
            status = reused_status
        elif not engine_c_executed:
            status = "skipped"
        else:
            status = str(state.get("status") or block.get("status") or "unknown")
        add_node(
            node_id,
            "agent_evidence",
            status,
            block,
            summary={
                "agent": agent_name,
                "claim": block.get("claim"),
                "score": block.get("score"),
                "confidence": block.get("confidence", state.get("confidence")),
                "evidence_count": len(block.get("evidence_items") or block.get("evidence") or []),
            },
            input_refs=[cache_node_id if history_reused else admission_id],
        )
        add_edge(
            cache_node_id if history_reused else admission_id,
            node_id,
            "reused_agent_evidence" if history_reused else
            "authorized_agent_execution" if engine_c_executed else
            "skipped_by_admission",
        )

    evidence_id = "evidence_envelope"
    evidence_snapshot_id = str(envelope.get("evidence_snapshot_id") or debate.get("evidence_snapshot_id") or "")
    evidence_status = reused_status if history_reused and evidence_blocks else (
        "completed" if evidence_snapshot_id else "skipped"
    )
    add_node(
        evidence_id,
        "canonical_evidence",
        evidence_status,
        envelope or evidence_blocks,
        summary={
            "evidence_snapshot_id": evidence_snapshot_id or None,
            "evidence_ids": envelope.get("evidence_ids") or [],
            "agent_block_count": len(evidence_blocks),
        },
        input_refs=agent_node_ids if engine_c_path_available else [admission_id],
        artifact_refs=(
            [{"type": "evidence_snapshot", "id": evidence_snapshot_id}]
            if evidence_snapshot_id else []
        ),
    )
    if engine_c_path_available:
        for node_id in agent_node_ids:
            add_edge(node_id, evidence_id, "contributed_evidence")
    else:
        add_edge(admission_id, evidence_id, "skipped_by_admission")

    rag_id = "rag_evidence"
    rag_snapshot_id = str(rag.get("rag_snapshot_id") or report.get("rag_snapshot_id") or "")
    rag_status = reused_status if history_reused and rag else (
        "skipped" if not engine_c_executed or not rag.get("enabled") else
        "completed" if rag.get("ready", True) and not rag.get("error") else
        "degraded"
    )
    add_node(
        rag_id,
        "rag_retrieval",
        rag_status,
        rag,
        summary={
            "rag_snapshot_id": rag_snapshot_id or None,
            "result_count": len(rag.get("items") or []),
            "enabled": bool(rag.get("enabled")),
        },
        input_refs=[evidence_id] if engine_c_path_available else [admission_id],
        artifact_refs=(
            [{"type": "rag_snapshot", "id": rag_snapshot_id}] if rag_snapshot_id else []
        ),
    )
    add_edge(
        evidence_id if engine_c_path_available else admission_id,
        rag_id,
        "retrieval_query_context" if engine_c_path_available else "skipped_by_admission",
    )

    xgb_id = "xgboost_probability"
    xgb = decision.get("xgb") or {}
    xgb_status = reused_status if history_reused and xgb else (
        "completed" if xgb else "skipped"
    )
    add_node(
        xgb_id,
        "xgboost_inference",
        xgb_status,
        xgb,
        summary={
            "probability": xgb.get("probability"),
            "verdict": xgb.get("verdict"),
            "artifact_id": xgb.get("artifact_id") or xgb.get("model_id"),
        },
        input_refs=[evidence_id] if engine_c_path_available else [admission_id],
    )
    add_edge(
        evidence_id if engine_c_path_available else admission_id,
        xgb_id,
        "feature_inference" if engine_c_path_available else "skipped_by_admission",
    )

    model_node_ids: list[str] = []
    model_statuses: list[str] = []
    for slot in ("model_a", "model_b"):
        node_id = slot
        model_node_ids.append(node_id)
        result = debate.get(slot) if isinstance(debate.get(slot), dict) else {}
        calls = [
            item for item in debate.get("model_calls", [])
            if isinstance(item, dict) and item.get("provider_slot") == slot
        ]
        if history_reused and result:
            status = reused_status
        elif not engine_c_executed or debate.get("execution_mode") == "skipped":
            status = "skipped"
        elif any(item.get("status") == "failed" for item in calls):
            status = "degraded"
        elif calls and all(item.get("status") == "fallback" for item in calls):
            status = "fallback"
        else:
            status = "completed"
        model_statuses.append(status)
        add_node(
            node_id,
            "model_opinion",
            status,
            result,
            summary={
                "slot": slot,
                "verdict": result.get("verdict"),
                "score": result.get("score"),
                "confidence": result.get("confidence"),
                "call_ids": [str(item.get("call_id")) for item in calls],
            },
            input_refs=[evidence_id, rag_id, xgb_id] if engine_c_path_available else [admission_id],
            artifact_refs=[
                {"type": "model_call", "id": str(item.get("call_id"))}
                for item in calls if item.get("call_id")
            ],
        )
        if engine_c_path_available:
            for source, relation in (
                (evidence_id, "consumed_canonical_evidence"),
                (rag_id, "consumed_rag_context"),
                (xgb_id, "consumed_xgboost_prior"),
            ):
                add_edge(source, node_id, relation)
        else:
            add_edge(admission_id, node_id, "skipped_by_admission")

    debate_id = "debate_arbiter"
    arbiter = debate.get("arbiter") if isinstance(debate.get("arbiter"), dict) else {}
    debate_status = reused_status if history_reused and arbiter else (
        "fallback" if arbiter and model_statuses and all(item == "fallback" for item in model_statuses) else
        "completed" if arbiter else
        "skipped"
    )
    add_node(
        debate_id,
        "dual_model_debate",
        debate_status,
        {"arbiter": arbiter, "stages": debate.get("stages") or []},
        summary={
            "execution_mode": debate.get("execution_mode"),
            "conformance": debate.get("debate_conformance"),
            "arbiter_verdict": arbiter.get("verdict"),
            "arbiter_score": arbiter.get("score"),
        },
        input_refs=model_node_ids if engine_c_path_available else [admission_id],
    )
    if engine_c_path_available:
        for node_id in model_node_ids:
            add_edge(node_id, debate_id, "submitted_opinion")
    else:
        add_edge(admission_id, debate_id, "skipped_by_admission")

    decision_id = "decision_rule"
    runtime_snapshot = report.get("runtime_snapshot") or {}
    decision_status = reused_status if history_reused else "completed"
    add_node(
        decision_id,
        "dynamic_wec_decision_rule",
        decision_status,
        decision,
        summary={
            "policy_id": (decision.get("wec") or {}).get("policy_id"),
            "weights": decision.get("weights"),
            "engine_scores": decision.get("engine_scores"),
            "final_score": decision.get("final_score"),
            "review_required": decision.get("review_required"),
        },
        input_refs=(
            ["engine_a_input", "engine_b_input", evidence_id, xgb_id, debate_id]
            if engine_c_path_available
            else ["engine_a_input", "engine_b_input", admission_id]
        ),
        artifact_refs=[
            {"type": "runtime_snapshot", "id": str(runtime_snapshot.get("snapshot_id") or "unknown")}
        ],
    )
    add_edge("engine_a_input", decision_id, "weighted_engine_input")
    add_edge("engine_b_input", decision_id, "weighted_engine_input")
    if engine_c_path_available:
        add_edge(evidence_id, decision_id, "evidence_weight_adjustment")
        add_edge(xgb_id, decision_id, "engine_c_calibration")
        add_edge(debate_id, decision_id, "engine_c_opinion")
    if history_reused:
        add_edge(cache_node_id, decision_id, "reused_decision")
    elif not engine_c_executed:
        add_edge(admission_id, decision_id, "direct_ab_decision")

    final_id = "final_label"
    add_node(
        final_id,
        "final_label",
        decision_status,
        {
            "verdict": decision.get("verdict"),
            "score": decision.get("final_score"),
            "risk_level": decision.get("risk_level"),
        },
        summary={
            "verdict": decision.get("verdict"),
            "verdict_label": decision.get("verdict_label"),
            "final_score": decision.get("final_score"),
            "risk_level": decision.get("risk_level"),
        },
        input_refs=[decision_id],
    )
    add_edge(decision_id, final_id, "produced_final_label")

    order = [
        admission_id,
        "engine_a_input",
        "engine_b_input",
        *([cache_node_id] if history_reused else []),
        *agent_node_ids,
        evidence_id,
        rag_id,
        xgb_id,
        *model_node_ids,
        debate_id,
        decision_id,
        final_id,
    ]
    provenance = {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "provenance_id": f"provenance-{run_id.removeprefix('run-')}",
        "run_id": run_id,
        "report_id": report.get("report_id"),
        "runtime_snapshot_id": runtime_snapshot.get("snapshot_id"),
        "evidence_snapshot_id": evidence_snapshot_id or None,
        "nodes": nodes,
        "edges": edges,
        "reconstruction_order": order,
        "final_node_id": final_id,
    }
    validate_decision_provenance(provenance)
    return sanitized(provenance)


def validate_decision_provenance(provenance: dict[str, Any]) -> None:
    nodes = provenance.get("nodes") or []
    node_ids = [str(item.get("node_id") or "") for item in nodes]
    if not node_ids or len(node_ids) != len(set(node_ids)) or "" in node_ids:
        raise ValueError("decision provenance must contain unique node ids")
    known = set(node_ids)
    if provenance.get("final_node_id") not in known:
        raise ValueError("decision provenance final node is missing")
    if set(provenance.get("reconstruction_order") or []) != known:
        raise ValueError("decision provenance reconstruction order must cover every node")
    for node in nodes:
        if not str(node.get("output_digest") or "").startswith("sha256:"):
            raise ValueError(f"decision provenance node {node.get('node_id')} has no output digest")
        if any(ref not in known for ref in node.get("input_refs") or []):
            raise ValueError(f"decision provenance node {node.get('node_id')} has an unknown input ref")
    for edge in provenance.get("edges") or []:
        if edge.get("source") not in known or edge.get("target") not in known:
            raise ValueError(f"decision provenance edge {edge.get('edge_id')} has an unknown endpoint")


def reconstruct_decision_path(provenance: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the validated, deterministic decision path for UI or audit export."""
    validate_decision_provenance(provenance)
    by_id = {str(item["node_id"]): item for item in provenance["nodes"]}
    return [by_id[node_id] for node_id in provenance["reconstruction_order"]]
