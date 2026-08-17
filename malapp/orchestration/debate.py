from __future__ import annotations

import copy
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any

from malapp.agents.skill_context import build_debate_skill_context, compact_skill_context
from malapp.inference.local_qwen import local_qwen_enabled, normalize_llm_result, parse_model_json, qwen_generate

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
CALIBRATION_PATH = DATA_DIR / "eval" / "best_params.json"

ROLE_A = {
    "name": "保守复核模型",
    "strategy": "强调证据交叉印证、反例、缺失字段和误报风险。",
}
ROLE_B = {
    "name": "风险优先模型",
    "strategy": "强调高危权限、IOC、仿冒、业务危害链和漏报风险。",
}

def debate_model_workers() -> int:
    try:
        configured = int(os.getenv("MALAPP_DEBATE_WORKERS", "2") or "2")
    except ValueError:
        configured = 2
    return max(1, min(configured, 2))

def fast_model_retry_enabled() -> bool:
    return os.getenv("MALAPP_FAST_MODEL_RETRY", "1").strip().lower() in {"1", "true", "yes", "on"}

def full_schema_retry_enabled() -> bool:
    return os.getenv("MALAPP_LLM_FULL_SCHEMA_RETRY", "0").strip().lower() in {"1", "true", "yes", "on"}


def schema_repair_max_attempts() -> int:
    """Return the bounded number of format-only repair attempts per phase."""
    try:
        configured = int(os.getenv("MALAPP_SCHEMA_REPAIR_MAX_ATTEMPTS", "2") or "2")
    except ValueError:
        configured = 2
    return max(0, min(configured, 2))


def merge_generated_metrics(previous: dict[str, Any], newer: dict[str, Any]) -> dict[str, Any]:
    """Keep the latest response while preserving the cumulative request cost."""
    def metric(payload: dict[str, Any], key: str) -> int:
        try:
            return int(payload.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    merged = dict(newer)
    for key in ("latency_ms", "prompt_tokens", "completion_tokens"):
        merged[key] = metric(previous, key) + metric(newer, key)
    return merged

def run_debate(evidence_blocks: list[Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    # 双模型辩论入口：接收四智能体 EvidenceBlock，让模型甲/模型乙完成初判、质疑、反驳和终审。
    # 这里负责压缩证据、并行调用模型、校验 JSON 输出，并把失败原因返回给上层流水线。
    config = config or {}
    evidence = [
        compact_evidence_for_llm(asdict(item) if hasattr(item, "__dataclass_fields__") else dict(item))
        for item in evidence_blocks
    ]
    evidence = attach_llm_agent_reviews(evidence, config.get("llm_agent_reviews"))
    initial_evidence_json = json.dumps(evidence_for_phase(evidence, "initial"), ensure_ascii=False, separators=(",", ":"))
    initial_evidence_json_b = json.dumps(evidence_for_model_phase(evidence, "initial", "model_b"), ensure_ascii=False, separators=(",", ":"))
    turn_evidence_json = json.dumps(evidence_for_phase(evidence, "turn"), ensure_ascii=False, separators=(",", ":"))
    turn_evidence_json_b = json.dumps(evidence_for_model_phase(evidence, "turn", "model_b"), ensure_ascii=False, separators=(",", ":"))
    rebuttal_evidence_json = json.dumps(evidence_for_phase(evidence, "rebuttal"), ensure_ascii=False, separators=(",", ":"))
    rebuttal_evidence_json_b = json.dumps(evidence_for_model_phase(evidence, "rebuttal", "model_b"), ensure_ascii=False, separators=(",", ":"))
    closing_evidence_json = json.dumps(evidence_for_phase(evidence, "closing"), ensure_ascii=False, separators=(",", ":"))
    closing_evidence_json_b = json.dumps(evidence_for_model_phase(evidence, "closing", "model_b"), ensure_ascii=False, separators=(",", ":"))
    providers = {
        "model_a": build_provider("model_a", config),
        "model_b": build_provider("model_b", config),
    }
    max_rounds = max(1, min(int(config.get("max_attack_rounds", 1)), 6))
    min_rounds = max(1, min(int(config.get("min_attack_rounds", 1)), max_rounds))
    score_threshold = max(0.0, min(float(config.get("convergence_score_threshold", 0.06)), 0.5))
    argument_threshold = max(0.0, min(float(config.get("convergence_argument_threshold", 0.82)), 1.0))
    verification_mode = bool(config.get("verification_mode"))

    state = "created"
    transitions: list[dict[str, Any]] = []
    stages: list[dict[str, Any]] = []
    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    rag_context = compact_rag_context(config.get("rag_context"))
    skill_contexts = {
        "initial": build_debate_skill_context("initial", evidence),
        "directed_attack": build_debate_skill_context("directed_attack", evidence),
        "rebuttal": build_debate_skill_context("rebuttal", evidence),
        "closing": build_debate_skill_context("closing", evidence),
    }
    memory = {
        "evidence_summary": summarize_evidence(evidence),
        "rag_context": rag_context,
        "skill_contexts": skill_contexts,
        "stage_summaries": [],
    }
    total_started = time.perf_counter()

    def transition(target: str) -> None:
        nonlocal state
        transitions.append({"from": state, "to": target, "ts": time.time()})
        state = target

    transition("initial_testimony")
    with ThreadPoolExecutor(max_workers=debate_model_workers()) as executor:
        future_a = executor.submit(
            initial_report,
            providers["model_a"],
            "model_a",
            ROLE_A,
            initial_evidence_json,
            evidence,
            rag_context,
            skill_contexts["initial"],
        )
        future_b = executor.submit(
            initial_report,
            providers["model_b"],
            "model_b",
            ROLE_B,
            initial_evidence_json_b,
            evidence,
            rag_context,
            skill_contexts["initial"],
        )
        current_a = safe_model_result(
            future_a,
            "initial_testimony",
            role=ROLE_A,
        )
        current_b = safe_model_result(
            future_b,
            "initial_testimony",
            role=ROLE_B,
        )
    initial_a = dict(current_a)
    initial_b = dict(current_b)
    initial_stage = stage_record("initial_testimony", 0, [current_a, current_b])
    append_stage(stages, memory, token_usage, initial_stage)

    convergence_history = []
    stop_reason = "xgboost_evidence_verification" if verification_mode else "max_rounds"
    completed_rounds = 0
    for round_number in range(1, 1 if verification_mode else max_rounds + 1):
        completed_rounds = round_number
        transition(f"attack_round_{round_number}")
        attack_plan_a = build_attack_plan("model_a", current_b, evidence)
        attack_plan_b = build_attack_plan("model_b", current_a, evidence)
        attack_memory = snapshot_debate_memory(memory)
        with ThreadPoolExecutor(max_workers=debate_model_workers()) as executor:
            future_a = executor.submit(
                debate_turn,
                providers["model_a"],
                ROLE_A,
                "directed_attack",
                turn_evidence_json,
                current_a,
                current_b,
                attack_memory,
                attack_plan_a,
            )
            future_b = executor.submit(
                debate_turn,
                providers["model_b"],
                ROLE_B,
                "directed_attack",
                turn_evidence_json_b,
                current_b,
                current_a,
                attack_memory,
                attack_plan_b,
            )
            attack_a = safe_model_result(
                future_a,
                "directed_attack",
                role=ROLE_A,
            )
            attack_b = safe_model_result(
                future_b,
                "directed_attack",
                role=ROLE_B,
            )
        attack_stage = stage_record("directed_attack", round_number, [attack_a, attack_b])
        append_stage(stages, memory, token_usage, attack_stage)

        transition(f"rebuttal_round_{round_number}")
        rebuttal_memory = snapshot_debate_memory(memory)
        with ThreadPoolExecutor(max_workers=debate_model_workers()) as executor:
            future_a = executor.submit(
                debate_turn,
                providers["model_a"],
                ROLE_A,
                "evidence_rebuttal",
                rebuttal_evidence_json,
                current_a,
                attack_b,
                rebuttal_memory,
                {
                    "target": "模型乙质疑",
                    "instruction": "从原始证据块重新引用支持己方观点的关键条目；承认合理质疑并修正判断。",
                    "required_evidence_ids": evidence_ids(evidence),
                },
            )
            future_b = executor.submit(
                debate_turn,
                providers["model_b"],
                ROLE_B,
                "role_reversal_rebuttal",
                rebuttal_evidence_json_b,
                current_b,
                attack_a,
                rebuttal_memory,
                {
                    "target": "模型甲质疑",
                    "instruction": "先假设模型甲正确，寻找支持甲但被遗漏的证据，再基于完整证据反驳或修正。",
                    "required_evidence_ids": evidence_ids(evidence),
                },
            )
            rebuttal_a = safe_model_result(
                future_a,
                "evidence_rebuttal",
                role=ROLE_A,
            )
            rebuttal_b = safe_model_result(
                future_b,
                "role_reversal_rebuttal",
                role=ROLE_B,
            )
        rebuttal_stage = stage_record("evidence_rebuttal", round_number, [rebuttal_a, rebuttal_b])
        append_stage(stages, memory, token_usage, rebuttal_stage)
        current_a, current_b = rebuttal_a, rebuttal_b

        convergence = measure_convergence(current_a, current_b)
        convergence["round"] = round_number
        convergence_history.append(convergence)
        if round_number >= min_rounds and convergence["score_distance"] <= score_threshold:
            stop_reason = "score_convergence"
            break
        if round_number >= min_rounds and convergence["argument_similarity"] >= argument_threshold:
            stop_reason = "argument_convergence"
            break

    if verification_mode:
        closing_a = current_a
        closing_b = current_b
    else:
        transition("closing_statement")
        closing_memory = snapshot_debate_memory(memory)
        closing_mode = closing_model_mode(config)
        if closing_mode == "model_a":
            closing_a = closing_report(
                providers["model_a"],
                ROLE_A,
                closing_evidence_json,
                initial_a,
                current_a,
                closing_memory,
            )
            closing_b = skipped_closing_result(current_b, "model_b", closing_mode)
        elif closing_mode == "model_b":
            closing_a = skipped_closing_result(current_a, "model_a", closing_mode)
            try:
                closing_b = closing_report(
                    providers["model_b"],
                    ROLE_B,
                    closing_evidence_json_b,
                    initial_b,
                    current_b,
                    closing_memory,
                )
            except Exception as exc:
                raise RuntimeError(model_unavailable_failure_message(ROLE_B, "closing_statement", exc)) from exc
        else:
            with ThreadPoolExecutor(max_workers=debate_model_workers()) as executor:
                future_a = executor.submit(
                    closing_report,
                    providers["model_a"],
                    ROLE_A,
                    closing_evidence_json,
                    initial_a,
                    current_a,
                    closing_memory,
                )
                future_b = executor.submit(
                    closing_report,
                    providers["model_b"],
                    ROLE_B,
                    closing_evidence_json_b,
                    initial_b,
                    current_b,
                    closing_memory,
                )
                closing_a = safe_model_result(
                    future_a,
                    "closing_statement",
                    role=ROLE_A,
                )
                closing_b = safe_model_result(
                    future_b,
                    "closing_statement",
                    role=ROLE_B,
                )
        closing_stage = stage_record("closing_statement", completed_rounds + 1, [closing_a, closing_b])
        closing_stage["closing_mode"] = closing_mode
        append_stage(stages, memory, token_usage, closing_stage)

    transition("arbiter_review")
    arbiter = arbitrate(evidence, initial_a, initial_b, closing_a, closing_b, memory, config)
    transition("completed")

    return {
        "execution_mode": "llm_evidence_verification" if verification_mode else "full_debate",
        "state_machine": {
            "state": state,
            "phases": [
                "initial_testimony",
                "directed_attack",
                "evidence_rebuttal",
                "closing_statement",
                "arbiter_review",
            ],
            "transitions": transitions,
        },
        "model_a": public_model_result(closing_a, ROLE_A),
        "model_b": public_model_result(closing_b, ROLE_B),
        "stages": stages,
        "cross_examination": flatten_debate_turns(stages),
        "debate_rounds": completed_rounds,
        "convergence": {
            "stop_reason": stop_reason,
            "max_rounds": max_rounds,
            "score_threshold": score_threshold,
            "argument_threshold": argument_threshold,
            "history": convergence_history,
        },
        "memory": memory,
        "metrics": {
            "token_usage": token_usage,
            "latency_ms": int((time.perf_counter() - total_started) * 1000),
            "closing_mode": "verification" if verification_mode else closing_model_mode(config),
            "stage_latency_ms": {
                f"{stage['phase']}:{stage['round']}": stage["latency_ms"] for stage in stages
            },
        },
        "providers": {name: provider.public_config() for name, provider in providers.items()},
        "arbiter": arbiter,
        "xgb_prior": config.get("xgb_prior"),
    }


def safe_model_result(
    future: Any,
    phase: str,
    role: dict[str, str],
) -> dict[str, Any]:
    """Return the model result, or fail the whole sample when a required model is unavailable."""
    try:
        return future.result()
    except Exception as exc:
        raise RuntimeError(model_unavailable_failure_message(role, phase, exc)) from exc


def safe_model_b_result(
    future: Any,
    phase: str,
    role: dict[str, str],
    evidence: list[dict[str, Any]],
    reference: dict[str, Any] | None = None,
    own: dict[str, Any] | None = None,
    opponent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Backward-compatible wrapper; model B is also a required model now."""
    try:
        return safe_model_result(future, phase, role)
    except Exception:
        raise


def model_unavailable_failure_message(role: dict[str, str], phase: str, exc: Exception) -> str:
    phase_names = {
        "initial_testimony": "初判",
        "directed_attack": "质疑",
        "evidence_rebuttal": "反驳",
        "role_reversal_rebuttal": "反驳",
        "rebuttal": "反驳",
        "closing_statement": "终审",
    }
    role_name = role.get("name") or role.get("id") or "服务器模型"
    phase_name = phase_names.get(phase, phase)
    reason = compact_text(str(exc), 260)
    return (
        f"{role_name}在{phase_name}阶段不可用或输出无效，已停止本样本研判；"
        f"请等待模型服务恢复后重新研判。原因：{reason}"
    )


def is_model_service_disconnect(exc: Exception) -> bool:
    text = str(exc).lower()
    markers = (
        "remote end closed connection without response",
        "connection closed",
        "connection reset",
        "timed out",
        "timeout",
        "主动断开",
        "请求超时",
        "服务端",
        "model-b",
        "malapp-model-b",
        "18012",
        "8012",
    )
    return any(marker in text for marker in markers)


def model_b_unavailable_initial(
    role: dict[str, str],
    evidence: list[dict[str, Any]],
    phase: str,
    exc: Exception,
    reference: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reference = reference or {}
    score = clamp(float(reference.get("score", 0.5)))
    refs = normalize_list(reference.get("evidence_refs")) or evidence_ids(evidence)
    ref_text = "、".join(refs[:4]) or "四智能体证据"
    return {
        "score": score,
        "verdict": reference.get("verdict")
        if reference.get("verdict") in {"malicious", "suspicious", "benign"}
        else verdict_from_score(score),
        "risk_level": reference.get("risk_level")
        if reference.get("risk_level") in {"high", "medium", "low"}
        else risk_level(score),
        "confidence": 0.0,
        "arguments": [
            f"{role.get('name', '模型乙')}本轮接口已连接但服务端主动断开，未生成可采信的大模型推理。",
            f"系统保留{ref_text}和模型甲结果继续研判，避免单个模型服务异常导致整条样本失败。",
            "该记录只表示模型乙本轮不可用，不代表模型乙已经完成真实初判或终审。",
        ],
        "omissions": ["缺少模型乙本轮有效输出。"],
        "evidence_refs": refs,
        "contradictions": ["模型乙服务不可用，双模型交叉验证完整性下降。"],
        "evidence_chain": [
            "模型乙接口连接后被服务端关闭 -> 未取得有效响应 -> 保留其它证据继续研判 -> 标记模型乙本轮不可用",
            f"{ref_text} -> 继续支撑当前流程 -> 终审降低模型乙权重 -> 避免样本直接失败",
        ],
        "feature_relations": [
            "模型服务状态只影响辩论完整性，不改变四智能体原始证据和规则证据。",
        ],
        "backend": "model_unavailable",
        "phase": phase,
        "role": role.get("name", "风险优先模型"),
        "raw_text": "",
        "provider_error": compact_text(str(exc), 260),
        "validation_warning": "模型乙服务端主动断开，本轮按不可用处理，流程继续。",
        "latency_ms": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


def model_b_unavailable_turn(
    role: dict[str, str],
    evidence: list[dict[str, Any]],
    phase: str,
    exc: Exception,
    own: dict[str, Any] | None = None,
    opponent: dict[str, Any] | None = None,
) -> dict[str, Any]:
    own = own or {}
    opponent = opponent or {}
    score = clamp(float(own.get("score", opponent.get("score", 0.5))))
    refs = normalize_list(own.get("evidence_refs")) or normalize_list(opponent.get("evidence_refs")) or evidence_ids(evidence)
    ref_text = "、".join(refs[:4]) or "四智能体证据"
    return {
        "question": "模型乙本轮服务不可用，无法对模型甲结论提出有效质疑。",
        "answer": (
            "模型乙接口连接后被服务端关闭，本轮不产生真实质疑或反驳。"
            f"系统保留{ref_text}、模型甲结果和已有辩论记忆继续研判，并在终审降低模型乙权重。"
        ),
        "score": score,
        "verdict": own.get("verdict")
        if own.get("verdict") in {"malicious", "suspicious", "benign"}
        else verdict_from_score(score),
        "risk_level": own.get("risk_level")
        if own.get("risk_level") in {"high", "medium", "low"}
        else risk_level(score),
        "confidence": 0.0,
        "arguments": [
            "模型乙服务异常，本轮不作为有效推理依据。",
            "研判流程继续执行，终审会降低模型乙本轮贡献。",
        ],
        "evidence_refs": refs,
        "accepted_challenges": [],
        "rejected_challenges": [],
        "omissions": ["缺少模型乙本轮有效质疑或反驳。"],
        "contradictions": ["模型乙服务不可用，无法完成对模型甲的交叉验证。"],
        "evidence_chain": [
            "模型乙请求被服务端关闭 -> 本轮辩论缺失 -> 保留其它证据 -> 降低模型乙权重",
            f"{ref_text} -> 继续支撑流程 -> 终审注明模型乙不可用",
        ],
        "feature_relations": [
            "模型乙服务状态与样本特征无关，只影响双模型辩论完整性。",
        ],
        "backend": "model_unavailable",
        "phase": phase,
        "role": role.get("name", "风险优先模型"),
        "raw_text": "",
        "provider_error": compact_text(str(exc), 260),
        "validation_warning": "模型乙服务端主动断开，本轮按不可用处理，流程继续。",
        "latency_ms": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }


def closing_model_mode(config: dict[str, Any] | None = None) -> str:
    config = config or {}
    value = str(
        config.get("closing_model")
        or config.get("single_closing_model")
        or os.getenv("MALAPP_CLOSING_MODEL", "model_a")
    ).strip().lower()
    if value in {"model_a", "a", "甲"}:
        return "model_a"
    if value in {"model_b", "b", "乙", "single", "fast"}:
        return "model_b"
    return "both"


def skipped_closing_result(latest: dict[str, Any], model_name: str, mode: str) -> dict[str, Any]:
    result = copy.deepcopy(latest)
    result["closing_skipped"] = True
    result["closing_skip_reason"] = f"{mode} 单模型终审模式下沿用 {model_name} 的反驳后结论"
    result["phase"] = "closing_statement_skipped"
    result["latency_ms"] = 0
    result["prompt_tokens"] = 0
    result["completion_tokens"] = 0
    return result


def snapshot_debate_memory(memory: dict[str, Any]) -> dict[str, Any]:
    return copy.deepcopy(memory)


def compact_evidence_for_llm(block: dict[str, Any]) -> dict[str, Any]:
    return {
        "agent": block.get("agent"),
        "claim": compact_text(block.get("claim"), 160),
        "score": block.get("score"),
        "confidence": block.get("confidence"),
        "evidence": [compact_text(item, 220) for item in normalize_list(block.get("evidence"))[:8]],
        "evidence_items": [
            compact_evidence_item(item)
            for item in block.get("evidence_items", [])
            if isinstance(item, dict)
        ][:8],
        "missing_fields": normalize_list(block.get("missing_fields"))[:8],
    }


def attach_llm_agent_reviews(
    evidence: list[dict[str, Any]],
    reviews: Any,
) -> list[dict[str, Any]]:
    if not isinstance(reviews, list):
        return evidence
    by_agent = {
        str(item.get("agent")): item
        for item in reviews
        if isinstance(item, dict) and item.get("agent")
    }
    for block in evidence:
        agent = str(block.get("agent") or "")
        review = by_agent.get(agent)
        if not review:
            continue
        compact_review = compact_llm_agent_review(review)
        block["llm_independent_review"] = compact_review
        disagreement = llm_rule_disagreement(block, compact_review)
        if disagreement:
            block["llm_rule_disagreement"] = disagreement
        score_disagreement = score_review_disagreement(block, compact_review)
        if score_disagreement:
            block["score_review_disagreement"] = score_disagreement
    return evidence


def compact_llm_agent_review(review: dict[str, Any]) -> dict[str, Any]:
    return {
        "review_verdict": compact_text(review.get("review_verdict"), 20),
        "review_reason": compact_text(review.get("review_reason"), 180),
        "rule_alignment": compact_text(review.get("rule_alignment"), 20),
        "rule_difference": compact_text(review.get("rule_difference"), 180),
        "trust_assessment": compact_text(review.get("trust_assessment"), 40),
        "conflict_resolution": compact_text(review.get("conflict_resolution"), 180),
        "causal_reasoning": compact_text(review.get("causal_reasoning"), 220),
        "feature_links": [compact_text(item, 120) for item in normalize_list(review.get("feature_links"))[:2]],
        "summary": compact_text(review.get("summary"), 160),
        "contradictions": [compact_text(item, 120) for item in normalize_list(review.get("contradictions"))[:2]],
        "missing_impact": compact_text(review.get("missing_impact"), 140),
    }


def llm_rule_disagreement(block: dict[str, Any], review: dict[str, Any]) -> dict[str, Any] | None:
    rule_verdict = verdict_from_score(float(block.get("score") or 0))
    review_verdict = chinese_verdict_to_code(review.get("review_verdict"))
    alignment = str(review.get("rule_alignment") or "")
    if review_verdict and review_verdict != rule_verdict:
        return {
            "type": "verdict_conflict",
            "rule_verdict": rule_verdict,
            "llm_review_verdict": review_verdict,
            "reason": compact_text(review.get("rule_difference") or review.get("review_reason"), 180),
            "debate_focus": "模型甲乙需要同时解释原始特征复核和规则/机器学习证据为何不同，并给出综合取舍。",
        }
    if "冲突" in alignment or "部分" in alignment:
        return {
            "type": "partial_alignment",
            "rule_verdict": rule_verdict,
            "llm_review_verdict": review_verdict or "",
            "reason": compact_text(review.get("rule_difference") or review.get("conflict_resolution"), 180),
            "debate_focus": "模型甲乙需要说明两类证据的一致点和分歧点，再给出综合判断。",
        }
    return None


def score_review_disagreement(block: dict[str, Any], review: dict[str, Any]) -> dict[str, Any] | None:
    """Compare the public malicious probability with the raw-feature agent review."""
    try:
        score = float(block.get("score") or 0)
    except Exception:
        score = 0.0
    score_verdict = verdict_from_score(score)
    review_verdict = chinese_verdict_to_code(review.get("review_verdict"))
    if not review_verdict or review_verdict == score_verdict:
        return None
    return {
        "type": "score_review_conflict",
        "score_verdict": score_verdict,
        "llm_review_verdict": review_verdict,
        "score": round(score, 4),
        "reason": (
            "该智能体的机器学习恶意概率与只看原始特征的智能体判断不一致，"
            "说明模型先验、字段缺失或证据覆盖可能影响了结论。"
        ),
        "debate_focus": (
            "模型甲乙必须说明是否采信机器学习恶意概率，还是采信原始特征复核，"
            "并解释字段缺失、证据强度和其他智能体结论如何影响综合裁决。"
        ),
    }


def chinese_verdict_to_code(value: Any) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if "恶" in text or "malicious" in text:
        return "malicious"
    if "可疑" in text or "疑" in text or "suspicious" in text:
        return "suspicious"
    if "良" in text or "benign" in text:
        return "benign"
    return ""


def compact_evidence_item(item: dict[str, Any]) -> dict[str, Any]:
    values = item.get("source_values")
    if isinstance(values, dict):
        source_values = {str(key): compact_text(value, 160) for key, value in list(values.items())[:6]}
    elif isinstance(values, list):
        source_values = [compact_text(value, 160) for value in values[:6]]
    else:
        source_values = compact_text(values, 160) if values not in ("", None) else ""
    return {
        "evidence_type": item.get("evidence_type", "context"),
        "source_fields": normalize_list(item.get("source_fields"))[:6],
        "source_values": source_values,
        "direction": item.get("direction", "context"),
        "strength": item.get("strength"),
        "description": compact_text(item.get("description"), 220),
    }


def evidence_for_phase(evidence: list[dict[str, Any]], phase: str) -> list[dict[str, Any]]:
    budgets = {
        "initial": {"items": 3, "text": 150, "values": 100, "missing": 4},
        "turn": {"items": 2, "text": 120, "values": 80, "missing": 4},
        "rebuttal": {"items": 1, "text": 90, "values": 60, "missing": 2},
        "closing": {"items": 2, "text": 95, "values": 65, "missing": 2},
    }
    budget = budgets.get(phase, budgets["turn"])
    return [
        compact_evidence_for_phase(
            item,
            item_limit=budget["items"],
            text_limit=budget["text"],
            value_limit=budget["values"],
            missing_limit=budget["missing"],
        )
        for item in evidence
    ]


def evidence_for_model_phase(evidence: list[dict[str, Any]], phase: str, model_name: str) -> list[dict[str, Any]]:
    if model_name != "model_b":
        return evidence_for_phase(evidence, phase)
    budgets = {
        "initial": {"items": 2, "text": 105, "values": 70, "missing": 3},
        "turn": {"items": 1, "text": 80, "values": 50, "missing": 2},
        "rebuttal": {"items": 1, "text": 70, "values": 45, "missing": 2},
        "closing": {"items": 1, "text": 75, "values": 45, "missing": 2},
    }
    budget = budgets.get(phase, budgets["turn"])
    return [
        compact_evidence_for_phase(
            item,
            item_limit=budget["items"],
            text_limit=budget["text"],
            value_limit=budget["values"],
            missing_limit=budget["missing"],
        )
        for item in evidence
    ]


def compact_evidence_for_phase(
    block: dict[str, Any],
    item_limit: int,
    text_limit: int,
    value_limit: int,
    missing_limit: int,
) -> dict[str, Any]:
    items = [item for item in block.get("evidence_items", []) if isinstance(item, dict)]
    items = select_phase_evidence_items(items, item_limit)
    agent_judgement = compact_phase_llm_review(
        block.get("llm_independent_review"),
        text_limit,
    )
    rule_judgement = {
        "rule_verdict": verdict_from_score(float(block.get("score") or 0)),
        "claim": compact_text(block.get("claim"), text_limit),
        "score": block.get("score"),
        "confidence": block.get("confidence"),
        "evidence_summary": [compact_text(item, text_limit) for item in normalize_list(block.get("evidence"))[:item_limit]],
        "evidence_items": [
            compact_evidence_item_for_phase(item, text_limit, value_limit)
            for item in items
        ],
        "missing_fields": normalize_list(block.get("missing_fields"))[:missing_limit],
    }
    return {
        "agent": block.get("agent"),
        "claim": compact_text(block.get("claim"), text_limit),
        "score": block.get("score"),
        "confidence": block.get("confidence"),
        "agent_judgement": agent_judgement,
        "rule_judgement": rule_judgement,
        "llm_independent_review": agent_judgement,
        "llm_rule_disagreement": compact_phase_disagreement(
            block.get("llm_rule_disagreement"),
            text_limit,
        ),
        "score_review_disagreement": compact_phase_disagreement(
            block.get("score_review_disagreement"),
            text_limit,
        ),
        "evidence": rule_judgement["evidence_summary"],
        "evidence_items": rule_judgement["evidence_items"],
        "missing_fields": rule_judgement["missing_fields"],
    }


def compact_phase_llm_review(value: Any, text_limit: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "review_verdict": compact_text(value.get("review_verdict"), 20),
        "review_reason": compact_text(value.get("review_reason"), text_limit),
        "rule_alignment": compact_text(value.get("rule_alignment"), 20),
        "rule_difference": compact_text(value.get("rule_difference"), text_limit),
        "trust_assessment": compact_text(value.get("trust_assessment"), 40),
        "conflict_resolution": compact_text(value.get("conflict_resolution"), text_limit),
        "summary": compact_text(value.get("summary"), text_limit),
        "contradictions": [
            compact_text(item, text_limit)
            for item in normalize_list(value.get("contradictions"))[:2]
        ],
    }


def compact_phase_disagreement(value: Any, text_limit: int) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "type": compact_text(value.get("type"), 40),
        "rule_verdict": compact_text(value.get("rule_verdict"), 20),
        "score_verdict": compact_text(value.get("score_verdict"), 20),
        "llm_review_verdict": compact_text(value.get("llm_review_verdict"), 20),
        "score": value.get("score"),
        "reason": compact_text(value.get("reason"), text_limit),
        "debate_focus": compact_text(value.get("debate_focus"), text_limit),
    }


def select_phase_evidence_items(items: list[dict[str, Any]], item_limit: int) -> list[dict[str, Any]]:
    """Prefer concrete feature evidence; keep XGBoost only as a secondary prior."""
    conflicts: list[dict[str, Any]] = []
    concrete: list[dict[str, Any]] = []
    ml_priors: list[dict[str, Any]] = []
    for item in items:
        evidence_type = str(item.get("evidence_type") or "")
        source_fields = {str(field) for field in normalize_list(item.get("source_fields"))}
        if evidence_type == "evidence_conflict":
            conflicts.append(item)
        elif evidence_type == "xgboost_domain_probability" or "xgb_agent_scores" in source_fields:
            ml_priors.append(item)
        else:
            concrete.append(item)
    conflicts = sorted(conflicts, key=lambda item: float(item.get("strength") or 0), reverse=True)
    concrete = sorted(concrete, key=lambda item: float(item.get("strength") or 0), reverse=True)
    ml_priors = sorted(ml_priors, key=lambda item: float(item.get("strength") or 0), reverse=True)
    selected = conflicts[:item_limit]
    selected.extend(concrete[: max(0, item_limit - len(selected))])
    if len(selected) < item_limit and ml_priors:
        selected.append(ml_priors[0])
    return selected[:item_limit]


def compact_evidence_item_for_phase(item: dict[str, Any], text_limit: int, value_limit: int) -> dict[str, Any]:
    values = item.get("source_values")
    if isinstance(values, dict):
        source_values = {str(key): compact_text(value, value_limit) for key, value in list(values.items())[:4]}
    elif isinstance(values, list):
        source_values = [compact_text(value, value_limit) for value in values[:4]]
    else:
        source_values = compact_text(values, value_limit) if values not in ("", None) else ""
    return {
        "evidence_type": item.get("evidence_type", "context"),
        "source_fields": normalize_list(item.get("source_fields"))[:4],
        "source_values": source_values,
        "direction": item.get("direction", "context"),
        "strength": item.get("strength"),
        "description": compact_text(item.get("description"), text_limit),
    }


def compact_model_result_for_prompt(result: dict[str, Any]) -> dict[str, Any]:
    compact: dict[str, Any] = {
        "verdict": result.get("verdict"),
        "score": result.get("score"),
        "risk_level": result.get("risk_level"),
        "confidence": result.get("confidence"),
        "arguments": [compact_text(item, 160) for item in normalize_list(result.get("arguments"))[:3]],
        "evidence_refs": normalize_list(result.get("evidence_refs"))[:4],
        "omissions": [compact_text(item, 120) for item in normalize_list(result.get("omissions"))[:4]],
        "contradictions": [compact_text(item, 140) for item in normalize_list(result.get("contradictions"))[:3]],
        "evidence_chain": [compact_text(item, 180) for item in normalize_list(result.get("evidence_chain"))[:3]],
        "feature_relations": [compact_text(item, 180) for item in normalize_list(result.get("feature_relations"))[:2]],
    }
    for key, limit in {
        "question": 180,
        "answer": 220,
        "accepted_challenges": 140,
        "rejected_challenges": 140,
        "accepted_corrections": 140,
        "discarded_claims": 140,
    }.items():
        value = result.get(key)
        if isinstance(value, list):
            compact[key] = [compact_text(item, limit) for item in value[:3]]
        elif value not in (None, ""):
            compact[key] = compact_text(value, limit)
    return compact


def compact_model_result_for_rebuttal(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": result.get("verdict"),
        "score": result.get("score"),
        "risk_level": result.get("risk_level"),
        "confidence": result.get("confidence"),
        "arguments": [compact_text(item, 110) for item in normalize_list(result.get("arguments"))[:2]],
        "evidence_refs": normalize_list(result.get("evidence_refs"))[:3],
        "omissions": [compact_text(item, 80) for item in normalize_list(result.get("omissions"))[:2]],
        "question": compact_text(result.get("question"), 120),
        "answer": compact_text(result.get("answer"), 140),
        "contradictions": [compact_text(item, 100) for item in normalize_list(result.get("contradictions"))[:2]],
        "evidence_chain": [compact_text(item, 120) for item in normalize_list(result.get("evidence_chain"))[:2]],
    }


def compact_model_result_for_closing(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "verdict": result.get("verdict"),
        "score": result.get("score"),
        "risk_level": result.get("risk_level"),
        "confidence": result.get("confidence"),
        "arguments": [compact_text(item, 105) for item in normalize_list(result.get("arguments"))[:2]],
        "evidence_refs": normalize_list(result.get("evidence_refs"))[:3],
        "accepted_corrections": [
            compact_text(item, 80) for item in normalize_list(result.get("accepted_corrections"))[:2]
        ],
        "discarded_claims": [
            compact_text(item, 80) for item in normalize_list(result.get("discarded_claims"))[:2]
        ],
        "contradictions": [compact_text(item, 90) for item in normalize_list(result.get("contradictions"))[:2]],
        "evidence_chain": [compact_text(item, 105) for item in normalize_list(result.get("evidence_chain"))[:2]],
    }


def compact_memory_for_prompt(memory: dict[str, Any]) -> dict[str, Any]:
    skill_contexts = memory.get("skill_contexts") if isinstance(memory.get("skill_contexts"), dict) else {}
    return {
        "evidence_summary": compact_evidence_summary(memory.get("evidence_summary", {})),
        "rag_context": compact_rag_context(memory.get("rag_context"), item_limit=3, content_limit=160),
        "skill_context": compact_skill_context(skill_contexts.get("directed_attack") or skill_contexts.get("initial")),
        "stage_summaries": memory.get("stage_summaries", [])[-3:],
    }


def compact_memory_for_rebuttal(memory: dict[str, Any]) -> dict[str, Any]:
    skill_contexts = memory.get("skill_contexts") if isinstance(memory.get("skill_contexts"), dict) else {}
    summaries = []
    for stage in memory.get("stage_summaries", [])[-2:]:
        positions = []
        for position in stage.get("positions", [])[:2]:
            positions.append(
                {
                    "model": position.get("model"),
                    "verdict": position.get("verdict"),
                    "score": position.get("score"),
                    "evidence_refs": normalize_list(position.get("evidence_refs"))[:3],
                }
            )
        summaries.append({"phase": stage.get("phase"), "round": stage.get("round"), "positions": positions})
    return {
        "rag_context": compact_rag_context(memory.get("rag_context"), item_limit=2, content_limit=120),
        "skill_context": compact_skill_context(skill_contexts.get("rebuttal")),
        "stage_summaries": summaries,
    }


def compact_memory_for_closing(memory: dict[str, Any]) -> dict[str, Any]:
    skill_contexts = memory.get("skill_contexts") if isinstance(memory.get("skill_contexts"), dict) else {}
    summaries = []
    for stage in memory.get("stage_summaries", [])[-2:]:
        positions = []
        for position in stage.get("positions", [])[:2]:
            positions.append(
                {
                    "model": position.get("model"),
                    "verdict": position.get("verdict"),
                    "score": position.get("score"),
                    "risk_level": position.get("risk_level"),
                    "evidence_refs": normalize_list(position.get("evidence_refs"))[:2],
                }
            )
        summaries.append({"phase": stage.get("phase"), "round": stage.get("round"), "positions": positions})
    return {
        "rag_context": compact_rag_context(memory.get("rag_context"), item_limit=3, content_limit=140),
        "skill_context": compact_skill_context(skill_contexts.get("closing")),
        "stage_summaries": summaries,
    }


def compact_rag_context(value: Any, item_limit: int = 4, content_limit: int = 180) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"enabled": False, "items": []}
    items = []
    raw_items = value.get("items")
    if not isinstance(raw_items, list):
        raw_items = []
    for item in raw_items[:item_limit]:
        if not isinstance(item, dict):
            continue
        items.append(
            {
                "source_type": item.get("source_type"),
                "source_name": compact_text(item.get("source_name"), 60),
                "title": compact_text(item.get("title"), 80),
                "similarity": item.get("similarity"),
                "content": compact_text(item.get("content"), content_limit),
            }
        )
    return {
        "enabled": bool(value.get("enabled", True)),
        "query": compact_text(value.get("query"), 160),
        "items": items,
    }


def compact_evidence_summary(summary: dict[str, Any]) -> dict[str, Any]:
    agents = []
    for item in summary.get("agents", [])[:4] if isinstance(summary, dict) else []:
        agents.append(
            {
                "agent": item.get("agent"),
                "claim": compact_text(item.get("claim"), 80),
                "score": item.get("score"),
                "confidence": item.get("confidence"),
                "key_evidence": [compact_text(text, 80) for text in normalize_list(item.get("key_evidence"))[:1]],
            }
        )
    return {"agents": agents}


def compact_plan_for_prompt(plan: dict[str, Any]) -> dict[str, Any]:
    opponent_snapshot = plan.get("opponent_snapshot")
    if isinstance(opponent_snapshot, dict):
        opponent_snapshot = compact_model_result_for_prompt(opponent_snapshot)
    else:
        opponent_snapshot = {}
    return {
        "attacker": plan.get("attacker"),
        "target": plan.get("target"),
        "instruction": compact_text(plan.get("instruction"), 180),
        "opponent_snapshot": opponent_snapshot,
        "target_claims": [compact_text(item, 140) for item in normalize_list(plan.get("target_claims"))[:3]],
        "insufficient_citations": normalize_list(plan.get("insufficient_citations"))[:4],
        "logic_jumps": [compact_text(item, 120) for item in normalize_list(plan.get("logic_jumps"))[:3]],
        "intelligence_contradictions": normalize_list(plan.get("intelligence_contradictions"))[:3],
        "required_evidence_ids": normalize_list(plan.get("required_evidence_ids"))[:4],
    }


def debate_context_summary(
    evidence_json: str,
    own: dict[str, Any],
    opponent: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    try:
        evidence = json.loads(evidence_json)
    except Exception:
        evidence = []
    if not isinstance(evidence, list):
        evidence = []

    malicious: list[dict[str, Any]] = []
    benign: list[dict[str, Any]] = []
    gaps: list[str] = []
    agents: list[dict[str, Any]] = []
    llm_reviews: list[dict[str, Any]] = []
    llm_rule_disagreements: list[dict[str, Any]] = []
    score_review_disagreements: list[dict[str, Any]] = []
    for block in evidence:
        if not isinstance(block, dict):
            continue
        agent = block.get("agent")
        agents.append(
            {
                "agent": agent,
                "score": block.get("score"),
                "confidence": block.get("confidence"),
                "claim": compact_text(block.get("claim"), 100),
            }
        )
        review = block.get("llm_independent_review")
        if isinstance(review, dict) and review:
            llm_reviews.append(
                {
                    "agent": agent,
                    "review_verdict": review.get("review_verdict"),
                    "review_reason": compact_text(review.get("review_reason"), 120),
                    "rule_alignment": review.get("rule_alignment"),
                    "rule_difference": compact_text(review.get("rule_difference"), 120),
                    "summary": compact_text(review.get("summary"), 120),
                }
            )
        disagreement = block.get("llm_rule_disagreement")
        if isinstance(disagreement, dict) and disagreement:
            llm_rule_disagreements.append(
                {
                    "agent": agent,
                    "rule_verdict": disagreement.get("rule_verdict"),
                    "llm_review_verdict": disagreement.get("llm_review_verdict"),
                    "reason": compact_text(disagreement.get("reason"), 120),
                    "debate_focus": compact_text(disagreement.get("debate_focus"), 120),
                }
            )
        score_disagreement = block.get("score_review_disagreement")
        if isinstance(score_disagreement, dict) and score_disagreement:
            score_review_disagreements.append(
                {
                    "agent": agent,
                    "score_verdict": score_disagreement.get("score_verdict"),
                    "llm_review_verdict": score_disagreement.get("llm_review_verdict"),
                    "score": score_disagreement.get("score"),
                    "reason": compact_text(score_disagreement.get("reason"), 120),
                    "debate_focus": compact_text(score_disagreement.get("debate_focus"), 120),
                }
            )
        gaps.extend(str(item) for item in normalize_list(block.get("missing_fields"))[:4])
        for item in block.get("evidence_items", []):
            if not isinstance(item, dict):
                continue
            row = {
                "agent": agent,
                "type": item.get("evidence_type"),
                "direction": item.get("direction"),
                "strength": item.get("strength"),
                "fields": normalize_list(item.get("source_fields"))[:4],
                "description": compact_text(item.get("description"), 120),
            }
            if item.get("direction") == "supports_malicious":
                malicious.append(row)
            elif item.get("direction") == "supports_benign":
                benign.append(row)

    malicious = sorted(malicious, key=lambda item: float(item.get("strength") or 0), reverse=True)[:5]
    benign = sorted(benign, key=lambda item: float(item.get("strength") or 0), reverse=True)[:4]
    return {
        "agent_scores": agents,
        "strong_malicious_evidence": malicious,
        "benign_or_counter_evidence": benign,
        "llm_independent_reviews": llm_reviews[:4],
        "llm_rule_disagreements": llm_rule_disagreements[:4],
        "score_review_disagreements": score_review_disagreements[:4],
        "missing_fields": sorted(set(gaps))[:8],
        "own_position": {
            "verdict": own.get("verdict"),
            "score": own.get("score"),
            "risk_level": own.get("risk_level"),
            "evidence_refs": normalize_list(own.get("evidence_refs"))[:4],
        },
        "opponent_position": {
            "verdict": opponent.get("verdict"),
            "score": opponent.get("score"),
            "risk_level": opponent.get("risk_level"),
            "evidence_refs": normalize_list(opponent.get("evidence_refs"))[:4],
        },
        "must_check": {
            "target_claims": normalize_list(plan.get("target_claims"))[:3],
            "insufficient_citations": normalize_list(plan.get("insufficient_citations"))[:4],
            "logic_jumps": normalize_list(plan.get("logic_jumps"))[:3],
            "contradictions": normalize_list(plan.get("intelligence_contradictions"))[:3],
            "score_review_disagreements": score_review_disagreements[:4],
        },
    }


def compact_text(value: Any, limit: int) -> str:
    if value is None:
        return ""
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[: limit - 3] + "..."


def strip_model_thinking_text(value: Any) -> str:
    text = "" if value is None else str(value)
    text = re.sub(r"<think\b[^>]*>.*?</think>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    if re.search(r"<think\b[^>]*>", text, flags=re.IGNORECASE):
        brace_index = text.find("{")
        if brace_index >= 0:
            text = text[brace_index:]
        else:
            text = re.sub(r"<think\b[^>]*>.*", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"</?think\b[^>]*>", " ", text, flags=re.IGNORECASE)
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1].strip()
    return text.strip()


class ModelProvider:
    def __init__(self, name: str, backend: str, model: str, api_url: str = "", api_key: str = ""):
        self.name = name
        self.backend = backend
        self.model = model
        self.api_url = api_url
        self.api_key = api_key

    def generate(self, system_prompt: str, user_prompt: str, max_tokens: int = 160) -> dict[str, Any]:
        started = time.perf_counter()
        usage = {}
        context_tokens = self.context_token_limit()
        system_prompt, user_prompt = fit_prompt_for_context(
            system_prompt,
            user_prompt,
            context_tokens=context_tokens,
        )
        max_tokens = bounded_completion_tokens(
            system_prompt,
            user_prompt,
            max_tokens,
            context_tokens=context_tokens,
        )
        if self.backend == "local_qwen":
            raw = qwen_generate(system_prompt, user_prompt, max_new_tokens=max_tokens, model_id=self.model)
        elif self.backend == "openai_compatible":
            raw, usage = self._http_generate(system_prompt, user_prompt, max_tokens)
        else:
            raw = ""
        raw = strip_model_thinking_text(raw)
        return {
            "raw_text": raw,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "prompt_tokens": int(usage.get("prompt_tokens") or estimate_tokens(system_prompt + user_prompt)),
            "completion_tokens": int(usage.get("completion_tokens") or estimate_tokens(raw)),
        }

    def context_token_limit(self) -> int:
        suffix = self.name.upper().removeprefix("MODEL_")
        specific_key = f"MALAPP_MODEL_{suffix}_CONTEXT_TOKENS"
        specific_value = os.getenv(specific_key, "").strip()
        if specific_value:
            try:
                return max(1024, int(specific_value))
            except ValueError:
                pass
        model_hint = f"{self.name} {self.model} {self.api_url}".lower()
        if "model_b" in model_hint or "malapp-model-b" in model_hint:
            return int(os.getenv("MALAPP_MODEL_B_CONTEXT_TOKENS", "2048") or "2048")
        return int(os.getenv("MALAPP_MODEL_CONTEXT_TOKENS", "4096") or "4096")

    def _http_generate(self, system_prompt: str, user_prompt: str, max_tokens: int) -> tuple[str, dict[str, Any]]:
        if self.context_token_limit() <= 4096 or self.name == "model_b":
            no_think_guard = (
                "/no_think\n"
                "禁止输出 <think>、思考过程、分析草稿或 Markdown。"
                "第一字符必须是 {，最后字符必须是 }。"
            )
            system_prompt = no_think_guard + "\n" + system_prompt
            user_prompt = no_think_guard + "\n" + user_prompt
        base_payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "max_tokens": max_tokens,
            "chat_template_kwargs": {"enable_thinking": False},
        }
        payload_dict = dict(base_payload)
        json_mode_enabled = os.getenv("MALAPP_MODEL_JSON_MODE", "1").strip().lower() in {"1", "true", "yes", "on"}
        # Even short-context servers benefit from native JSON mode.  Older
        # servers that reject this field are handled by the request variants.
        if json_mode_enabled:
            payload_dict["response_format"] = {"type": "json_object"}
        timeout_seconds = max(30.0, float(os.getenv("MALAPP_MODEL_API_TIMEOUT", "600")))

        retry_payloads = [payload_dict]
        if fast_model_retry_enabled():
            # 快速模式只保留一次兼容回退，避免同一长提示词反复请求导致单样本耗时暴涨。
            compat_payload = dict(base_payload)
            compat_payload.pop("response_format", None)
            compat_payload.pop("chat_template_kwargs", None)
            if compat_payload != payload_dict:
                retry_payloads.append(compat_payload)
        else:
            if "response_format" in payload_dict:
                retry_payloads.append(dict(base_payload))
            if "chat_template_kwargs" in base_payload:
                plain_payload = dict(base_payload)
                plain_payload.pop("chat_template_kwargs", None)
                retry_payloads.append(plain_payload)
            minimal_payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": max_tokens,
                "temperature": 0,
            }
            retry_payloads.append(minimal_payload)

        last_error = ""
        errors: list[str] = []
        default_transport_retries = "1" if fast_model_retry_enabled() else "3"
        transport_retries = max(1, min(int(os.getenv("MALAPP_MODEL_TRANSPORT_RETRIES", default_transport_retries) or default_transport_retries), 5))
        retry_sleep_seconds = max(0.0, min(float(os.getenv("MALAPP_MODEL_RETRY_SLEEP_SECONDS", "1.5") or "1.5"), 10.0))

        for index, current_payload in enumerate(retry_payloads):
            payload = json.dumps(current_payload, ensure_ascii=False).encode("utf-8")
            request = urllib.request.Request(
                self.api_url.rstrip("/") + "/chat/completions",
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
                },
                method="POST",
            )
            for transport_try in range(transport_retries):
                try:
                    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                        data = json.loads(response.read().decode("utf-8"))
                    message = data["choices"][0].get("message", {})
                    content = message.get("content") or message.get("reasoning_content") or ""
                    return strip_model_thinking_text(content), data.get("usage", {})
                except urllib.error.HTTPError as exc:
                    body = exc.read().decode("utf-8", "replace")
                    last_error = (
                        f"{self.model}@{self.api_url} attempt {index + 1}/{len(retry_payloads)} "
                        f"HTTP {exc.code}: {compact_text(body, 600)}"
                    )
                    errors.append(last_error)
                    if exc.code not in {400, 413, 422}:
                        raise RuntimeError(last_error) from exc
                    break
                except urllib.error.URLError as exc:
                    last_error = f"{self.model}@{self.api_url} attempt {index + 1}/{len(retry_payloads)} URL error: {exc}"
                    errors.append(last_error)
                    if transport_try >= transport_retries - 1:
                        raise RuntimeError(last_error) from exc
                    time.sleep(retry_sleep_seconds * (transport_try + 1))
                except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError) as exc:
                    last_error = (
                        f"{self.model}@{self.api_url} attempt {index + 1}/{len(retry_payloads)} "
                        f"transport {transport_try + 1}/{transport_retries} connection closed: {exc}"
                    )
                    errors.append(last_error)
                    if transport_try < transport_retries - 1:
                        time.sleep(retry_sleep_seconds * (transport_try + 1))
                        continue
                    break

        short_payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "user",
                    "content": (
                        system_prompt[:900]
                        + "\n\n"
                        + user_prompt[:1800]
                        + "\n\n请严格输出 JSON 对象。"
                    ),
                }
            ],
            "max_tokens": min(max_tokens, 128),
            "temperature": 0,
        }
        default_compact_retries = "1" if fast_model_retry_enabled() else "3"
        compact_transport_retries = max(1, min(int(os.getenv("MALAPP_MODEL_COMPACT_TRANSPORT_RETRIES", default_compact_retries) or default_compact_retries), 5))
        try:
            short_request = urllib.request.Request(
                    self.api_url.rstrip("/") + "/chat/completions",
                    data=json.dumps(short_payload, ensure_ascii=False).encode("utf-8"),
                    headers={
                        "Content-Type": "application/json",
                        **({"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}),
                    },
                    method="POST",
                )
            for transport_try in range(compact_transport_retries):
                try:
                    with urllib.request.urlopen(short_request, timeout=timeout_seconds) as response:
                        data = json.loads(response.read().decode("utf-8"))
                    message = data["choices"][0].get("message", {})
                    content = message.get("content") or message.get("reasoning_content") or ""
                    return strip_model_thinking_text(content), data.get("usage", {})
                except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError) as exc:
                    errors.append(
                        f"{self.model}@{self.api_url} compact retry transport "
                        f"{transport_try + 1}/{compact_transport_retries} connection closed: {exc}"
                    )
                    if transport_try >= compact_transport_retries - 1:
                        raise
                    time.sleep(retry_sleep_seconds * (transport_try + 1))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            errors.append(f"{self.model}@{self.api_url} compact retry HTTP {exc.code}: {compact_text(body, 600)}")
            raise RuntimeError(
                "; ".join(errors[-5:]) or last_error
            ) from exc
        except urllib.error.URLError as exc:
            errors.append(f"{self.model}@{self.api_url} compact retry URL error: {exc}")
            raise RuntimeError("; ".join(errors[-5:]) or last_error) from exc
        except (http.client.RemoteDisconnected, ConnectionResetError, TimeoutError) as exc:
            errors.append(f"{self.model}@{self.api_url} compact retry connection closed: {exc}")
            raise RuntimeError("; ".join(errors[-5:]) or last_error) from exc

    def public_config(self) -> dict[str, Any]:
        return {"backend": self.backend, "model": self.model, "api_url": self.api_url}


def build_provider(name: str, config: dict[str, Any]) -> ModelProvider:
    item = config.get(name, {}) if isinstance(config.get(name), dict) else {}
    suffix = "A" if name == "model_a" else "B"
    api_url = str(item.get("api_url") or os.getenv(f"MALAPP_MODEL_{suffix}_API_URL", ""))
    model = str(
        item.get("model")
        or os.getenv(f"MALAPP_MODEL_{suffix}_MODEL", "")
        or os.getenv("MALAPP_QWEN_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
    )
    api_key = str(item.get("api_key") or os.getenv(f"MALAPP_MODEL_{suffix}_API_KEY", ""))
    backend = str(
        item.get("backend")
        or ("openai_compatible" if api_url else "local_qwen" if local_qwen_enabled() else "rule")
    )
    return ModelProvider(name, backend, model, api_url, api_key)


def initial_report(
    provider: ModelProvider,
    model_name: str,
    role: dict[str, str],
    evidence_json: str,
    evidence: list[dict[str, Any]],
    rag_context: dict[str, Any] | None = None,
    skill_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    fallback = fallback_initial(model_name, role, evidence)
    role_focus = (
        "你是风险优先复核模型，重点检查涉诈业务标签、黑产家族、网络威胁、仿冒与漏报风险；"
        "但仍需解释为什么这些风险证据足以覆盖可能的反向证据。"
        if model_name == "model_b"
        else
        "你是保守证据复核模型，重点检查证据交叉印证、反例、缺失字段与误报风险；"
        "但不能因为存在缺失字段就忽略已经成链的高危证据。"
    )
    format_guard = (
        "Output contract: return one compact JSON object only. "
        "Keep arguments 4 items, omissions <=4 items, evidence_refs 3-4 items, "
        "contradictions <=3 items, evidence_chain 4 items, feature_relations 3 items. "
        "Each Chinese sentence should be 45-120 Chinese characters. "
        "Use normal Chinese punctuation only. Do not output stray quotes, duplicated punctuation, "
        "empty separators, markdown, or repeated keys. Finish the JSON object with }.\n"
    )
    model_b_guard = (
        "Risk-priority initial testimony is not a question stage. It must be a declarative risk summary based only on the provided evidence blocks. "
        "Do not write question sentences such as 该样本是否应被判定为恶意、该应用是否应被判定为恶意、"
        "是否属于恶意行为、是否应判为恶意、是否需要判定为恶意、请核验、请判断. "
        "Every argument must contain conclusion, evidence combination, and risk meaning. "
        "Independently summarize the malicious tendency, risk level, main supporting features, "
        "and remaining uncertainty; it must not output a single question as its initial judgement. "
    ) if model_name == "model_b" else ""
    prompt = (
        format_guard
        + model_b_guard
        + "Independently judge the compressed evidence. This is the first-stage independent initial testimony: you do not know the other model's judgement yet. Do not mention 模型甲、模型乙、对方、质疑、反驳、我方修正判断、针对模型甲、针对模型乙, and do not ask another model to explain anything. Return only valid JSON. "
        + "Required keys: verdict, score, risk_level, arguments, omissions, evidence_refs, "
        + "confidence, contradictions, evidence_chain, feature_relations. "
        + "arguments, evidence_chain, and feature_relations must be summary statements, not questions. They must describe your own understanding of the evidence blocks and your own conclusion. "
        + "Do not write process/meta sentences such as 仅依据当前输入的 EvidenceBlock 独立形成初判, "
        + "该阶段仅依据输入证据块形成独立陈述, or 输入证据块 -> 特征组合复核. "
        + "Instead, write inference basis: concrete evidence source -> feature relation -> why it supports malicious/suspicious/benign. "
        + "Never write sentences like 该样本是否应被判定为恶意, 该应用是否应被判定为恶意, "
        + "是否为恶意样本, 是否属于恶意行为, or 关键证据支持当前判断. "
        + "For risk-priority judgement, use a risk-priority summary style: summarize what the evidence supports, "
        + "which fields reinforce the risk, and why the verdict follows. "
        + "verdict enum: malicious, suspicious, benign. risk_level enum: high, medium, low. "
        + "score and confidence are decimals from 0 to 1. All list fields must be JSON string arrays. "
        + f"Choose evidence_refs from {evidence_ids(evidence)} and cite at least two non-xgboost evidence blocks. "
        + f"Role strategy: {role['strategy']}. Role focus: {role_focus} Do not copy rule fallback conclusions. "
        + "Your score is your own malicious tendency judgement. Do not copy xgboost_prior, "
        + "xgboost_domain_probability, or any single agent score as your score. "
        + "If your score is close to a machine-learning probability, arguments must explain which concrete "
        + "non-XGBoost evidence makes you agree with it. "
        + "If evidence_type=evidence_conflict appears, you must explicitly decide whether the current "
        + "sample should follow the concrete domain evidence, treat XGBoost only as a weak prior, "
        + "or remain suspicious pending more fields. Explain why. "
        + "Each agent block contains two kinds of information: the agent's independent review of raw features "
        + "and the deterministic evidence extracted by tools. Do not output these internal schema names. "
        + "For each cited agent, compare the semantic conclusion and the concrete evidence items. "
        + "If they are consistent, explain which raw fields and extracted evidence reinforce each other. "
        + "If they differ, describe the conflict in Chinese without naming internal fields, then give an integrated judgement; "
        + "do not simply choose either side. "
        + "Do not output internal words such as agent_judgement, rule_judgement, llm_rule_disagreement, "
        + "rule_judge, llm_ru, question, answer, present, or rule_judge. "
        + "Use concrete field names, evidence strengths, missing fields, and feature combinations. "
        + "arguments must explain 根据哪个智能体的哪类证据形成结论, and why the score is higher or lower. "
        + "evidence_chain must use the pattern 证据来源 -> 特征组合 -> 风险含义 -> 初判结论. "
        + "feature_relations must describe how two or more fields reinforce or weaken each other. "
        + "contradictions must identify conflicts such as benign signature versus malicious network/business evidence. "
        + "If RAG context is provided, use it only as historical cases, family/IOC background, official-asset reference, "
        + "or judgement-spec guidance. Do not treat RAG facts as current sample hits unless current evidence also contains them. "
        + "Do not output placeholder text. "
        + "Use Skill context as the progressive-disclosure instruction for current stage; it defines agent duties, "
        + "field boundaries, score meaning, and debate contract. "
        + f"Skill context: {json.dumps(compact_skill_context(skill_context), ensure_ascii=False, separators=(',', ':'))}. "
        + f"Retrieved RAG context: {json.dumps(compact_rag_context(rag_context), ensure_ascii=False, separators=(',', ':'))}. "
        + f"Compressed evidence: {evidence_json}"
    )
    return invoke(provider, role, prompt, fallback, "initial_testimony")

def build_attack_plan(attacker: str, opponent: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    opponent_refs = {str(item) for item in opponent.get("evidence_refs", [])}
    all_refs = {str(item.get("agent")) for item in evidence if item.get("agent")}
    missing_refs = sorted(all_refs - opponent_refs)
    contradictions = []
    explicit_conflicts = []
    score_review_conflicts = []
    opponent_score = float(opponent.get("score", 0))
    for item in evidence:
        score = float(item.get("score", 0))
        score_conflict = item.get("score_review_disagreement")
        if isinstance(score_conflict, dict) and score_conflict:
            score_review_conflicts.append(
                {
                    "agent": item.get("agent"),
                    "score_verdict": score_conflict.get("score_verdict"),
                    "llm_review_verdict": score_conflict.get("llm_review_verdict"),
                    "score": score_conflict.get("score"),
                    "reason": compact_text(score_conflict.get("reason"), 180),
                    "question": compact_text(score_conflict.get("debate_focus"), 180),
                }
            )
        for evidence_item in normalize_list(item.get("evidence_items")):
            if isinstance(evidence_item, dict) and evidence_item.get("evidence_type") == "evidence_conflict":
                explicit_conflicts.append(
                    {
                        "agent": item.get("agent"),
                        "reason": compact_text(evidence_item.get("description"), 180),
                        "trust_hint": compact_text(evidence_item.get("trust_hint"), 180),
                        "question": compact_text(evidence_item.get("debate_question"), 180),
                    }
                )
        if abs(score - opponent_score) >= 0.35:
            contradictions.append(
                {
                    "agent": item.get("agent"),
                    "evidence_score": score,
                    "opponent_score": opponent_score,
                    "reason": "证据块风险分与对方结论差异较大",
                }
            )
    return {
        "attacker": attacker,
        "target": opponent.get("role") or opponent.get("model") or "",
        "opponent_snapshot": compact_model_result_for_prompt(opponent),
        "target_claims": list(opponent.get("arguments", []))[:3],
        "insufficient_citations": missing_refs,
        "logic_jumps": [
            "结论是否由单一证据直接跳转",
            "风险等级是否与引用证据强度一致",
            "是否忽略 missing_fields 与反例",
            "机器学习先验是否覆盖了相反方向的领域证据",
        ],
        "evidence_conflicts": explicit_conflicts[:4],
        "score_review_conflicts": score_review_conflicts[:4],
        "intelligence_contradictions": (score_review_conflicts + explicit_conflicts + contradictions)[:4],
    }


def debate_turn(
    provider: ModelProvider,
    role: dict[str, str],
    turn_type: str,
    evidence_json: str,
    own: dict[str, Any],
    opponent: dict[str, Any],
    memory: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    fallback = fallback_turn(turn_type, own, opponent, plan)
    plan = compact_plan_for_prompt(plan)
    context_summary = debate_context_summary(evidence_json, own, opponent, plan)
    is_rebuttal = turn_type in {"evidence_rebuttal", "role_reversal_rebuttal"}
    if is_rebuttal:
        own = compact_model_result_for_rebuttal(own)
        opponent = compact_model_result_for_rebuttal(opponent)
        memory = compact_memory_for_rebuttal(memory)
    else:
        own = compact_model_result_for_prompt(own)
        opponent = compact_model_result_for_prompt(opponent)
        memory = compact_memory_for_prompt(memory)
    format_guard = (
        "Output contract: return one compact JSON object only. "
        "Keep arguments 3-4 items, evidence_refs 3-4 items, accepted_challenges <=2 items, "
        "rejected_challenges <=2 items, omissions <=3 items, contradictions <=3 items, "
        "evidence_chain 3-4 items, feature_relations 2-3 items. "
        "question should be 70-140 Chinese characters. answer should be 180-360 Chinese characters. "
        "Use normal Chinese punctuation only. Do not output stray quotes, duplicated punctuation, "
        "empty separators, markdown, or repeated keys. Finish immediately after the final }.\n"
    )
    attack_instruction = (
        "Challenge mode: hide your own confidence. Attack the opponent's logic. "
        "First read Plan.opponent_snapshot and Opponent position. "
        "Your question must directly target a claim, verdict, score, risk_level, evidence_chain, "
        "feature_relation, contradiction, or omission that the opponent actually stated. "
        "Do not challenge a position the opponent did not take. "
        "question must point to one concrete flaw from the opponent's claim: missing evidence, logic jump, "
        "feature conflict, unverified field, or misuse of a high/low score. "
        "answer must explicitly say: 根据哪个智能体的哪条证据提出质疑、该证据和对方结论哪里冲突、"
        "如果该质疑成立会怎样改变风险等级或结论. Cite exact evidence_refs. "
        "Do not ask generic questions such as 是否判定为恶意样本. "
        "If attacking a high-risk verdict, cite benign/counter evidence or missing fields. "
        "If attacking a low-risk verdict, cite strong malicious evidence or omitted threat chains. "
    )
    rebuttal_instruction = (
        "Rebuttal mode: respond to the opponent's exact challenge. "
        "State whether the challenge is accepted, partially accepted, or rejected, then explain why. "
        "answer must include one added evidence item, one corrected inference, one accepted/rejected point, "
        "and one remaining uncertainty. Explain 根据哪些四智能体证据或中文解释支撑本方反驳. "
        "Do not merely repeat the original verdict. "
        "Do not copy the question into answer. The answer must be a complete evidence-based rebuttal, "
        "not another question. "
    )
    prompt = (
        format_guard
        + "Return only valid JSON for this debate turn. "
        + "Required keys: question, answer, score, verdict, risk_level, confidence, "
        + "arguments, evidence_refs, accepted_challenges, rejected_challenges, omissions, "
        + "contradictions, evidence_chain, feature_relations. "
        + "Use Chinese natural language inside string values. "
        + "Question and answer must cite concrete evidence fields or missing fields. "
        + "score must be your updated malicious tendency after this debate turn; do not copy "
        + "xgboost_prior, xgboost_domain_probability, own.score, or opponent.score without explaining "
        + "the concrete evidence-based adjustment. "
        + "When Plan.evidence_conflicts is not empty, question or answer must discuss at least one "
        + "conflict and state which side should be trusted now: concrete domain evidence, machine-learning "
        + "prior, or suspicious pending additional fields. "
        + "When evidence contains both an agent raw-feature review and deterministic tool evidence, question or answer must compare "
        + "their semantic conclusions and explain whether they reinforce each other or need integration. "
        + "Do not output internal words such as agent_judgement, rule_judgement, llm_rule_disagreement, "
        + "rule_judge, llm_ru, question, answer, or present. "
        + "When score_review_disagreement exists, explicitly discuss why the public malicious probability and the raw-feature "
        + "agent judgement differ, and whether the difference should lower, keep, or raise the current risk level. "
        + "If Plan.opponent_snapshot is present, challenge only content present in that snapshot or Opponent position. "
        + "feature_relations must connect at least two evidence fields or explain why such connection is missing. "
        + (rebuttal_instruction if is_rebuttal else attack_instruction)
        + f"Phase: {turn_type}. Plan: {json.dumps(plan, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Integrated context summary: {json.dumps(context_summary, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Own position: {json.dumps(own, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Opponent position: {json.dumps(opponent, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Compressed memory: {json.dumps(memory, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Compressed evidence: {evidence_json}"
    )
    return invoke(provider, role, prompt, fallback, turn_type)


def closing_report(
    provider: ModelProvider,
    role: dict[str, str],
    evidence_json: str,
    initial: dict[str, Any],
    latest: dict[str, Any],
    memory: dict[str, Any],
) -> dict[str, Any]:
    fallback = fallback_closing(initial, latest, memory)
    initial = compact_model_result_for_closing(initial)
    latest = compact_model_result_for_closing(latest)
    memory = compact_memory_for_closing(memory)
    format_guard = (
        "Output contract: return one compact JSON object only. "
        "Keep arguments 2 items, evidence_refs 2-3 items, accepted_corrections <=2 items, "
        "discarded_claims <=2 items, omissions <=2 items, contradictions <=2 items, "
        "evidence_chain 2 items, feature_relations 1 item. "
        "Each Chinese sentence must be concise, under 40 Chinese characters. "
        "Use normal Chinese punctuation only. Do not output stray quotes, duplicated punctuation, "
        "empty separators, markdown, or repeated keys. Finish the JSON object with }.\n"
    )
    prompt = (
        format_guard
        + "Return only valid JSON for the closing statement. "
        + "Required keys: verdict, score, risk_level, confidence, arguments, evidence_refs, "
        + "accepted_corrections, discarded_claims, omissions, contradictions, evidence_chain, feature_relations. "
        + "Use Chinese natural language inside string values. "
        + "Final arguments must cite concrete evidence blocks, field values, and debate corrections. Be brief. "
        + "Closing must integrate both the agent raw-feature review and deterministic tool evidence. "
        + "If they disagree, state how the conflict was resolved in the final score without outputting internal field names. "
        + "If any score_review_disagreement exists, explain whether the malicious probability or the raw-feature "
        + "agent judgement is more credible and why. "
        + f"Role strategy: {role['strategy']}. "
        + f"Initial position: {json.dumps(initial, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Latest position: {json.dumps(latest, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Compressed debate memory: {json.dumps(memory, ensure_ascii=False, separators=(',', ':'))}. "
        + f"Compressed evidence: {evidence_json}"
    )
    return invoke(provider, role, prompt, fallback, "closing_statement")

def invoke(
    provider: ModelProvider,
    role: dict[str, str],
    prompt: str,
    fallback: dict[str, Any],
    phase: str,
) -> dict[str, Any]:
    if provider.backend == "rule":
        if llm_rule_fallback_disabled():
            raise RuntimeError("未配置可用的大模型服务：本地 Qwen 未启用，且未配置服务器模型 API；规则模式已禁用")
        return with_metrics(fallback, "rule", phase, prompt)
    try:
        system_prompt = f"你是{role['name']}。{role['strategy']} 必须只输出一个合法 JSON 对象。"
        if phase == "initial_testimony":
            system_prompt += (
                " 当前阶段是第一阶段独立初判，只能根据输入 EvidenceBlock 写陈述性总结。"
                " 你不知道另一模型判断，禁止出现模型甲、模型乙、对方、质疑、反驳、"
                "我方修正判断、针对模型甲、针对模型乙，也禁止输出问句。"
            )
        generated = provider.generate(
            system_prompt,
            prompt,
            max_tokens=model_max_tokens_for_phase(phase, provider.name),
        )
        parsed = parse_model_json(generated["raw_text"])
        if phase == "initial_testimony":
            parsed = coerce_initial_schema_values(parsed)
        elif phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"}:
            parsed = coerce_turn_schema_values(parsed)
        elif phase == "closing_statement":
            parsed = coerce_closing_schema_values(parsed)
        schema_completed_fields: list[str] = []
        if phase == "initial_testimony" and usable_initial_output(parsed) and not valid_initial_schema(parsed):
            parsed, schema_completed_fields = complete_initial_schema(parsed, fallback)
        elif phase == "initial_testimony" and not valid_initial_schema(parsed):
            recovered = recover_initial_output_from_raw(generated["raw_text"], fallback)
            if usable_initial_output(recovered):
                parsed, schema_completed_fields = complete_initial_schema(recovered, fallback)
        # The bounded repair loop below is the normal recovery path.  Keep the
        # legacy full re-generation opt-in only, so one phase never exceeds the
        # configured two repair attempts.
        if (
            phase == "initial_testimony"
            and not valid_initial_schema(parsed)
            and full_schema_retry_enabled()
            and schema_repair_max_attempts() == 0
        ):
            retried = provider.generate(
                "You are a strict JSON generator. Return only one valid JSON object.",
                build_initial_retry_prompt(prompt),
                max_tokens=model_repair_tokens_for_phase(phase),
            )
            retried_parsed = coerce_initial_schema_values(parse_model_json(retried["raw_text"]))
            if usable_initial_output(retried_parsed):
                retried_parsed, schema_completed_fields = complete_initial_schema(
                    retried_parsed,
                    fallback,
                )
                generated = merge_generated_metrics(generated, retried)
                parsed = retried_parsed
        if phase == "initial_testimony" and not valid_initial_schema(parsed):
            for _repair_attempt in range(schema_repair_max_attempts()):
                validation_error = schema_validation_failure_reason(phase, parsed)
                repaired = provider.generate(
                    "你是 JSON 格式修复器。只输出修复后的合法 JSON，不要解释。",
                    build_json_repair_prompt(generated["raw_text"], validation_error),
                    max_tokens=model_repair_tokens_for_phase(phase),
                )
                generated = merge_generated_metrics(generated, repaired)
                repaired_parsed = coerce_initial_schema_values(parse_model_json(repaired["raw_text"]))
                if usable_initial_output(repaired_parsed):
                    repaired_parsed, completed = complete_initial_schema(repaired_parsed, fallback)
                    schema_completed_fields = list(dict.fromkeys(schema_completed_fields + completed))
                parsed = repaired_parsed
                if valid_initial_schema(parsed):
                    break
        if phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"} and usable_turn_output(parsed) and not valid_turn_schema(parsed):
            parsed, schema_completed_fields = complete_turn_schema(parsed, fallback)
        elif phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"} and not valid_turn_schema(parsed):
            recovered = recover_turn_output_from_raw(generated["raw_text"], fallback)
            if usable_turn_output(recovered):
                parsed, schema_completed_fields = complete_turn_schema(recovered, fallback)
        if (
            phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"}
            and not valid_turn_schema(parsed)
            and full_schema_retry_enabled()
            and schema_repair_max_attempts() == 0
        ):
            retried = provider.generate(
                "你是严格 JSON 生成器。只输出一个合法 JSON 对象，不要 Markdown。",
                build_turn_retry_prompt(prompt, phase),
                max_tokens=model_repair_tokens_for_phase(phase),
            )
            retried_parsed = coerce_turn_schema_values(parse_model_json(retried["raw_text"]))
            if usable_turn_output(retried_parsed):
                retried_parsed, schema_completed_fields = complete_turn_schema(retried_parsed, fallback)
                generated = merge_generated_metrics(generated, retried)
                parsed = retried_parsed
        if phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"} and not valid_turn_schema(parsed):
            for _repair_attempt in range(schema_repair_max_attempts()):
                validation_error = schema_validation_failure_reason(phase, parsed)
                repaired = provider.generate(
                    "你是 JSON 格式修复器。只输出修复后的合法 JSON，不要解释。",
                    build_turn_repair_prompt(generated["raw_text"], phase, validation_error),
                    max_tokens=model_repair_tokens_for_phase(phase),
                )
                generated = merge_generated_metrics(generated, repaired)
                repaired_parsed = coerce_turn_schema_values(parse_model_json(repaired["raw_text"]))
                if usable_turn_output(repaired_parsed):
                    repaired_parsed, completed = complete_turn_schema(repaired_parsed, fallback)
                    schema_completed_fields = list(dict.fromkeys(schema_completed_fields + completed))
                parsed = repaired_parsed
                if valid_turn_schema(parsed):
                    break
        if phase == "closing_statement" and usable_closing_output(parsed) and not valid_closing_schema(parsed):
            parsed, schema_completed_fields = complete_closing_schema(parsed, fallback)
        elif (
            phase == "closing_statement"
            and not valid_closing_schema(parsed)
            and full_schema_retry_enabled()
            and schema_repair_max_attempts() == 0
        ):
            retried = provider.generate(
                "你是严格 JSON 生成器。只输出一个合法 JSON 对象，不要 Markdown。",
                build_closing_retry_prompt(prompt),
                max_tokens=model_repair_tokens_for_phase(phase),
            )
            retried_parsed = coerce_closing_schema_values(parse_model_json(retried["raw_text"]))
            if usable_closing_output(retried_parsed):
                retried_parsed, schema_completed_fields = complete_closing_schema(retried_parsed, fallback)
                generated = merge_generated_metrics(generated, retried)
                parsed = retried_parsed
        if phase == "closing_statement" and not valid_closing_schema(parsed):
            for _repair_attempt in range(schema_repair_max_attempts()):
                validation_error = schema_validation_failure_reason(phase, parsed)
                repaired = provider.generate(
                    "你是 JSON 格式修复器。只输出修复后的合法 JSON，不要解释。",
                    build_closing_repair_prompt(generated["raw_text"], validation_error),
                    max_tokens=model_repair_tokens_for_phase(phase),
                )
                generated = merge_generated_metrics(generated, repaired)
                repaired_parsed = coerce_closing_schema_values(parse_model_json(repaired["raw_text"]))
                if usable_closing_output(repaired_parsed):
                    repaired_parsed, completed = complete_closing_schema(repaired_parsed, fallback)
                    schema_completed_fields = list(dict.fromkeys(schema_completed_fields + completed))
                parsed = repaired_parsed
                if valid_closing_schema(parsed):
                    break
        if phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"} and not valid_turn_schema(parsed):
            completed, schema_completed_fields = complete_turn_schema(
                parsed if isinstance(parsed, dict) else {},
                fallback,
            )
            completed["validation_warning"] = "模型已完成本轮推理，但输出字段未完全符合协议，已按模型上下文补齐展示字段。"
            parsed = completed
        if phase == "closing_statement" and not valid_closing_schema(parsed):
            completed, schema_completed_fields = complete_closing_schema(
                parsed if isinstance(parsed, dict) else {},
                fallback,
            )
            completed["validation_warning"] = "模型已完成终审推理，但输出字段未完全符合协议，已按模型上下文补齐展示字段。"
            parsed = completed
        if phase == "initial_testimony" and not valid_initial_schema(parsed):
            completed, schema_completed_fields = complete_initial_schema(
                parsed if isinstance(parsed, dict) else {},
                fallback,
            )
            completed, sanitized_fields = sanitize_initial_report_text(completed, fallback, role)
            parsed = completed
            schema_completed_fields = list(
                dict.fromkeys(schema_completed_fields + sanitized_fields)
            )
            parsed["validation_warning"] = (
                "大模型已生成初判，但初判内容未完全满足独立陈述协议；"
                "程序已移除问句、对方视角和辩论阶段用语后再展示。"
            )
        if phase == "initial_testimony" and valid_initial_schema(parsed):
            parsed, sanitized_fields = sanitize_initial_report_text(parsed, fallback, role)
            if sanitized_fields:
                schema_completed_fields = list(
                    dict.fromkeys(schema_completed_fields + sanitized_fields)
                )
        if phase == "closing_statement" and not valid_closing_schema(parsed):
            dump_llm_validation_failure(provider, phase, generated, parsed)
            if llm_rule_fallback_disabled():
                raise RuntimeError(
                    f"{provider.backend} output did not satisfy debate schema at {phase}; "
                    "rule fallback is disabled"
            )
            result = with_metrics(fallback, f"{provider.backend}_invalid_fallback", phase, prompt)
            result["raw_text"] = generated["raw_text"]
            result["validation_warning"] = "模型终审输出未通过严格 JSON Schema，格式修复仍失败，已降级为规则结果。"
            result["latency_ms"] = generated["latency_ms"]
            result["prompt_tokens"] = generated["prompt_tokens"]
            result["completion_tokens"] = generated["completion_tokens"]
            return result
        if placeholder_model_output(parsed, generated["raw_text"], fallback, phase):
            dump_llm_validation_failure(provider, phase, generated, parsed)
            if llm_rule_fallback_disabled():
                raise RuntimeError(
                    f"{provider.backend} output did not satisfy debate schema at {phase}; "
                    "rule fallback is disabled"
            )
            result = with_metrics(fallback, f"{provider.backend}_invalid_fallback", phase, prompt)
            result["raw_text"] = generated["raw_text"]
            result["validation_warning"] = "模型输出未通过严格 JSON Schema，格式修复仍失败，已降级为规则结果。"
            result["latency_ms"] = generated["latency_ms"]
            result["prompt_tokens"] = generated["prompt_tokens"]
            result["completion_tokens"] = generated["completion_tokens"]
            return result
        normalized = normalize_turn(parsed, generated["raw_text"], fallback)
        result = {
            **normalized,
            "latency_ms": generated["latency_ms"],
            "prompt_tokens": generated["prompt_tokens"],
            "completion_tokens": generated["completion_tokens"],
            "backend": provider.backend,
            "phase": phase,
        }
        if schema_completed_fields:
            result["schema_completed_fields"] = schema_completed_fields
            result["validation_warning"] = (
                "大模型已生成结论和论据；缺失的协议字段由程序完成结构化补齐："
                + "、".join(schema_completed_fields)
            )
        return result
    except Exception as exc:
        if llm_rule_fallback_disabled():
            raise RuntimeError(
                f"{provider.backend} model call failed at {phase}: {exc}"
            ) from exc
        result = with_metrics(fallback, f"{provider.backend}_fallback", phase, prompt)
        result["provider_error"] = str(exc)
        return result


def llm_rule_fallback_disabled() -> bool:
    return os.getenv("MALAPP_DISABLE_LLM_RULE_FALLBACK", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def model_max_tokens_for_phase(phase: str, model_name: str = "") -> int:
    default_by_phase = {
        "initial_testimony": 1150,
        "directed_attack": 1150,
        "evidence_rebuttal": 1250,
        "role_reversal_rebuttal": 1250,
        "closing_statement": 1050,
    }
    model_b_by_phase = {
        "initial_testimony": 720,
        "directed_attack": 620,
        "evidence_rebuttal": 680,
        "role_reversal_rebuttal": 680,
        "closing_statement": 620,
    }
    env_value = os.getenv("MALAPP_QWEN_MAX_NEW_TOKENS", "").strip()
    if env_value:
        try:
            return max(256, min(1800, int(env_value)))
        except ValueError:
            pass
    if model_name == "model_b":
        return model_b_by_phase.get(phase, 420)
    return default_by_phase.get(phase, 560)


def bounded_completion_tokens(
    system_prompt: str,
    user_prompt: str,
    requested: int,
    context_tokens: int | None = None,
) -> int:
    context_tokens = int(context_tokens or os.getenv("MALAPP_MODEL_CONTEXT_TOKENS", "4096") or "4096")
    prompt_tokens = estimate_tokens(system_prompt + user_prompt)
    reserved = 384 if context_tokens <= 2048 else 192
    min_tokens = 64 if context_tokens <= 2048 else 256
    available = max(min_tokens, context_tokens - prompt_tokens - reserved)
    return max(min_tokens, min(int(requested), available, 1800))


def fit_prompt_for_context(
    system_prompt: str,
    user_prompt: str,
    context_tokens: int,
) -> tuple[str, str]:
    if context_tokens > 2048:
        return system_prompt, user_prompt
    target_prompt_tokens = int(os.getenv("MALAPP_MODEL_B_PROMPT_TOKEN_BUDGET", "700") or "700")
    if estimate_tokens(system_prompt + user_prompt) <= target_prompt_tokens:
        return system_prompt, user_prompt

    # Keep the contract/instructions at the front and the concrete compressed
    # evidence at the end. The middle part usually contains repeated context
    # from previous rounds, which is the safest portion to elide for 2048-token
    # model B.
    head_chars = 900
    tail_chars = 1500
    marker = "\n...中间辩论上下文已压缩，以下保留关键证据与输出要求...\n"
    compact_user = user_prompt[:head_chars] + marker + user_prompt[-tail_chars:]
    while estimate_tokens(system_prompt + compact_user) > target_prompt_tokens and tail_chars > 500:
        tail_chars -= 200
        compact_user = user_prompt[:head_chars] + marker + user_prompt[-tail_chars:]
    while estimate_tokens(system_prompt + compact_user) > target_prompt_tokens and head_chars > 350:
        head_chars -= 150
        compact_user = user_prompt[:head_chars] + marker + user_prompt[-tail_chars:]
    return system_prompt, compact_user


def model_repair_tokens_for_phase(phase: str) -> int:
    default_by_phase = {
        "initial_testimony": 420,
        "directed_attack": 320,
        "evidence_rebuttal": 340,
        "role_reversal_rebuttal": 340,
        "closing_statement": 340,
    }
    return default_by_phase.get(phase, 420)


def dump_llm_validation_failure(
    provider: ModelProvider,
    phase: str,
    generated: dict[str, Any],
    parsed: dict[str, Any],
) -> None:
    try:
        path = DATA_DIR / "llm_validation_failures.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "ts": time.time(),
                        "provider": provider.backend,
                        "model": provider.model,
                        "phase": phase,
                        "raw_text": str(generated.get("raw_text") or "")[:4000],
                        "parsed": parsed,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    except Exception:
        pass


def clean_debate_punctuation(text: str) -> str:
    text = re.sub(r"模型([甲乙])\s*(提出质疑|质疑依据|反驳观点|补充依据)\s*[：:]\s*", "", text)
    text = re.sub(r"本轮质疑基于([^：:\n]+)[：:]\s*质疑点", r"本轮质疑基于\1，质疑点", text)
    text = re.sub(r"质疑点\s*[：:]\s*", "", text)
    text = re.sub(r"回答\s*[：:]\s*", "", text)
    text = re.sub(r"[“\"]恶意判断依据\s*[：:]\s*([^”\"]+)[”\"]", r"恶意判断依据为\1", text)
    text = re.sub(r"[“\"]模型评分\s*[：:]?\s*([0-9.]+)[”\"]", r"模型评分 \1", text)
    text = re.sub(r"请针对[“\"]([^”\"]+)[”\"]说明", r"请针对\1说明", text)
    text = re.sub(r"([，。！？；：、])\s+([，。！？；：、])", r"\1", text)
    text = re.sub(r"\s+([，。！？；：、])", r"\1", text)
    text = re.sub(r"([，。！？；：、])\s+", r"\1", text)
    text = text.replace("；为什么", "；需要说明为什么").replace("，为什么", "，需要说明为什么")
    text = re.sub(r"([。！？]){2,}", r"\1", text)
    text = re.sub(r"([，；：、]){2,}", r"\1", text)
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def clean_display_text(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value or "")
    text = re.sub(r"<think>.*?</think>", " ", text, flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"</?think>", " ", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\b(question|answer|arguments|evidence_refs|evidence_chain|feature_relations|contradictions|omissions|verdict|risk_level|confidence|score)\s*[:：]\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"(^|[。；;，,\n\r\s])(?:question|answer|arguments|evidence_refs|evidence_chain|feature_relations|contradictions|omissions|verdict|risk_level|confidence|score)\s+",
        r"\1",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"协议字段已自动补齐", "", text, flags=re.IGNORECASE)
    text = re.sub(r"自动补齐字段\s*[:：]\s*[^。；\n\r]+", "", text, flags=re.IGNORECASE)
    text = re.sub(
        r"\b(score|verdict|risk_level|arguments|omissions|evidence_refs|confidence|contradictions|evidence_chain|feature_relations|accepted_corrections|discarded_claims)\b\s*,?\s*",
        "",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\b(malicious|suspicious|benign|high|medium|low)\b", lambda m: {
        "malicious": "恶意",
        "suspicious": "可疑",
        "benign": "良性",
        "high": "高风险",
        "medium": "中风险",
        "low": "低风险",
    }.get(m.group(1).lower(), m.group(0)), text, flags=re.IGNORECASE)
    field_replacements = {
        "source__上游风险分数": "上游风险分数",
        "source_上游风险分数": "上游风险分数",
        "source_risk_score": "上游风险分数",
        "analysis.技术场景翻译:标签": "技术场景标签",
        "analysis.技术场景翻译.标签": "技术场景标签",
        "analysis.技术场景翻译": "技术场景翻译",
        "technical_scene_translation.labels": "技术场景标签",
        "technical_scene_translation": "技术场景翻译",
        "matched_rules": "命中规则",
        "business_harm_labels": "业务危害标签",
        "harm_chain.stages": "危害链阶段",
        "harm_chain": "危害链",
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
        "business_tags": "业务标签",
        "packer_or_obfuscation": "加固或混淆",
        "sdk_risk": "SDK 风险",
        "network_indicator": "网络威胁指标",
        "malware_family": "黑产家族",
        "declared_impersonation": "仿冒标记",
        "impersonation_probability": "仿冒恶意概率",
        "xgboost_domain_probability": "机器学习先验恶意概率",
        "xgb_agent_scores": "智能体恶意概率",
        "xgb_score": "机器学习分数",
        "agent_judgement": "智能体复核结论",
        "agent_judgment": "智能体复核结论",
        "rule_judgement": "工具证据结论",
        "rule_judgment": "工具证据结论",
        "rule_judge": "工具证据结论",
        "llm_rule_disagreement": "智能体复核与工具证据存在分歧",
        "score_review_disagreement": "评分复核分歧",
        "llm_independent_review": "智能体独立复核",
        "llm_review": "智能体复核",
        "llm_ru": "智能体复核",
        "EvidenceBlock": "证据块",
        "ML概率": "机器学习概率",
        "LLM可疑冲突": "大模型可疑冲突",
        "question": "质疑点",
        "answer": "回应依据",
        "present": "字段存在",
        "official_app_name": "正版应用名称",
        "official_pkg": "正版包名",
        "official_md5": "正版 MD5",
        "official_icon": "正版图标",
        "brand_similarity": "品牌相似度",
        "icon_path": "图标路径",
        "icon_base64": "图标 Base64",
        "icon_hash": "图标哈希",
        "icon_text": "图标文字",
        "official_app_assets": "正版应用资产",
        "genuine_package_match": "正版包名匹配",
        "genuine_signature_match": "正版签名匹配",
        "genuine_name_match": "正版名称匹配",
        "name_obfuscation": "名称伪装",
        "impersonation_flag": "仿冒标记",
        "visual_similarity": "视觉相似度",
        "sample_icon_available": "样本图标可用",
        "official_asset_match.asset_count": "正版资产数量",
        "official_asset_match": "正版资产匹配",
        "asset_count": "资产数量",
        "assessment": "评估结果",
    }
    for old, new in field_replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"\b(rule judge|rule_judge)\b", "工具证据结论", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(llm ru|llm_ru|llm)\b", "大模型", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(agent judgement|agent_judgement|agent judgment|agent_judgment)\b", "智能体复核结论", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(rule judgement|rule_judgement|rule judgment|rule_judgment)\b", "工具证据结论", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(question|answer)\b", lambda m: {"question": "质疑点", "answer": "回应依据"}.get(m.group(1).lower(), m.group(0)), text, flags=re.IGNORECASE)
    text = text.replace("->", "，").replace("→", "，")
    text = re.sub(r"原始字段\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)\s*=\s*['\"]?([^，。；\n\r'\"]+)['\"]?", r"原始字段“\1”为“\2”", text)
    text = re.sub(r"业务标签\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)为", r"业务标签“\1”为", text)
    text = re.sub(r"标签\s*=\s*\[([^\]]+)\]", r"标签为“\1”", text)
    text = re.sub(r"结论\s+([^，。；\n\r]+)", r"结论：\1", text)
    text = re.sub(r"\s+", " ", text).strip()
    text = text.strip("\"'“”` ")
    text = clean_debate_punctuation(text)
    replacements = {
        "；。": "。",
        ";。": "。",
        "。；": "。",
        "，。": "。",
        "、。": "。",
        "。。": "。",
        "，，": "，",
        "；；": "；",
        "：：": "：",
        " ,": "，",
        " ;": "；",
        " .": "。",
    }
    changed = True
    while changed:
        before = text
        for old, new in replacements.items():
            text = text.replace(old, new)
        text = re.sub(r"\s*([，。！？；：、])\s*", r"\1", text)
        text = re.sub(r"([。！？]){2,}", r"\1", text)
        text = re.sub(r"([，；：、]){2,}", r"\1", text)
        text = re.sub(r"([。！？])([；，、])", r"\1", text)
        changed = text != before
    return text.strip("\"'“”` ")


def text_similarity(a: Any, b: Any) -> float:
    left = re.sub(r"\s+", "", clean_display_text(a))
    right = re.sub(r"\s+", "", clean_display_text(b))
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0
    common = set(left) & set(right)
    return len(common) / max(len(set(left)), len(set(right)), 1)


def build_evidence_response(
    turn_type: str,
    question: str,
    arguments: list[str],
    refs: list[str],
    accepted: list[str],
    rejected: list[str],
    omissions: list[str],
    contradictions: list[str],
    score: float,
    verdict: str,
) -> str:
    ref_text = "、".join(refs[:4]) or "当前证据块"
    argument_text = "；".join(arguments[:3]) or f"{ref_text} 中的关键证据"
    accepted_text = "；".join(accepted[:2])
    rejected_text = "；".join(rejected[:2])
    gap_text = "；".join((contradictions + omissions)[:2])
    if turn_type in {"evidence_rebuttal", "role_reversal_rebuttal"}:
        stance = "部分接受对方质疑" if accepted_text or gap_text else "不完全接受对方质疑"
        response = (
            f"{stance}。本轮不是重复提出问题，而是基于 {ref_text} 进行反驳：{argument_text}。"
            f"这些证据使当前结论维持为 {verdict}，综合评分约为 {score:.2f}。"
        )
        if accepted_text:
            response += f" 已接受的质疑点是：{accepted_text}。"
        if rejected_text:
            response += f" 未采纳的质疑点是：{rejected_text}。"
        if gap_text:
            response += f" 仍需保留的不确定性是：{gap_text}。"
        return response
    return (
        f"本轮质疑基于 {ref_text}：{argument_text}。需要核验对方结论是否遗漏上述证据、"
        f"是否存在逻辑跳跃或字段缺口；若质疑成立，当前结论应调整为 {verdict}，"
        f"综合评分约为 {score:.2f}。"
    )


def clean_text_list(value: Any) -> list[str]:
    result = []
    for item in normalize_list(value):
        text = clean_display_text(item)
        if text and text not in result and all(text_similarity(text, old) < 0.88 for old in result):
            result.append(text)
    return result


def clean_text_list_limited(value: Any, limit: int = 5) -> list[str]:
    return clean_text_list(value)[:limit]


def normalize_turn(parsed: dict[str, Any], raw: str, fallback: dict[str, Any]) -> dict[str, Any]:
    base = normalize_llm_result(raw, float(fallback["score"]), str(fallback["verdict"]))
    derived_verdict = verdict_from_score(base["score"])
    contradictions = clean_text_list(parsed.get("contradictions"))
    model_verdict = str(parsed.get("verdict") or "").strip().lower()
    if model_verdict in {"malicious", "suspicious", "benign"} and model_verdict != derived_verdict:
        contradictions.append(
            f"模型原始结论 {model_verdict} 与评分 {base['score']:.2f} 不一致，"
            f"已按校准阈值统一为 {derived_verdict}"
        )
    try:
        confidence = clamp(float(parsed.get("confidence", fallback.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = clamp(float(fallback.get("confidence", 0.5)))
    if model_verdict and model_verdict != derived_verdict:
        confidence = min(confidence, 0.6)
    question = clean_display_text(parsed.get("question") or fallback.get("question", ""))
    if is_generic_turn_question(question):
        question = clean_display_text(fallback.get("question", ""))
        contradictions.append("模型输出了泛化质疑，系统已改写为基于对方真实论据的定向质疑。")
        confidence = min(confidence, 0.65)
    return {
        **fallback,
        **parsed,
        "score": base["score"],
        "verdict": derived_verdict,
        "risk_level": risk_level(base["score"]),
        "question": question,
        "answer": clean_display_text(parsed.get("answer") or fallback.get("answer", "")),
        "arguments": clean_text_list(parsed.get("arguments")) or clean_text_list(fallback.get("arguments", [])),
        "evidence_refs": normalize_list(parsed.get("evidence_refs")) or fallback.get("evidence_refs", []),
        "confidence": confidence,
        "evidence_chain": clean_text_list(parsed.get("evidence_chain")) or clean_text_list(fallback.get("evidence_chain", [])),
        "feature_relations": clean_text_list(parsed.get("feature_relations")) or clean_text_list(fallback.get("feature_relations", [])),
        "contradictions": contradictions,
        "raw_text": raw,
    }


INITIAL_TESTIMONY_FORBIDDEN_TERMS = (
    "模型甲",
    "模型乙",
    "Model A",
    "Model B",
    "model_a",
    "model_b",
    "对方",
    "质疑",
    "反驳",
    "我方",
    "我方修正判断",
    "我方结论",
    "针对模型甲",
    "针对模型乙",
    "请解释",
    "请解释为什么",
    "请说明",
    "请核验",
    "请判断",
    "该应用是否",
    "该样本是否",
    "是否应被判定",
    "是否应判定",
    "是否为恶意",
    "是否属于恶意",
    "是否判定为恶意",
    "是否应判为恶意",
    "是否需要判定为恶意",
    "是否具有恶意",
    "是否存在高危权限",
    "是否存在高危",
    "仅依据当前输入",
    "EvidenceBlock 独立形成初判",
    "独立形成初判",
    "该阶段仅依据输入证据块",
    "输入证据块形成独立陈述",
    "输入证据块 -> 特征组合复核",
    "关键证据支持当前判断",
    "模型未指出明确",
    "模型原始结论",
    "评分复核",
    "复核分支",
    "ML概率",
    "LLM可疑冲突",
    "llm_ru",
    "llm_rule",
    "已按校准阈值",
    "rule_judge",
    "rule judge",
    "rule_judgement",
    "rule judgement",
    "field/value",
    "feature relation sentence",
)


def initial_sentence_violates_contract(text: Any) -> bool:
    cleaned = clean_display_text(str(text or "")).strip()
    if not cleaned:
        return True
    if len(cleaned) < 16:
        return True
    if "？" in cleaned or "?" in cleaned:
        return True
    return any(part in cleaned for part in INITIAL_TESTIMONY_FORBIDDEN_TERMS)


def initial_report_violates_contract(parsed: dict[str, Any]) -> bool:
    text_fields: list[Any] = []
    for field in ("arguments", "contradictions", "evidence_chain", "feature_relations"):
        text_fields.extend(normalize_list(parsed.get(field)))
    return any(
        initial_sentence_violates_contract(item)
        for item in text_fields
        if item not in (None, "", [])
    )


def valid_base_model_schema(parsed: dict[str, Any]) -> bool:
    if not parsed:
        return False
    if parsed.get("verdict") not in {"malicious", "suspicious", "benign"}:
        return False
    if parsed.get("risk_level") not in {"high", "medium", "low"}:
        return False
    try:
        float(parsed.get("score"))
        float(parsed.get("confidence"))
    except (TypeError, ValueError):
        return False
    required_arrays = (
        "arguments",
        "omissions",
        "evidence_refs",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    )
    if not all(isinstance(parsed.get(field), list) for field in required_arrays):
        return False
    return True


def valid_initial_schema(parsed: dict[str, Any]) -> bool:
    if not valid_base_model_schema(parsed):
        return False
    if initial_report_violates_contract(parsed):
        return False
    return True


def usable_initial_output(parsed: dict[str, Any]) -> bool:
    if not parsed or parsed.get("verdict") not in {"malicious", "suspicious", "benign"}:
        return False
    try:
        float(parsed.get("score"))
    except (TypeError, ValueError):
        return False
    return bool(normalize_list(parsed.get("arguments")) or normalize_list(parsed.get("evidence_refs")))


def coerce_initial_schema_values(parsed: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parsed, dict) or not parsed:
        return {}
    result = dict(parsed)
    # Accept common Chinese keys returned by instruction-following models.
    # The internal protocol remains English so downstream validation is stable.
    field_aliases = {
        "结论": "verdict",
        "判定": "verdict",
        "风险等级": "risk_level",
        "风险": "risk_level",
        "恶意概率": "score",
        "恶意倾向": "score",
        "风险分数": "score",
        "分数": "score",
        "置信度": "confidence",
        "置信水平": "confidence",
        "主要依据": "arguments",
        "论据": "arguments",
        "引用证据": "evidence_refs",
        "证据引用": "evidence_refs",
        "缺失字段": "omissions",
        "矛盾点": "contradictions",
        "证据链": "evidence_chain",
        "特征关系": "feature_relations",
    }
    for source, target in field_aliases.items():
        if source in result and result.get(target) in (None, "", [], {}):
            result[target] = result[source]
    verdict_map = {
        "恶意": "malicious",
        "高风险": "malicious",
        "malicious": "malicious",
        "可疑": "suspicious",
        "中风险": "suspicious",
        "suspicious": "suspicious",
        "良性": "benign",
        "低风险": "benign",
        "benign": "benign",
    }
    risk_map = {
        "高": "high",
        "高风险": "high",
        "high": "high",
        "中": "medium",
        "中风险": "medium",
        "medium": "medium",
        "低": "low",
        "低风险": "low",
        "low": "low",
    }
    verdict = str(result.get("verdict", "")).strip().lower()
    result["verdict"] = verdict_map.get(verdict, result.get("verdict"))
    risk = str(result.get("risk_level", "")).strip().lower()
    result["risk_level"] = risk_map.get(risk, result.get("risk_level"))
    for field in (
        "arguments",
        "omissions",
        "evidence_refs",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    ):
        if not isinstance(result.get(field), list):
            result[field] = normalize_list(result.get(field))
    return result


def coerce_turn_schema_values(parsed: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parsed, dict) or not parsed:
        return {}
    result = coerce_initial_schema_values(parsed)
    for source, target in {
        "问题": "question",
        "质疑": "question",
        "回答": "answer",
        "答复": "answer",
    }.items():
        if source in result and result.get(target) in (None, "", [], {}):
            result[target] = result[source]
    for field in ("question", "answer"):
        value = result.get(field)
        if isinstance(value, list):
            result[field] = "；".join(str(item) for item in value if str(item).strip())
        elif isinstance(value, dict):
            result[field] = "；".join(
                f"{key}：{value}"
                for key, value in value.items()
                if value not in ("", None, [], {})
            )
    for field in (
        "arguments",
        "evidence_refs",
        "accepted_challenges",
        "rejected_challenges",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    ):
        if not isinstance(result.get(field), list):
            result[field] = normalize_list(result.get(field))
    return result


def coerce_closing_schema_values(parsed: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(parsed, dict) or not parsed:
        return {}
    result = coerce_initial_schema_values(parsed)
    for field in (
        "accepted_corrections",
        "discarded_claims",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    ):
        if not isinstance(result.get(field), list):
            result[field] = normalize_list(result.get(field))
    return result


def complete_initial_schema(
    parsed: dict[str, Any],
    fallback: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    result = dict(parsed)
    completed = []
    score = clamp(float(result.get("score", fallback.get("score", 0.5))))
    defaults = {
        "score": score,
        "verdict": result.get("verdict")
        if result.get("verdict") in {"malicious", "suspicious", "benign"}
        else verdict_from_score(score),
        "risk_level": risk_level(score),
        "arguments": normalize_list(result.get("arguments")),
        "omissions": normalize_list(result.get("omissions")),
        "evidence_refs": normalize_list(result.get("evidence_refs")),
        "confidence": clamp(0.45 + abs(score - 0.5) * 0.5),
        "contradictions": [],
        "evidence_chain": [
            f"{argument} -> 支撑风险分数 {score:.2f}"
            for argument in normalize_list(result.get("arguments"))[:3]
        ],
        "feature_relations": [
            f"{ref} 证据块参与综合判断"
            for ref in normalize_list(result.get("evidence_refs"))[:4]
        ],
    }
    for field, value in defaults.items():
        current = result.get(field)
        if current in (None, "") or (field in {"arguments", "omissions", "evidence_refs", "contradictions", "evidence_chain", "feature_relations"} and not isinstance(current, list)):
            result[field] = value
            completed.append(field)
    refs = normalize_list(result.get("evidence_refs"))
    fallback_refs = normalize_list(fallback.get("evidence_refs"))
    if len(refs) < 2 or all(ref == "xgboost_prior" for ref in refs):
        result["evidence_refs"] = list(dict.fromkeys(refs + fallback_refs))
        if "evidence_refs" not in completed:
            completed.append("evidence_refs")
    return result, completed


def build_inference_basis_from_fallback(fallback: dict[str, Any], verdict_text: str, risk_text: str, score: float) -> list[str]:
    basis = [clean_display_text(item) for item in normalize_list(fallback.get("inference_basis"))]
    basis = [item for item in basis if item and not initial_sentence_violates_contract(item)]
    if basis:
        return basis[:3]
    refs = normalize_list(fallback.get("evidence_refs"))
    ref_text = "、".join(refs[:4]) or "四智能体证据"
    if verdict_text == "恶意":
        return [
            f"恶意判断依据：{ref_text}中存在高强度风险证据，相关字段在静态、情报、仿冒或业务侧形成交叉支撑，因此判为{risk_text}。",
            f"分数依据：当前恶意倾向为 {score:.3f}，说明多项证据的风险方向一致，足以支撑{verdict_text}初判。",
        ]
    if verdict_text == "良性":
        return [
            f"良性判断依据：{ref_text}未形成足够强的恶意闭环，关键高危字段缺失或反向证据较多，因此倾向{risk_text}。",
            f"分数依据：当前恶意倾向为 {score:.3f}，说明证据不足以支撑恶意结论，先按{verdict_text}处理。",
        ]
    return [
        f"可疑判断依据：{ref_text}中同时存在风险信号与证据缺口，现有字段只能支撑{risk_text}，不能直接定为恶意或良性。",
        f"分数依据：当前恶意倾向为 {score:.3f}，说明证据强度处于中间区间，需要结合缺失字段继续复核。",
    ]


def sanitize_initial_report_text(
    parsed: dict[str, Any],
    fallback: dict[str, Any],
    role: dict[str, str],
) -> tuple[dict[str, Any], list[str]]:
    """Keep initial testimony declarative and useful for report display."""
    result = dict(parsed)
    completed: list[str] = []
    score = clamp(float(result.get("score", fallback.get("score", 0.5))))
    verdict_text = {
        "malicious": "恶意",
        "suspicious": "可疑",
        "benign": "良性",
    }.get(str(result.get("verdict") or verdict_from_score(score)), "可疑")
    risk_text = {"high": "高风险", "medium": "中风险", "low": "低风险"}.get(
        str(result.get("risk_level") or risk_level(score)),
        "中风险",
    )
    refs = normalize_list(result.get("evidence_refs")) or normalize_list(fallback.get("evidence_refs"))
    ref_text = "、".join(refs[:4]) or "四智能体证据"

    arguments = clean_text_list_limited(
        [
            item for item in normalize_list(result.get("arguments"))
            if not initial_sentence_violates_contract(item)
        ],
        5,
    )
    inference_basis = build_inference_basis_from_fallback(fallback, verdict_text, risk_text, score)
    if len(arguments) < 2:
        role_name = role.get("name", "模型")
        if role_name == "风险优先模型":
            arguments = inference_basis + [
                f"复核侧更关注风险证据能否交叉印证；本轮综合{ref_text}后倾向{verdict_text}，风险等级为{risk_text}。"
            ]
        else:
            arguments = inference_basis + [
                f"证据复核侧更关注误报风险；本轮综合{ref_text}后倾向{verdict_text}，风险等级为{risk_text}。"
            ]
        completed.append("arguments")
    elif not any("判断依据" in item or "分数依据" in item or "依据：" in item for item in arguments):
        arguments = inference_basis[:2] + arguments[:3]
        completed.append("arguments")
    result["arguments"] = clean_text_list_limited(arguments, 5)

    evidence_chain = clean_text_list_limited(
        [
            item for item in normalize_list(result.get("evidence_chain"))
            if not initial_sentence_violates_contract(item)
        ],
        5,
    )
    if len(evidence_chain) < 2:
        evidence_chain = [
            f"{ref_text} -> 提取静态、情报、仿冒和业务侧证据 -> 识别风险方向 -> 输出{verdict_text}结论。",
            f"证据强度与缺失字段共同约束恶意倾向分 -> 当前分数 {score:.3f} -> 风险等级为{risk_text}。",
        ]
        completed.append("evidence_chain")
    result["evidence_chain"] = clean_text_list_limited(evidence_chain, 5)

    feature_relations = clean_text_list_limited(
        [
            item for item in normalize_list(result.get("feature_relations"))
            if not initial_sentence_violates_contract(item)
        ],
        4,
    )
    if len(feature_relations) < 1:
        feature_relations = [
            f"{ref_text}之间形成交叉印证或相互约束，用于判断单一证据是否足以支撑{verdict_text}结论。"
        ]
        completed.append("feature_relations")
    result["feature_relations"] = clean_text_list_limited(feature_relations, 4)

    contradictions = clean_text_list_limited(
        [
            item for item in normalize_list(result.get("contradictions"))
            if not initial_sentence_violates_contract(item)
        ],
        4,
    )
    result["contradictions"] = contradictions
    return result, completed


def valid_turn_schema(parsed: dict[str, Any]) -> bool:
    if not parsed:
        return False
    try:
        float(parsed.get("score"))
    except (TypeError, ValueError):
        return False
    if parsed.get("verdict") not in {"malicious", "suspicious", "benign"}:
        return False
    question = str(parsed.get("question") or "").strip()
    answer = str(parsed.get("answer") or "").strip()
    if not question or not answer:
        return False
    required_arrays = (
        "arguments",
        "evidence_refs",
        "accepted_challenges",
        "rejected_challenges",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    )
    return all(isinstance(parsed.get(field), list) for field in required_arrays)


def usable_turn_output(parsed: dict[str, Any]) -> bool:
    if not parsed:
        return False
    try:
        float(parsed.get("score"))
    except (TypeError, ValueError):
        return False
    text_fields = [
        parsed.get("question"),
        parsed.get("answer"),
        parsed.get("arguments"),
        parsed.get("evidence_refs"),
    ]
    return any(normalize_list(item) for item in text_fields)


def complete_turn_schema(
    parsed: dict[str, Any],
    fallback: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    result = dict(parsed)
    completed: list[str] = []
    score = clamp(float(result.get("score", fallback.get("score", 0.5))))
    verdict = result.get("verdict") if result.get("verdict") in {"malicious", "suspicious", "benign"} else verdict_from_score(score)
    arguments = normalize_list(result.get("arguments")) or normalize_list(result.get("answer")) or normalize_list(fallback.get("arguments"))
    refs = normalize_list(result.get("evidence_refs")) or normalize_list(fallback.get("evidence_refs"))
    omissions = normalize_list(result.get("omissions")) or normalize_list(fallback.get("omissions"))
    accepted = normalize_list(result.get("accepted_challenges")) or normalize_list(fallback.get("accepted_challenges"))
    rejected = normalize_list(result.get("rejected_challenges")) or normalize_list(fallback.get("rejected_challenges"))
    contradictions = normalize_list(result.get("contradictions"))
    evidence_chain = normalize_list(result.get("evidence_chain")) or [
        f"{argument} -> 支撑当前 {verdict_from_score(score)} 判断"
        for argument in arguments[:3]
    ]
    feature_relations = normalize_list(result.get("feature_relations")) or [
        f"{ref} 与对方引用证据共同校验结论可靠性"
        for ref in refs[:3]
    ]
    try:
        confidence = clamp(float(result.get("confidence", fallback.get("confidence", 0.5))))
    except (TypeError, ValueError):
        confidence = clamp(float(fallback.get("confidence", 0.5)))
    question = str(result.get("question") or "").strip()
    answer = str(result.get("answer") or "").strip()
    if len(question) < 12:
        ref_text = "、".join(refs[:4]) or "当前证据块"
        question = f"请核验对方结论是否充分覆盖 {ref_text}，以及是否存在证据缺口。"
        completed.append("question")
    arguments = [
        item for item in arguments
        if text_similarity(item, question) < 0.72 and not clean_display_text(item).endswith(("?", "？"))
    ] or normalize_list(fallback.get("arguments"))
    answer_is_invalid = (
        len(answer) < 12
        or text_similarity(answer, question) >= 0.72
        or (answer.endswith(("?", "？")) and len(answer) < 80)
    )
    if answer_is_invalid:
        answer = build_evidence_response(
            str(fallback.get("turn_type") or result.get("turn_type") or ""),
            question,
            arguments,
            refs,
            accepted,
            rejected,
            omissions,
            contradictions,
            score,
            verdict,
        )
        completed.append("answer")
    defaults = {
        "score": score,
        "verdict": verdict,
        "risk_level": risk_level(score),
        "confidence": confidence,
        "question": clean_display_text(question),
        "answer": clean_display_text(answer),
        "arguments": clean_text_list_limited(arguments, 4),
        "evidence_refs": refs,
        "accepted_challenges": clean_text_list_limited(accepted, 2),
        "rejected_challenges": clean_text_list_limited(rejected, 2),
        "omissions": clean_text_list_limited(omissions, 3),
        "contradictions": clean_text_list_limited(contradictions, 3),
        "evidence_chain": clean_text_list_limited(evidence_chain, 4),
        "feature_relations": clean_text_list_limited(feature_relations, 3),
    }
    for field, value in defaults.items():
        current = result.get(field)
        if current in (None, "") or (
            field
            in {
                "arguments",
                "evidence_refs",
                "accepted_challenges",
                "rejected_challenges",
                "omissions",
                "contradictions",
                "evidence_chain",
                "feature_relations",
            }
            and not isinstance(current, list)
        ):
            result[field] = value
            if field not in completed:
                completed.append(field)
    for field in (
        "arguments",
        "accepted_challenges",
        "rejected_challenges",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    ):
        result[field] = clean_text_list_limited(result.get(field), len(defaults.get(field, [])) or 4)
    result["question"] = clean_display_text(result.get("question", ""))
    result["answer"] = clean_display_text(result.get("answer", ""))
    return result, completed


def valid_closing_schema(parsed: dict[str, Any]) -> bool:
    # A closing statement is allowed to discuss corrections, discarded
    # claims and the opposing model. Do not apply the initial-testimony
    # forbidden-term contract here.
    if not valid_base_model_schema(parsed):
        return False
    required_arrays = (
        "accepted_corrections",
        "discarded_claims",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    )
    return all(isinstance(parsed.get(field), list) for field in required_arrays)


def schema_validation_failure_reason(phase: str, parsed: Any) -> str:
    """Produce a compact, actionable error for the model-only repair request."""
    if not isinstance(parsed, dict) or not parsed:
        return "未提取到合法 JSON 对象，或 JSON 对象为空"

    errors: list[str] = []
    required = ["verdict", "score", "risk_level", "confidence", "arguments", "evidence_refs"]
    if phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"}:
        required.extend(["question", "answer"])
    if phase == "closing_statement":
        required.extend(["accepted_corrections", "discarded_claims"])
    for field in required:
        value = parsed.get(field)
        if value in (None, "", [], {}):
            errors.append(f"缺少 {field}")

    array_fields = ["arguments", "evidence_refs", "omissions", "contradictions", "evidence_chain", "feature_relations"]
    if phase in {"directed_attack", "evidence_rebuttal", "role_reversal_rebuttal"}:
        array_fields.extend(["accepted_challenges", "rejected_challenges"])
    if phase == "closing_statement":
        array_fields.extend(["accepted_corrections", "discarded_claims"])
    for field in array_fields:
        if field in parsed and parsed.get(field) not in (None, "") and not isinstance(parsed.get(field), list):
            errors.append(f"{field} 必须为 JSON 数组")

    if chinese_verdict_to_code(parsed.get("verdict")) not in {"malicious", "suspicious", "benign"}:
        errors.append("verdict 必须为 malicious、suspicious 或 benign")
    if str(parsed.get("risk_level") or "").strip().lower() not in {"high", "medium", "low"}:
        errors.append("risk_level 必须为 high、medium 或 low")
    for field in ("score", "confidence"):
        try:
            value = float(parsed.get(field))
            if not 0 <= value <= 1:
                errors.append(f"{field} 必须在 0 到 1 之间")
        except (TypeError, ValueError):
            errors.append(f"{field} 必须为数字")
    if phase == "initial_testimony" and initial_report_violates_contract(parsed):
        errors.append("初判内容必须是陈述句，不能包含问句或辩论阶段词")
    return "；".join(errors[:10]) or "存在不符合协议的字段类型或必填字段"


def usable_closing_output(parsed: dict[str, Any]) -> bool:
    if not parsed:
        return False
    try:
        float(parsed.get("score"))
    except (TypeError, ValueError):
        return False
    return bool(
        normalize_list(parsed.get("arguments"))
        or normalize_list(parsed.get("evidence_refs"))
        or normalize_list(parsed.get("evidence_chain"))
    )


def complete_closing_schema(
    parsed: dict[str, Any],
    fallback: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    result, completed = complete_initial_schema(parsed, fallback)
    score = clamp(float(result.get("score", fallback.get("score", 0.5))))
    defaults = {
        "accepted_corrections": clean_text_list_limited(result.get("accepted_corrections"), 2)
        or clean_text_list_limited(fallback.get("accepted_corrections"), 2),
        "discarded_claims": clean_text_list_limited(result.get("discarded_claims"), 2)
        or clean_text_list_limited(fallback.get("discarded_claims"), 2),
        "omissions": clean_text_list_limited(result.get("omissions"), 2) or clean_text_list_limited(fallback.get("omissions"), 2),
        "contradictions": clean_text_list_limited(result.get("contradictions"), 2),
        "evidence_chain": clean_text_list_limited(result.get("evidence_chain"), 2)
        or [
            f"{argument} -> 终审分数 {score:.2f}"
            for argument in normalize_list(result.get("arguments"))[:3]
        ],
        "feature_relations": clean_text_list_limited(result.get("feature_relations"), 1)
        or [
            f"{ref} 证据块与其他证据共同约束终审结论"
            for ref in normalize_list(result.get("evidence_refs"))[:4]
        ],
    }
    for field, value in defaults.items():
        current = result.get(field)
        if current in (None, "") or not isinstance(current, list):
            result[field] = value
            if field not in completed:
                completed.append(field)
    return result, completed


def recover_initial_output_from_raw(raw: Any, fallback: dict[str, Any]) -> dict[str, Any]:
    text = str(raw or "")
    if not text.strip():
        return {}
    recovered: dict[str, Any] = {}
    for field in ("verdict", "risk_level"):
        value = extract_json_string_field(text, field)
        if value:
            recovered[field] = value
    for field in ("score", "confidence"):
        value = extract_json_number_field(text, field)
        if value is not None:
            recovered[field] = value
    for field in (
        "arguments",
        "omissions",
        "evidence_refs",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    ):
        values = extract_json_array_field(text, field)
        if values:
            recovered[field] = values
    if not recovered.get("arguments"):
        recovered["arguments"] = extract_short_chinese_sentences(text, limit=2)
    if not recovered.get("score"):
        recovered["score"] = fallback.get("score", 0.5)
    if not recovered.get("verdict"):
        recovered["verdict"] = fallback.get("verdict", verdict_from_score(float(recovered.get("score", 0.5))))
    if not recovered.get("risk_level"):
        recovered["risk_level"] = risk_level(float(recovered.get("score", 0.5)))
    if not recovered.get("evidence_refs"):
        recovered["evidence_refs"] = normalize_list(fallback.get("evidence_refs"))[:4]
    if not recovered.get("evidence_chain"):
        recovered["evidence_chain"] = normalize_list(recovered.get("arguments"))[:2]
    if not recovered.get("feature_relations"):
        refs = normalize_list(recovered.get("evidence_refs"))[:2]
        recovered["feature_relations"] = [f"{'、'.join(refs) or '关键证据'} 支撑当前初判"]
    return coerce_initial_schema_values(recovered)


def recover_turn_output_from_raw(raw: Any, fallback: dict[str, Any]) -> dict[str, Any]:
    text = str(raw or "")
    if not text.strip():
        return {}
    recovered: dict[str, Any] = {}
    for field in ("question", "answer", "verdict", "risk_level"):
        value = extract_json_string_field(text, field)
        if value:
            recovered[field] = value
    for field in ("score", "confidence"):
        value = extract_json_number_field(text, field)
        if value is not None:
            recovered[field] = value
    for field in (
        "arguments",
        "evidence_refs",
        "accepted_challenges",
        "rejected_challenges",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
    ):
        values = extract_json_array_field(text, field)
        if values:
            recovered[field] = values
    if not recovered.get("arguments"):
        recovered["arguments"] = extract_short_chinese_sentences(text, limit=2)
    if not recovered.get("evidence_chain"):
        recovered["evidence_chain"] = normalize_list(recovered.get("arguments"))[:2]
    if not recovered.get("feature_relations"):
        refs = normalize_list(recovered.get("evidence_refs"))[:2]
        recovered["feature_relations"] = [f"{'、'.join(refs) or '关键证据'} 支撑当前判断"]
    if not recovered.get("score"):
        recovered["score"] = fallback.get("score", 0.5)
    if not recovered.get("verdict"):
        recovered["verdict"] = fallback.get("verdict", verdict_from_score(float(recovered.get("score", 0.5))))
    return coerce_turn_schema_values(recovered)


def extract_json_string_field(text: str, field: str) -> str:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*"((?:\\.|[^"\\])*)"', text)
    if not match:
        return ""
    try:
        return json.loads('"' + match.group(1) + '"')
    except json.JSONDecodeError:
        return match.group(1)


def extract_json_number_field(text: str, field: str) -> float | None:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*(-?\d+(?:\.\d+)?)', text)
    if not match:
        return None
    try:
        return clamp(float(match.group(1)))
    except ValueError:
        return None


def extract_json_array_field(text: str, field: str) -> list[str]:
    match = re.search(rf'"{re.escape(field)}"\s*:\s*(\[[\s\S]*?\])', text)
    if not match:
        return []
    try:
        value = json.loads(match.group(1))
    except json.JSONDecodeError:
        return []
    return [compact_text(item, 90) for item in normalize_list(value)[:2]]


def extract_short_chinese_sentences(text: str, limit: int = 2) -> list[str]:
    cleaned = re.sub(r"[{}\[\]\",:]", " ", text)
    candidates = [
        compact_text(item, 90)
        for item in re.split(r"[。；;\n]+", cleaned)
        if len(item.strip()) >= 8 and not item.strip().startswith(("feature_relations", "evidence_chain"))
    ]
    return candidates[:limit]


def build_json_repair_prompt(raw: str, validation_error: str = "") -> str:
    raw = compact_text(raw, 2200)
    error_text = compact_text(validation_error or "存在缺失或非法字段", 700)
    return (
        "Repair the following model output into one valid JSON object only. "
        "Do not re-judge the sample and do not add facts. Preserve the original meaning. "
        "This is first-stage independent initial testimony. The repaired JSON must use declarative Chinese summary sentences only. "
        "Do not include questions or these words: 模型甲, 模型乙, model_a, model_b, Model A, Model B, 对方, 质疑, 反驳, 我方修正判断, 针对模型甲, 针对模型乙, 请解释, 请说明, 请核验, 请判断. "
        "Required schema exactly:\n"
        "{"
        "\"verdict\":\"suspicious\","
        "\"score\":0.5,"
        "\"risk_level\":\"medium\","
        "\"arguments\":[\"specific evidence sentence\"],"
        "\"omissions\":[],"
        "\"evidence_refs\":[\"static_analysis\",\"threat_intel\"],"
        "\"confidence\":0.5,"
        "\"contradictions\":[],"
        "\"evidence_chain\":[\"field/value -> conclusion\"],"
        "\"feature_relations\":[\"feature relation sentence\"]"
        "}\n"
        "Choose verdict from malicious, suspicious, benign. Choose risk_level from high, medium, low. "
        "All list fields must be JSON arrays. verdict and risk_level must use English enum values. "
        "Return JSON only, no markdown.\n"
        f"Validation errors to fix: {error_text}\n"
        f"Raw output:\n{raw}"
    )


def build_initial_retry_prompt(original_prompt: str) -> str:
    evidence_excerpt = compact_text(original_prompt[-3000:], 3000)
    return (
        "Read the evidence excerpt and output only one JSON object. "
        "Do not include markdown or explanations outside JSON. "
        "Use this exact key set: verdict, score, risk_level, arguments, omissions, "
        "evidence_refs, confidence, contradictions, evidence_chain, feature_relations. "
        "verdict must be one of malicious, suspicious, benign. "
        "risk_level must be one of high, medium, low. "
        "score and confidence must be numbers from 0 to 1. "
        "arguments, omissions, evidence_refs, contradictions, evidence_chain, "
        "feature_relations must be arrays of strings. "
        "arguments and evidence_chain must cite concrete fields or values from the evidence. "
        "Do not output questions; write declarative Chinese summaries with concrete evidence. "
        "Do not include these terms: 模型甲, 模型乙, model_a, model_b, Model A, Model B, 对方, 质疑, 反驳, 我方修正判断, 针对模型甲, 针对模型乙, 请解释, 请说明, 请核验, 请判断. "
        "Example shape only: "
        "{\"verdict\":\"suspicious\",\"score\":0.5,\"risk_level\":\"medium\","
        "\"arguments\":[\"example\"],\"omissions\":[],\"evidence_refs\":[\"static_analysis\"],"
        "\"confidence\":0.5,\"contradictions\":[],\"evidence_chain\":[\"field -> conclusion\"],"
        "\"feature_relations\":[\"relation\"]}\n"
        f"Evidence excerpt:\n{evidence_excerpt}"
    )


def build_turn_retry_prompt(original_prompt: str, phase: str) -> str:
    evidence_excerpt = compact_text(original_prompt[-1800:], 1800)
    return (
        "根据下面证据和辩论上下文，只输出一个短 JSON 对象。不要 Markdown，不要解释。 "
        "必须包含 question, answer, score, verdict, risk_level, confidence, arguments, evidence_refs, "
        "accepted_challenges, rejected_challenges, omissions, contradictions, evidence_chain, feature_relations。 "
        "verdict 只能是 malicious/suspicious/benign；risk_level 只能是 high/medium/low；"
        "score 和 confidence 是 0 到 1 的小数；数组字段必须是字符串数组。 "
        "question 需要 70 到 140 个中文字符，answer 需要 180 到 360 个中文字符。"
        "question 和 answer 必须说明依据哪个智能体、哪条证据、哪里存在逻辑冲突或补强关系。不要重复任何 key。"
        f"当前阶段：{phase}。\n"
        "示例形状：{\"question\":\"是否忽略控制地址命中？\","
        "\"answer\":\"根据情报溯源智能体的控制地址命中和业务打标智能体的涉诈分类，网络层与业务层形成交叉印证；如果对方只引用签名正常，会忽略外联威胁对最终风险的主导作用，因此需要重新评估为高风险。\","
        "\"score\":0.82,\"verdict\":\"malicious\",\"risk_level\":\"high\",\"confidence\":0.78,"
        "\"arguments\":[\"control_url 命中威胁地址\"],\"evidence_refs\":[\"threat_intel\"],"
        "\"accepted_challenges\":[],"
        "\"rejected_challenges\":[\"签名正常不足以排除风险\"],"
        "\"omissions\":[\"缺少运行时回传日志\"],"
        "\"contradictions\":[\"签名正常但网络证据偏高危\"],"
        "\"evidence_chain\":[\"control_url 命中 -> 支持恶意\"],"
        "\"feature_relations\":[\"网络威胁指标与涉诈分类相互印证\"]}\n"
        f"证据和上下文：\n{evidence_excerpt}"
    )


def build_turn_repair_prompt(raw: str, phase: str, validation_error: str = "") -> str:
    raw = compact_text(raw, 1800)
    error_text = compact_text(validation_error or "存在缺失或非法字段", 700)
    return (
        "把下面模型输出修复成一个合法 JSON 对象。不要重新研判，不要添加新事实，保留原意。 "
        "必须包含 question, answer, score, verdict, risk_level, confidence, arguments, evidence_refs, "
        "accepted_challenges, rejected_challenges, omissions, contradictions, evidence_chain, feature_relations。 "
        "verdict 只能是 malicious/suspicious/benign；risk_level 只能是 high/medium/low；"
        "score 和 confidence 必须是 0 到 1 小数；数组字段必须是字符串数组，最多 2 项。不要重复 key。"
        f"当前阶段：{phase}。需要修复的校验错误：{error_text}。\n原始输出：\n{raw}"
    )


def build_closing_retry_prompt(original_prompt: str) -> str:
    evidence_excerpt = compact_text(original_prompt[-1600:], 1600)
    return (
        "根据下面证据和辩论记忆，只输出一个终审 JSON 对象。不要 Markdown，不要解释。 "
        "必须包含 verdict, score, risk_level, confidence, arguments, evidence_refs, "
        "accepted_corrections, discarded_claims, omissions, contradictions, evidence_chain, feature_relations。 "
        "verdict 只能是 malicious/suspicious/benign；risk_level 只能是 high/medium/low；"
        "score 和 confidence 是 0 到 1 小数；所有数组字段必须是字符串数组。 "
        "arguments、evidence_chain、feature_relations 必须引用具体字段、证据块或分数。 "
        "示例形状：{\"verdict\":\"malicious\",\"score\":0.82,\"risk_level\":\"high\",\"confidence\":0.78,"
        "\"arguments\":[\"情报溯源与业务打标共同支持恶意判断\"],"
        "\"evidence_refs\":[\"threat_intel\",\"business_label\"],"
        "\"accepted_corrections\":[\"接受动态行为缺失会降低置信度\"],"
        "\"discarded_claims\":[\"放弃仅凭签名正常判良性的观点\"],"
        "\"omissions\":[\"缺少运行时回传日志\"],"
        "\"contradictions\":[\"静态签名偏正常但业务风险偏高\"],"
        "\"evidence_chain\":[\"download_url -> 可疑下载地址 -> 支持恶意倾向\"],"
        "\"feature_relations\":[\"网络指标与涉诈分类构成交叉印证\"]}\n"
        f"证据和上下文：\n{evidence_excerpt}"
    )


def build_closing_repair_prompt(raw: str, validation_error: str = "") -> str:
    raw = compact_text(raw, 2200)
    error_text = compact_text(validation_error or "存在缺失或非法字段", 700)
    return (
        "把下面终审模型输出修复成一个合法 JSON 对象。不要重新研判，不要添加新事实，保留原意。 "
        "必须包含 verdict, score, risk_level, confidence, arguments, evidence_refs, accepted_corrections, "
        "discarded_claims, omissions, contradictions, evidence_chain, feature_relations。 "
        "verdict 只能是 malicious/suspicious/benign；risk_level 只能是 high/medium/low；"
        "score 和 confidence 必须是 0 到 1 小数；数组字段必须是字符串数组。\n"
        f"需要修复的校验错误：{error_text}。\n"
        f"原始输出：\n{raw}"
    )


def fallback_initial(model_name: str, role: dict[str, str], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    scores = [float(item.get("score", 0)) for item in evidence]
    avg = sum(scores) / max(1, len(scores))
    strongest = max(evidence, key=lambda item: float(item.get("score", 0)), default={})
    weakest = min(evidence, key=lambda item: float(item.get("score", 0)), default={})
    focus = weakest if model_name == "model_a" else strongest
    score = clamp(avg * 0.82 + float(focus.get("score", 0)) * 0.18)
    focus_agent = str(focus.get("agent", "unknown"))
    focus_score = float(focus.get("score", 0))
    verdict_text = {
        "malicious": "恶意",
        "suspicious": "可疑",
        "benign": "良性",
    }.get(verdict_from_score(score), "可疑")
    risk_text = {
        "high": "高风险",
        "medium": "中风险",
        "low": "低风险",
    }.get(risk_level(score), "中风险")
    evidence_ref_text = "、".join(evidence_ids(evidence)[:4]) or "四智能体证据"
    top_blocks = sorted(
        evidence,
        key=lambda item: float(item.get("score", 0)),
        reverse=verdict_text != "良性",
    )[:3]
    inference_basis = []
    for block in top_blocks:
        agent = str(block.get("agent", "领域智能体"))
        claim = clean_display_text(block.get("claim") or "")
        block_score = float(block.get("score", 0))
        evidence_items = normalize_list(block.get("evidence"))[:2]
        evidence_text = "；".join(clean_display_text(item) for item in evidence_items if clean_display_text(item))
        if not evidence_text:
            evidence_text = claim or f"证据强度 {block_score:.2f}"
        if verdict_text == "恶意":
            inference_basis.append(
                f"恶意判断依据：{agent}给出的{evidence_text}与其他领域风险信号方向一致，证据强度 {block_score:.2f}，支撑{risk_text}。"
            )
        elif verdict_text == "良性":
            inference_basis.append(
                f"良性判断依据：{agent}当前未形成明确恶意闭环，{evidence_text}的风险支撑不足，证据强度 {block_score:.2f}。"
            )
        else:
            inference_basis.append(
                f"可疑判断依据：{agent}提供的{evidence_text}显示存在风险但证据链仍不完整，证据强度 {block_score:.2f}。"
            )
    if not inference_basis:
        inference_basis = build_inference_basis_from_fallback(
            {"evidence_refs": evidence_ids(evidence)},
            verdict_text,
            risk_text,
            score,
        )
    return {
        "score": score,
        "verdict": verdict_from_score(score),
        "risk_level": risk_level(score),
        "arguments": inference_basis[:3],
        "inference_basis": inference_basis[:3],
        "omissions": list(focus.get("missing_fields", [])),
        "evidence_refs": evidence_ids(evidence),
        "confidence": clamp(0.45 + abs(score - 0.5) * 0.5),
        "evidence_chain": [
            f"{focus_agent}证据块 -> 证据强度 {focus_score:.2f} -> 参与形成{risk_text}初判。",
            f"{evidence_ref_text} -> 综合静态、情报、仿冒和业务侧特征 -> 输出{verdict_text}结论。",
        ],
        "feature_relations": [
            f"{focus_agent}与其余智能体证据共同支撑或约束结论，避免单一字段直接决定最终倾向。"
        ],
        "raw_text": "",
    }


def fallback_turn(
    turn_type: str,
    own: dict[str, Any],
    opponent: dict[str, Any],
    plan: dict[str, Any],
) -> dict[str, Any]:
    own_score = float(own.get("score", 0))
    opponent_score = float(opponent.get("score", own_score))
    score = clamp(own_score * 0.72 + opponent_score * 0.28)
    refs = normalize_list(plan.get("required_evidence_ids") or plan.get("insufficient_citations"))
    if not refs:
        refs = normalize_list(own.get("evidence_refs"))
    ref_text = "、".join(refs[:4]) or "当前已引用证据"
    question = contextual_turn_question(turn_type, own, opponent, plan, refs)
    return {
        "question": question,
        "answer": (
            f"已重新核验 {ref_text}。本方评分由 {own_score:.2f} 调整为 {score:.2f}，"
            "保留有原始证据支持的部分，并接受证据缺口相关质疑。"
        ),
        "score": score,
        "verdict": verdict_from_score(score),
        "risk_level": risk_level(score),
        "confidence": clamp(0.45 + abs(score - 0.5) * 0.5),
        "arguments": list(own.get("arguments", []))[:2] + ["已重新引用原始证据并纳入有效质疑。"],
        "evidence_refs": refs,
        "accepted_challenges": normalize_list(plan.get("logic_jumps"))[:2],
        "rejected_challenges": [],
        "omissions": normalize_list(own.get("omissions")),
        "contradictions": normalize_list(plan.get("intelligence_contradictions"))[:2],
        "evidence_chain": [
            f"{ref_text} -> 复核对方结论是否充分覆盖关键证据",
            f"本方原评分 {own_score:.2f} 与对方评分 {opponent_score:.2f} 对比后调整为 {score:.2f}",
        ],
        "feature_relations": [
            f"{ref_text} 与对方论据进行交叉核验",
        ],
        "turn_type": turn_type,
        "raw_text": "",
    }


GENERIC_TURN_QUESTIONS = (
    "该样本是否应被判定为恶意",
    "该应用是否应被判定为恶意",
    "该样本是否应被判定为高风险",
    "该应用是否应被判定为高风险",
    "是否应被判定为恶意",
    "是否应判定为恶意",
    "是否判定为恶意",
    "是否属于恶意",
    "是否具有恶意",
    "是否为恶意样本",
    "是否应该判定为恶意",
    "该样本是否",
    "该应用是否",
)


def opponent_claim_for_question(opponent: dict[str, Any]) -> str:
    for key in ("arguments", "evidence_chain", "feature_relations", "contradictions", "omissions"):
        for item in normalize_list(opponent.get(key)):
            text = compact_text(clean_display_text(item), 120)
            if text:
                return text
    verdict = opponent.get("verdict", "unknown")
    score = float(opponent.get("score", 0.5) or 0.5)
    return f"对方结论为 {verdict}、恶意倾向 {score:.2f}"


def contextual_turn_question(
    turn_type: str,
    own: dict[str, Any],
    opponent: dict[str, Any],
    plan: dict[str, Any],
    refs: list[str] | None = None,
) -> str:
    opponent_score = float(opponent.get("score", 0.5) or 0.5)
    opponent_verdict = opponent.get("verdict", "unknown")
    claim = opponent_claim_for_question(opponent)
    refs = refs or normalize_list(plan.get("required_evidence_ids") or plan.get("insufficient_citations"))
    if not refs:
        refs = normalize_list(own.get("evidence_refs"))
    ref_text = "、".join(refs[:3]) or "关键证据块"
    conflicts = normalize_list(plan.get("evidence_conflicts")) + normalize_list(plan.get("score_review_conflicts"))
    conflict_text = compact_text(clean_display_text(conflicts[0]), 120) if conflicts else ""
    if turn_type in {"evidence_rebuttal", "role_reversal_rebuttal"}:
        return (
            f"请回应对方围绕“{claim}”提出的质疑，并说明 {ref_text} 中哪些证据支持保留、修正或推翻本方结论。"
        )
    if conflict_text:
        return (
            f"对方结论为 {opponent_verdict}、恶意倾向 {opponent_score:.2f}，其核心依据是“{claim}”。"
            f"请针对“{conflict_text}”说明该结论是否遗漏证据、误用分数或存在逻辑跳跃。"
        )
    return (
        f"对方结论为 {opponent_verdict}、恶意倾向 {opponent_score:.2f}，其核心依据是“{claim}”。"
        f"请结合 {ref_text} 指出该依据是否充分、是否遗漏反向证据，以及质疑成立后结论应如何调整。"
    )


def is_generic_turn_question(text: Any) -> bool:
    cleaned = clean_display_text(text)
    if not cleaned:
        return True
    if any(term in cleaned for term in GENERIC_TURN_QUESTIONS):
        return True
    return len(cleaned) <= 18 and ("恶意" in cleaned or "高风险" in cleaned or cleaned.endswith(("?", "？")))


def fallback_closing(initial: dict[str, Any], latest: dict[str, Any], memory: dict[str, Any]) -> dict[str, Any]:
    score = clamp(float(initial.get("score", 0)) * 0.35 + float(latest.get("score", 0)) * 0.65)
    return {
        "score": score,
        "verdict": verdict_from_score(score),
        "risk_level": risk_level(score),
        "confidence": clamp(0.45 + abs(score - 0.5) * 0.5),
        "arguments": list(latest.get("arguments", []))[:3],
        "evidence_refs": normalize_list(latest.get("evidence_refs")),
        "accepted_corrections": [
            item["phase"] for item in memory.get("stage_summaries", []) if item["phase"] != "initial_testimony"
        ],
        "discarded_claims": [],
        "omissions": normalize_list(latest.get("omissions")),
        "contradictions": normalize_list(latest.get("contradictions")),
        "evidence_chain": normalize_list(latest.get("evidence_chain"))
        or [
            f"初判分数 {float(initial.get('score', 0)):.2f} -> 复核后分数 {float(latest.get('score', 0)):.2f} -> 终审分数 {score:.2f}",
        ],
        "feature_relations": normalize_list(latest.get("feature_relations"))
        or ["终审同时参考初判、反驳轮次和原始证据强度。"],
        "raw_text": "",
    }


def measure_convergence(left: dict[str, Any], right: dict[str, Any]) -> dict[str, Any]:
    score_distance = abs(float(left.get("score", 0)) - float(right.get("score", 0)))
    left_terms = argument_terms(left)
    right_terms = argument_terms(right)
    union = left_terms | right_terms
    similarity = len(left_terms & right_terms) / len(union) if union else 1.0
    return {
        "score_distance": round(score_distance, 4),
        "argument_similarity": round(similarity, 4),
        "same_verdict": left.get("verdict") == right.get("verdict"),
    }


def arbitrate(
    evidence: list[dict[str, Any]],
    initial_a: dict[str, Any],
    initial_b: dict[str, Any],
    closing_a: dict[str, Any],
    closing_b: dict[str, Any],
    memory: dict[str, Any],
    config: dict[str, Any],
) -> dict[str, Any]:
    strongest = max((float(item.get("score", 0)) for item in evidence), default=0.0)
    evidence_avg = sum(float(item.get("score", 0)) for item in evidence) / max(1, len(evidence))
    base_score = clamp(
        float(closing_a.get("score", 0)) * 0.3
        + float(closing_b.get("score", 0)) * 0.3
        + strongest * 0.25
        + evidence_avg * 0.15
    )
    calibration = calibrate_score(base_score, config)
    final_score = calibration["calibrated_score"]
    trace = build_arbiter_trace(initial_a, initial_b, closing_a, closing_b, memory)
    model_confidence = clamp(
        (
            float(closing_a.get("confidence", 0.5))
            + float(closing_b.get("confidence", 0.5))
        )
        / 2
    )
    return {
        "score": final_score,
        "raw_score": base_score,
        "verdict": verdict_from_score(final_score, calibration),
        "verdict_label": verdict_label(final_score, calibration),
        "risk_level": risk_level(final_score, calibration),
        "confidence": model_confidence,
        "rationale": (
            f"终审综合模型甲 {float(closing_a.get('score', 0)):.2f}、"
            f"模型乙 {float(closing_b.get('score', 0)):.2f}、"
            f"最强领域证据 {strongest:.2f} 和平均证据 {evidence_avg:.2f}，"
            f"校准后得到 {final_score:.2f}。"
        ),
        "logic_trace": trace,
        "final_summary": trace["summary"],
        "calibration": calibration,
    }


def build_arbiter_trace(
    initial_a: dict[str, Any],
    initial_b: dict[str, Any],
    closing_a: dict[str, Any],
    closing_b: dict[str, Any],
    memory: dict[str, Any],
) -> dict[str, Any]:
    positions = []
    for model, initial, closing in (
        ("model_a", initial_a, closing_a),
        ("model_b", initial_b, closing_b),
    ):
        delta = round(float(closing.get("score", 0)) - float(initial.get("score", 0)), 4)
        if abs(delta) <= 0.03 and closing.get("verdict") == initial.get("verdict"):
            outcome = "confirmed"
        elif closing.get("verdict") != initial.get("verdict") or abs(delta) >= 0.18:
            outcome = "overturned"
        else:
            outcome = "compromised"
        positions.append(
            {
                "model": model,
                "initial_score": initial.get("score"),
                "closing_score": closing.get("score"),
                "score_delta": delta,
                "initial_verdict": initial.get("verdict"),
                "closing_verdict": closing.get("verdict"),
                "outcome": outcome,
                "accepted_corrections": closing.get("accepted_corrections", []),
                "discarded_claims": closing.get("discarded_claims", []),
            }
        )
    turning_points = []
    for item in memory.get("stage_summaries", []):
        if item["phase"] in {"directed_attack", "evidence_rebuttal"}:
            turning_points.append(
                {
                    "phase": item["phase"],
                    "round": item.get("round"),
                    "positions": item.get("positions", []),
                }
            )
    outcome_labels = {"confirmed": "确认", "overturned": "推翻", "compromised": "折中修正"}
    summary_parts = [
        f"{item['model']} 的初始立场被{outcome_labels[item['outcome']]}"
        for item in positions
    ]
    return {
        "positions": positions,
        "turning_points": turning_points,
        "summary": "；".join(summary_parts) + "。裁决分数同时参考原始证据强度与校准阈值。",
    }


def calibrate_score(raw_score: float, config: dict[str, Any]) -> dict[str, Any]:
    defaults = {
        "malicious_threshold": 0.85,
        "suspicious_threshold": 0.6,
        "accuracy": None,
        "sample_count": 0,
        "source": "default",
    }
    try:
        data = json.loads(CALIBRATION_PATH.read_text(encoding="utf-8"))
        params = data.get("params", {})
        defaults.update(
            {
                "malicious_threshold": float(params.get("malicious_threshold", defaults["malicious_threshold"])),
                "suspicious_threshold": float(params.get("suspicious_threshold", defaults["suspicious_threshold"])),
                "accuracy": data.get("accuracy"),
                "sample_count": int(data.get("total", 0)),
                "source": str(CALIBRATION_PATH),
            }
        )
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    override = config.get("calibration") if isinstance(config.get("calibration"), dict) else {}
    defaults.update({key: override[key] for key in defaults if key in override})
    malicious_threshold = float(defaults["malicious_threshold"])
    suspicious_threshold = float(defaults["suspicious_threshold"])
    calibrated = raw_score
    if raw_score >= malicious_threshold:
        calibrated = malicious_threshold + (raw_score - malicious_threshold) * 0.9
    elif raw_score >= suspicious_threshold:
        calibrated = suspicious_threshold + (raw_score - suspicious_threshold) * 0.95
    return {
        **defaults,
        "raw_score": round(raw_score, 4),
        "calibrated_score": clamp(calibrated),
    }


def append_stage(
    stages: list[dict[str, Any]],
    memory: dict[str, Any],
    token_usage: dict[str, int],
    stage: dict[str, Any],
) -> None:
    stages.append(stage)
    memory["stage_summaries"].append(compress_stage(stage))
    account_usage(token_usage, *stage["turns"])


def stage_record(phase: str, round_number: int, turns: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "phase": phase,
        "round": round_number,
        "turns": turns,
        "latency_ms": max([int(item.get("latency_ms", 0)) for item in turns] or [0]),
        "token_usage": {
            "prompt_tokens": sum(int(item.get("prompt_tokens", 0)) for item in turns),
            "completion_tokens": sum(int(item.get("completion_tokens", 0)) for item in turns),
        },
    }


def compress_stage(stage: dict[str, Any]) -> dict[str, Any]:
    return {
        "phase": stage["phase"],
        "round": stage["round"],
        "positions": [
            {
                "model": "model_a" if index == 0 else "model_b",
                "verdict": turn.get("verdict"),
                "score": turn.get("score"),
                "key_arguments": normalize_list(turn.get("arguments"))[:2],
                "evidence_refs": normalize_list(turn.get("evidence_refs"))[:4],
                "accepted_challenges": normalize_list(turn.get("accepted_challenges"))[:2],
                "question": str(turn.get("question", ""))[:180],
                "answer": str(turn.get("answer", ""))[:220],
            }
            for index, turn in enumerate(stage["turns"])
        ],
    }


def summarize_evidence(evidence: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "agents": [
            {
                "agent": item.get("agent"),
                "claim": item.get("claim"),
                "score": item.get("score"),
                "confidence": item.get("confidence"),
                "key_evidence": normalize_list(item.get("evidence"))[:2],
                "missing_fields": normalize_list(item.get("missing_fields")),
            }
            for item in evidence
        ]
    }


def flatten_debate_turns(stages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for stage in stages:
        if stage["phase"] not in {"directed_attack", "evidence_rebuttal"}:
            continue
        for index, turn in enumerate(stage["turns"]):
            result.append(
                {
                    "round": stage["round"],
                    "type": "challenge" if stage["phase"] == "directed_attack" else "rebuttal",
                    "from": "model_a" if index == 0 else "model_b",
                    "to": "model_b" if index == 0 else "model_a",
                    "from_label": "模型甲" if index == 0 else "模型乙",
                    "to_label": "模型乙" if index == 0 else "模型甲",
                    "question": clean_display_text(turn.get("question", "")),
                    "answer": clean_display_text(turn.get("answer", "")),
                    "evidence_refs": turn.get("evidence_refs", []),
                }
            )
    return result


def public_model_result(result: dict[str, Any], role: dict[str, str]) -> dict[str, Any]:
    return {
        "role": role["name"],
        "strategy": role["strategy"],
        "score": result["score"],
        "verdict": result["verdict"],
        "verdict_label": verdict_label(float(result["score"])),
        "risk_level": result.get("risk_level", risk_level(float(result["score"]))),
        "arguments": clean_text_list(result.get("arguments")),
        "evidence_refs": normalize_list(result.get("evidence_refs")),
        "confidence": result.get("confidence", 0.5),
        "evidence_chain": clean_text_list(result.get("evidence_chain")),
        "feature_relations": clean_text_list(result.get("feature_relations")),
        "contradictions": clean_text_list(result.get("contradictions")),
        "accepted_corrections": clean_text_list(result.get("accepted_corrections")),
        "discarded_claims": clean_text_list(result.get("discarded_claims")),
        "logic_summary": model_logic_summary(result, role),
        "schema_completed_fields": result.get("schema_completed_fields", []),
        "validation_warning": result.get("validation_warning", ""),
        "model_backend": result.get("backend", "rule"),
        "raw_text": result.get("raw_text", ""),
    }


def model_logic_summary(result: dict[str, Any], role: dict[str, str]) -> str:
    score = clamp(float(result.get("score", 0.5)))
    verdict = verdict_label(score)
    risk = {"high": "高风险", "medium": "中风险", "low": "低风险"}.get(
        str(result.get("risk_level") or risk_level(score)),
        "未知风险",
    )
    arguments = clean_text_list(result.get("arguments"))[:3]
    evidence_refs = normalize_list(result.get("evidence_refs"))[:4]
    contradictions = clean_text_list(result.get("contradictions"))[:2]
    chain = clean_text_list(result.get("evidence_chain"))[:2]
    pieces = [
        f"{role['name']}按照“{role['strategy']}”进行复核，给出{verdict}结论，风险等级为{risk}，恶意倾向分为 {score:.3f}。"
    ]
    if evidence_refs:
        pieces.append(f"主要引用证据块：{'、'.join(evidence_refs)}。")
    if arguments:
        pieces.append(f"核心论据：{'；'.join(arguments)}。")
    if chain:
        pieces.append(f"证据链：{'；'.join(chain)}。")
    if contradictions:
        pieces.append(f"需要注意的矛盾或缺口：{'；'.join(contradictions)}。")
    return clean_display_text("".join(pieces))


def with_metrics(fallback: dict[str, Any], backend: str, phase: str, prompt: str) -> dict[str, Any]:
    return {
        **fallback,
        "backend": backend,
        "phase": phase,
        "latency_ms": 0,
        "prompt_tokens": estimate_tokens(prompt),
        "completion_tokens": estimate_tokens(json.dumps(fallback, ensure_ascii=False)),
    }


def account_usage(total: dict[str, int], *turns: dict[str, Any]) -> None:
    for turn in turns:
        total["prompt_tokens"] += int(turn.get("prompt_tokens", 0))
        total["completion_tokens"] += int(turn.get("completion_tokens", 0))
    total["total_tokens"] = total["prompt_tokens"] + total["completion_tokens"]


def argument_terms(result: dict[str, Any]) -> set[str]:
    text = " ".join(normalize_list(result.get("arguments"))).lower()
    return {item for item in text.replace("；", " ").replace("、", " ").split() if len(item) >= 2}


def evidence_ids(evidence: list[dict[str, Any]]) -> list[str]:
    return [str(item.get("agent")) for item in evidence if item.get("agent")]


def normalize_list(value: Any) -> list[str]:
    if isinstance(value, list):
        result = []
        for item in value:
            if isinstance(item, list):
                nested = normalize_list(item)
                if nested:
                    result.append(" → ".join(nested))
            elif isinstance(item, dict):
                description = str(item.get("description") or "").strip()
                source_values = item.get("source_values")
                details = ""
                if isinstance(source_values, dict) and source_values:
                    details = "；".join(f"{key}={value}" for key, value in source_values.items())
                text = description
                if details:
                    text = f"{text}（{details}）" if text else details
                if not text:
                    parts = []
                    if item.get("evidence_refs"):
                        parts.append(f"引用证据块：{'、'.join(normalize_list(item.get('evidence_refs')))}")
                    if item.get("omissions"):
                        parts.append(f"缺失或遗漏：{'、'.join(normalize_list(item.get('omissions')))}")
                    if item.get("score") not in ("", None):
                        parts.append(f"模型评分：{item.get('score')}")
                    if item.get("verdict"):
                        parts.append(f"模型结论：{item.get('verdict')}")
                    text = "；".join(parts) or "模型返回了结构化对象，但未提供可读说明。"
                result.append(text)
            elif str(item).strip():
                result.append(str(item))
        return result
    if value in ("", None):
        return []
    return [str(value)]


def placeholder_model_output(
    parsed: dict[str, Any],
    raw: str,
    fallback: dict[str, Any],
    phase: str,
) -> bool:
    text = str(raw or "")
    compact_text = clean_display_text(text).strip()
    if not compact_text:
        return True
    placeholder_terms = (
        "malicious|suspicious|benign",
        "high|medium|low",
        "定向质疑",
        "证据化回应",
        "修正后论据",
        "证据块agent",
        "重新引用的证据块agent",
        "放弃的论点",
    )
    if not parsed:
        return True
    try:
        score = float(parsed.get("score"))
    except (TypeError, ValueError):
        return True
    has_arguments = bool(normalize_list(parsed.get("arguments")))
    has_refs = bool(normalize_list(parsed.get("evidence_refs")))
    has_chain = bool(normalize_list(parsed.get("evidence_chain")))
    if any(term in compact_text for term in placeholder_terms):
        # A normal model answer may mention "定向质疑" or similar stage names in a valid JSON field.
        # Treat it as fatal only when the whole answer is essentially a short template fragment.
        if len(compact_text) < 120 or not (has_arguments or has_refs or has_chain):
            return True
    if score == 0.0 and float(fallback.get("score", 0.0)) >= 0.15 and not (has_arguments or has_refs):
        return True
    if phase in {"directed_attack", "evidence_rebuttal"}:
        question = str(parsed.get("question") or "").strip()
        answer = str(parsed.get("answer") or "").strip()
        if not question or not answer:
            return True
    return False


def estimate_tokens(text: str) -> int:
    return max(1, (len(str(text)) + 3) // 4)


def clamp(value: float) -> float:
    return max(0.0, min(1.0, round(value, 4)))


def verdict_from_score(score: float, calibration: dict[str, Any] | None = None) -> str:
    malicious = float((calibration or {}).get("malicious_threshold", 0.85))
    suspicious = float((calibration or {}).get("suspicious_threshold", 0.6))
    if score >= malicious:
        return "malicious"
    if score >= suspicious:
        return "suspicious"
    return "benign"


def risk_level(score: float, calibration: dict[str, Any] | None = None) -> str:
    verdict = verdict_from_score(score, calibration)
    return {"malicious": "high", "suspicious": "medium", "benign": "low"}[verdict]


def verdict_label(score: float, calibration: dict[str, Any] | None = None) -> str:
    return {"malicious": "恶意", "suspicious": "可疑", "benign": "良性"}[
        verdict_from_score(score, calibration)
    ]




