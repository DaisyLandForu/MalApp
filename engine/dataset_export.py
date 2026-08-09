from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
DB_PATH = DATA_DIR / "mvp.db"


def connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def _load_reports(limit: int = 5000) -> list[dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT payload_json FROM judgements
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 100000)),),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]
    finally:
        conn.close()


def _load_reviews() -> dict[str, dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT report_id, payload_json FROM human_reviews
            ORDER BY created_at ASC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()
    reviews: dict[str, dict[str, Any]] = {}
    for report_id, payload in rows:
        reviews[report_id] = json.loads(payload)
    return reviews


def _load_rewards() -> dict[str, dict[str, Any]]:
    conn = connect()
    try:
        rows = conn.execute(
            """
            SELECT report_id, reward_id, reward, components_json, created_at
            FROM reward_records
            ORDER BY created_at ASC
            """
        ).fetchall()
    except sqlite3.OperationalError:
        return {}
    finally:
        conn.close()
    rewards: dict[str, dict[str, Any]] = {}
    for report_id, reward_id, reward, components_json, created_at in rows:
        rewards[report_id] = {
            "reward_id": reward_id,
            "reward": reward,
            "components": json.loads(components_json),
            "created_at": created_at,
        }
    return rewards


def _agent_summary(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for block in report.get("evidence_blocks") or []:
        items = block.get("evidence_items") or block.get("evidence") or []
        rows.append(
            {
                "agent": block.get("agent"),
                "claim": block.get("claim"),
                "malicious_probability": block.get("score"),
                "confidence": block.get("confidence"),
                "top_evidence": items[:5],
                "missing_fields": (block.get("missing_fields") or [])[:8],
            }
        )
    return rows


def _debate_summary(report: dict[str, Any]) -> dict[str, Any]:
    debate = report.get("debate") or {}
    return {
        "model_a": debate.get("model_a"),
        "model_b": debate.get("model_b"),
        "cross_examination": debate.get("cross_examination"),
        "arbiter": debate.get("arbiter"),
    }


def _report_generation_output(report: dict[str, Any], review: dict[str, Any] | None = None) -> dict[str, Any]:
    decision = dict(report.get("decision") or {})
    if review and review.get("human_label") in {"malicious", "suspicious", "benign"}:
        decision["human_label"] = review["human_label"]
        decision["human_notes"] = review.get("notes") or ""
    return {
        "verdict": decision.get("verdict"),
        "risk_level": decision.get("risk_level"),
        "final_score": decision.get("final_score"),
        "key_evidence": decision.get("key_evidence") or [],
        "evidence_chain": [
            "从四智能体 EvidenceBlock 中提取可验证字段。",
            "结合机器学习恶意概率、双模型初判和终审裁决形成结论。",
            "若存在人工复核标签，以人工标签作为后续训练的高可信反馈。",
        ],
        "decision": decision,
    }


def build_report_sft_rows(reports: list[dict[str, Any]], reviews: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for report in reports:
        report_id = report.get("report_id") or ""
        review = reviews.get(report_id)
        if not review or review.get("review_status", "reviewed") not in {"reviewed", "adjudicated"}:
            continue
        corrected_output = str(review.get("corrected_output") or "").strip()
        if review.get("is_correct") not in {1, True} and not corrected_output:
            continue
        output: Any = _report_generation_output(report, review)
        if corrected_output:
            try:
                output = json.loads(corrected_output)
            except json.JSONDecodeError:
                output = {"corrected_text": corrected_output, "human_label": review.get("human_label")}
        rows.append(
            {
                "id": f"sft-report-{report_id}",
                "task": "report_generation",
                "instruction": "根据样本基础信息、四智能体 EvidenceBlock、RAG 摘要和双模型辩论摘要，输出稳定的中文恶意 APP 研判报告 JSON。",
                "input": {
                    "sample": report.get("sample") or {},
                    "agent_evidence": _agent_summary(report),
                    "rag_context": (report.get("evidence_layers") or {}).get("rag_context") or {},
                    "debate": _debate_summary(report),
                    "reward": report.get("execution", {}).get("reward"),
                },
                "output": output,
                "review_metadata": {
                    "review_id": review.get("review_id"),
                    "review_status": review.get("review_status", "reviewed"),
                    "error_types": review.get("error_types") or [],
                },
            }
        )
    return rows


def build_dpo_rows(reports: list[dict[str, Any]], reviews: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for report in reports:
        report_id = report.get("report_id") or ""
        review = reviews.get(report_id)
        if not review or review.get("review_status", "reviewed") not in {"reviewed", "adjudicated"}:
            continue
        human_label = review.get("human_label")
        if human_label not in {"malicious", "suspicious", "benign"}:
            continue
        corrected_output = str(review.get("corrected_output") or "").strip()
        semantic_wrong = review.get("is_correct") in {0, False}
        style_or_quality_wrong = any(
            (
                review.get("evidence_supported") is False,
                review.get("json_valid") is False,
                review.get("concise") is False,
                review.get("punctuation_valid") is False,
                review.get("hallucination") is True,
                bool(review.get("error_types")),
            )
        )
        if not semantic_wrong and not (style_or_quality_wrong and corrected_output):
            continue
        prompt = {
            "sample": report.get("sample") or {},
            "agent_evidence": _agent_summary(report),
            "debate": _debate_summary(report),
        }
        chosen = _report_generation_output(report, review)
        chosen["verdict"] = human_label
        chosen["human_correction"] = review.get("notes") or "人工复核修正模型结论。"
        if corrected_output:
            try:
                chosen = json.loads(corrected_output)
            except json.JSONDecodeError:
                chosen["corrected_text"] = corrected_output
        rejected = _report_generation_output(report, None)
        rows.append(
            {
                "id": f"dpo-report-{report_id}",
                "task": "report_preference",
                "prompt": prompt,
                "chosen": chosen,
                "rejected": rejected,
                "preference_metadata": {
                    "review_id": review.get("review_id"),
                    "error_types": review.get("error_types") or [],
                    "semantic_wrong": semantic_wrong,
                    "style_or_quality_wrong": style_or_quality_wrong,
                },
            }
        )
    return rows


def _policy_label(report: dict[str, Any], review: dict[str, Any] | None, reward: dict[str, Any] | None) -> dict[str, int]:
    decision = report.get("decision") or {}
    evidence_blocks = report.get("evidence_blocks") or []
    final_score = float(decision.get("final_score") or 0.0)
    final_conf = float(decision.get("confidence") or decision.get("final_confidence") or 0.0)
    missing_count = sum(len(block.get("missing_fields") or []) for block in evidence_blocks)
    debate = report.get("debate") or {}
    xgb = ((decision.get("fusion") or {}).get("xgb_probability") or 0.0)
    llm = ((decision.get("fusion") or {}).get("llm_probability") or 0.0)
    wrong = bool(review and review.get("is_correct") in {0, False})
    low_reward = bool(reward and float(reward.get("reward") or 0.0) < 0.55)
    return {
        "use_rag": int(missing_count >= 4 or any("threat" in str(block.get("agent")) for block in evidence_blocks)),
        "full_debate": int(wrong or abs(float(xgb) - float(llm)) >= 0.25 or 0.35 <= final_score <= 0.65 or not debate.get("cross_examination")),
        "human_review": int(wrong or low_reward or final_conf < 0.6 or 0.35 <= final_score <= 0.65 or missing_count >= 8),
    }


def build_policy_rows(
    reports: list[dict[str, Any]],
    reviews: dict[str, dict[str, Any]],
    rewards: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for report in reports:
        report_id = report.get("report_id") or ""
        decision = report.get("decision") or {}
        fusion = decision.get("fusion") or {}
        evidence_blocks = report.get("evidence_blocks") or []
        features = {
            "final_score": decision.get("final_score"),
            "final_confidence": decision.get("confidence") or decision.get("final_confidence"),
            "xgb_probability": fusion.get("xgb_probability"),
            "llm_probability": fusion.get("llm_probability"),
            "llm_confidence": fusion.get("llm_confidence"),
            "evidence_block_count": len(evidence_blocks),
            "evidence_item_count": sum(len(b.get("evidence_items") or b.get("evidence") or []) for b in evidence_blocks),
            "missing_field_count": sum(len(b.get("missing_fields") or []) for b in evidence_blocks),
            "agent_scores": {b.get("agent"): b.get("score") for b in evidence_blocks},
            "reward": (rewards.get(report_id) or {}).get("reward"),
        }
        rows.append(
            {
                "id": f"policy-{report_id}",
                "task": "policy_decision",
                "features": features,
                "label": _policy_label(report, reviews.get(report_id), rewards.get(report_id)),
            }
        )
    return rows


def export_all_datasets(output_dir: str | None = None, limit: int = 5000) -> dict[str, Any]:
    reports = _load_reports(limit=limit)
    reviews = _load_reviews()
    rewards = _load_rewards()
    out_dir = Path(output_dir).expanduser().resolve() if output_dir else DATA_DIR / "exports" / f"training_loop_{_stamp()}"
    sft_rows = build_report_sft_rows(reports, reviews)
    dpo_rows = build_dpo_rows(reports, reviews)
    policy_rows = build_policy_rows(reports, reviews, rewards)
    files = {
        "report_generation_sft": out_dir / "report_generation_sft.jsonl",
        "debate_dpo": out_dir / "debate_dpo.jsonl",
        "policy_training": out_dir / "policy_training.jsonl",
        "summary": out_dir / "export_summary.json",
    }
    _write_jsonl(files["report_generation_sft"], sft_rows)
    _write_jsonl(files["debate_dpo"], dpo_rows)
    _write_jsonl(files["policy_training"], policy_rows)
    summary = {
        "created_at": datetime.now().isoformat(),
        "report_count": len(reports),
        "human_review_count": len(reviews),
        "reward_count": len(rewards),
        "report_generation_sft_count": len(sft_rows),
        "debate_dpo_count": len(dpo_rows),
        "policy_training_count": len(policy_rows),
        "files": {name: str(path) for name, path in files.items()},
    }
    files["summary"].write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary
