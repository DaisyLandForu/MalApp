from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request, status

from apps.server.auth import require_authenticated, server_config
from apps.server.limits import bounded_int, payload_object
from malapp.application.contracts import JudgementRequest
from malapp.application.dashboard import dashboard_overview
from malapp.application.judgement import list_reports
from malapp.application.service import get_judgement_service
from malapp.observability.rewards import get_reward, list_rewards
from malapp.observability.trace import get_trace, list_human_reviews, list_traces, save_human_review

router = APIRouter(dependencies=[Depends(require_authenticated)])


@router.post("/api/judgements", status_code=status.HTTP_201_CREATED)
def create_judgement(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    request = JudgementRequest.from_payload(payload_object(payload), source="web_api")
    return get_judgement_service().judge(request)


@router.get("/api/reports")
def reports(request: Request, limit: int = Query(50)) -> dict[str, Any]:
    config = server_config(request)
    return {
        "items": list_reports(
            limit=bounded_int(limit, name="limit", default=50, maximum=config.max_query_limit)
        )
    }


@router.get("/api/agent-traces")
def traces(request: Request, limit: int = Query(100)) -> dict[str, Any]:
    config = server_config(request)
    return {
        "items": list_traces(
            limit=bounded_int(limit, name="limit", default=100, maximum=config.max_query_limit)
        )
    }


@router.get("/api/agent-trace")
def trace(report_id: str = "", trace_id: str = "", run_id: str = "") -> dict[str, Any]:
    result = get_trace(report_id=report_id, trace_id=trace_id, run_id=run_id)
    if not result:
        raise HTTPException(404, "trace not found")
    return result


@router.get("/api/human-reviews")
def human_reviews(request: Request, limit: int = Query(200)) -> dict[str, Any]:
    config = server_config(request)
    return {
        "items": list_human_reviews(
            limit=bounded_int(limit, name="limit", default=200, maximum=config.max_query_limit)
        )
    }


@router.post("/api/human-reviews", status_code=status.HTTP_201_CREATED)
def create_human_review(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    report_id = str(item.get("report_id") or "").strip()
    if not report_id:
        raise ValueError("report_id is required")
    return save_human_review(
        report_id=report_id,
        human_label=str(item.get("human_label") or "").strip(),
        notes=str(item.get("notes") or ""),
        reviewer=str(item.get("reviewer") or ""),
        is_correct=item.get("is_correct") if "is_correct" in item else None,
        error_types=item.get("error_types"),
        evidence_supported=item.get("evidence_supported"),
        json_valid=item.get("json_valid"),
        concise=item.get("concise"),
        punctuation_valid=item.get("punctuation_valid"),
        hallucination=item.get("hallucination"),
        corrected_output=str(item.get("corrected_output") or ""),
        review_status=str(item.get("review_status") or "reviewed"),
        second_reviewer=str(item.get("second_reviewer") or ""),
        adjudication_notes=str(item.get("adjudication_notes") or ""),
    )


@router.get("/api/rewards")
def rewards(request: Request, report_id: str = "", limit: int = Query(200)) -> dict[str, Any]:
    if report_id:
        return get_reward(report_id) or {"error": "reward not found"}
    config = server_config(request)
    return {
        "items": list_rewards(
            limit=bounded_int(limit, name="limit", default=200, maximum=config.max_query_limit)
        )
    }


@router.get("/api/dashboard/overview")
def dashboard() -> dict[str, Any]:
    return dashboard_overview()
