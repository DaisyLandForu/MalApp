from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status

from apps.server.auth import require_admin, server_config
from apps.server.limits import bounded_int, payload_object
from malapp.application.batch import (
    get_batch_job,
    pause_batch_judgement,
    resume_batch_judgement,
    retry_failed_batch_judgement,
    start_batch_judgement,
)

router = APIRouter(dependencies=[Depends(require_admin)])


@router.get("/api/batch-jobs/status")
def batch_status(job_id: str = "") -> dict[str, Any]:
    try:
        return get_batch_job(job_id)
    except Exception as exc:
        raise HTTPException(404, str(exc)) from exc


@router.post("/api/batch-jobs/start", status_code=status.HTTP_201_CREATED)
def start_batch(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    limit = bounded_int(
        item.get("limit"),
        name="limit",
        default=1,
        maximum=server_config(request).max_batch_items,
    )
    return start_batch_judgement(str(item.get("batch_id") or ""), limit)


@router.post("/api/batch-jobs/pause")
def pause_batch(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return pause_batch_judgement(str(payload_object(payload).get("job_id") or ""))


@router.post("/api/batch-jobs/resume")
def resume_batch(payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    return resume_batch_judgement(str(payload_object(payload).get("job_id") or ""))


@router.post("/api/batch-jobs/retry-failed", status_code=status.HTTP_201_CREATED)
def retry_failed_batch(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    raw_limit = item.get("limit")
    limit = (
        bounded_int(
            raw_limit,
            name="limit",
            default=1,
            maximum=server_config(request).max_batch_items,
        )
        if raw_limit not in (None, "")
        else None
    )
    return retry_failed_batch_judgement(str(item.get("job_id") or ""), limit)
