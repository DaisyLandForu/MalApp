"""Explicit state machine for the authoritative judgement pipeline."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

PIPELINE_STAGES = (
    "NORMALIZE",
    "STATIC_EXTRACTION",
    "AGENT_EXECUTION",
    "RAG_RETRIEVAL",
    "XGB_INFERENCE",
    "DEBATE",
    "FINAL_DECISION",
    "PERSIST",
)
TERMINAL_STAGE_STATUSES = {"completed", "failed", "degraded", "skipped"}


@dataclass
class StageRecord:
    name: str
    status: str = "pending"
    started_at: float | None = None
    completed_at: float | None = None
    latency_ms: float = 0.0
    error: str | None = None
    degradation_reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    _started_mono: float | None = field(default=None, repr=False)

    def public(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "latency_ms": self.latency_ms,
            "error": self.error,
            "degradation_reasons": list(self.degradation_reasons),
            "metadata": dict(self.metadata),
        }


class PipelineStateMachine:
    def __init__(self, pipeline_id: str | None = None):
        self.pipeline_id = pipeline_id or f"pipeline-{uuid.uuid4().hex[:16]}"
        self.started_at = time.time()
        self._records = {name: StageRecord(name=name) for name in PIPELINE_STAGES}
        self._active: str | None = None

    def start(self, stage: str) -> None:
        record = self._record(stage)
        if self._active is not None:
            raise RuntimeError(f"pipeline stage {self._active} is still active")
        if record.status != "pending":
            raise RuntimeError(f"pipeline stage {stage} already entered")
        index = PIPELINE_STAGES.index(stage)
        unfinished = [name for name in PIPELINE_STAGES[:index] if self._records[name].status not in TERMINAL_STAGE_STATUSES]
        if unfinished:
            raise RuntimeError(f"pipeline stage order violation before {stage}: {unfinished}")
        record.status = "started"
        record.started_at = time.time()
        record._started_mono = time.monotonic()
        self._active = stage

    def complete(self, stage: str, metadata: dict[str, Any] | None = None) -> None:
        self._finish(stage, "completed", metadata=metadata)

    def degrade(
        self,
        stage: str,
        reasons: list[str] | tuple[str, ...] | str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        values = [reasons] if isinstance(reasons, str) else list(reasons)
        self._finish(stage, "degraded", reasons=[str(item) for item in values], metadata=metadata)

    def fail(self, stage: str, error: Exception | str, metadata: dict[str, Any] | None = None) -> None:
        self._finish(stage, "failed", error=str(error), metadata=metadata)

    def skip(self, stage: str, reason: str, metadata: dict[str, Any] | None = None) -> None:
        record = self._record(stage)
        if self._active == stage and record.status == "started":
            self._finish(stage, "skipped", reasons=[str(reason)], metadata=metadata)
            return
        if self._active is not None:
            raise RuntimeError(f"pipeline stage {self._active} is still active")
        if record.status != "pending":
            raise RuntimeError(f"pipeline stage {stage} already entered")
        index = PIPELINE_STAGES.index(stage)
        unfinished = [name for name in PIPELINE_STAGES[:index] if self._records[name].status not in TERMINAL_STAGE_STATUSES]
        if unfinished:
            raise RuntimeError(f"pipeline stage order violation before {stage}: {unfinished}")
        now = time.time()
        record.status = "skipped"
        record.started_at = now
        record.completed_at = now
        record.degradation_reasons = [str(reason)]
        record.metadata = dict(metadata or {})

    def snapshot(self) -> dict[str, Any]:
        stages = [self._records[name].public() for name in PIPELINE_STAGES]
        statuses = {item["status"] for item in stages}
        if "failed" in statuses:
            status = "failed"
        elif "degraded" in statuses:
            status = "degraded"
        elif statuses <= TERMINAL_STAGE_STATUSES:
            status = "completed"
        else:
            status = "running"
        return {
            "pipeline_id": self.pipeline_id,
            "status": status,
            "started_at": self.started_at,
            "completed_at": time.time() if status != "running" else None,
            "stage_order": list(PIPELINE_STAGES),
            "stages": stages,
            "by_name": {item["name"]: item for item in stages},
        }

    def _finish(
        self,
        stage: str,
        status: str,
        *,
        error: str | None = None,
        reasons: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        record = self._record(stage)
        if self._active != stage or record.status != "started":
            raise RuntimeError(f"pipeline stage {stage} is not active")
        record.status = status
        record.completed_at = time.time()
        record.latency_ms = round((time.monotonic() - (record._started_mono or time.monotonic())) * 1000, 3)
        record.error = error
        record.degradation_reasons = list(reasons or [])
        record.metadata = dict(metadata or {})
        self._active = None

    def _record(self, stage: str) -> StageRecord:
        if stage not in self._records:
            raise ValueError(f"unknown pipeline stage: {stage}")
        return self._records[stage]
