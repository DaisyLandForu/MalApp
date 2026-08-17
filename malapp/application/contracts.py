"""Application-layer requests independent of HTTP, batch, and MCP transports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class JudgementRequest:
    sample: dict[str, Any]
    source: str

    @classmethod
    def from_payload(cls, payload: Any, *, source: str) -> JudgementRequest:
        if not isinstance(payload, dict) or not payload:
            raise ValueError("sample must be a non-empty JSON object")
        clean_source = str(source).strip()
        if not clean_source:
            raise ValueError("judgement request source is required")
        return cls(sample=dict(payload), source=clean_source)
