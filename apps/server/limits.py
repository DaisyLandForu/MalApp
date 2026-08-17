"""Central request, query and batch limit helpers."""

from __future__ import annotations

from typing import Any


def bounded_int(
    value: Any,
    *,
    name: str,
    default: int,
    maximum: int,
    minimum: int = 1,
) -> int:
    candidate = default if value in (None, "") else value
    try:
        parsed = int(candidate)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def payload_object(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    return payload
