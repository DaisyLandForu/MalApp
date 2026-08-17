"""Shared identifiers and safe digests for end-to-end observability."""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "credentials",
    "password",
    "secret",
    "access_token",
    "refresh_token",
    "bearer_token",
}


def new_run_id() -> str:
    """Return an opaque identifier shared by every artifact from one invocation."""
    return f"run-{uuid.uuid4().hex[:20]}"


def sanitized(value: Any) -> Any:
    """Recursively remove credentials before observability data is persisted."""
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in _SECRET_KEYS or normalized.endswith("_api_key") or normalized.endswith("_secret"):
                clean[str(key)] = "[REDACTED]"
            else:
                clean[str(key)] = sanitized(item)
        return clean
    if isinstance(value, (list, tuple, set)):
        return [sanitized(item) for item in value]
    if isinstance(value, bytes):
        return f"<bytes:{len(value)}>"
    try:
        json.dumps(value)
    except (TypeError, ValueError):
        return str(value)
    return value


def safe_digest(value: Any) -> str:
    """Hash canonical, credential-free JSON without retaining the input itself."""
    payload = json.dumps(
        sanitized(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return f"sha256:{hashlib.sha256(payload.encode('utf-8')).hexdigest()}"


def exception_type(error: Exception | str | None) -> str | None:
    if isinstance(error, Exception):
        return type(error).__name__
    return "RuntimeError" if error else None
