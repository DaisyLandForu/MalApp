"""ASGI middleware enforcing declared and streamed request body limits."""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from apps.server.config import ServerConfig

ASGIMessage = dict[str, Any]
Receive = Callable[[], Awaitable[ASGIMessage]]
Send = Callable[[ASGIMessage], Awaitable[None]]

UPLOAD_PATHS = frozenset(
    {
        "/api/data/excel-preview",
        "/api/data/import-excel",
        "/api/static-analysis",
    }
)


class RequestSizeLimitMiddleware:
    def __init__(self, app: Any, config: ServerConfig):
        self.app = app
        self.config = config

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path") or "")
        limit = self.config.max_upload_bytes if path in UPLOAD_PATHS else self.config.max_json_bytes
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length:
            try:
                declared_length = int(raw_length)
            except ValueError:
                await self._error(send, 400, "Invalid Content-Length")
                return
            if declared_length < 0:
                await self._error(send, 400, "Invalid Content-Length")
                return
            if declared_length > limit:
                await self._error(send, 413, f"Payload exceeds the {limit}-byte limit")
                return

        received = 0
        buffered: list[ASGIMessage] = []
        while True:
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    await self._error(send, 413, f"Payload exceeds the {limit}-byte limit")
                    return
            buffered.append(message)
            if message.get("type") == "http.disconnect" or not message.get("more_body", False):
                break

        async def replay_receive() -> ASGIMessage:
            if buffered:
                return buffered.pop(0)
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)

    @staticmethod
    async def _error(send: Send, status_code: int, message: str) -> None:
        body = json.dumps({"error": message}, ensure_ascii=False).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
