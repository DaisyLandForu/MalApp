from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any, BinaryIO


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.hermes_bridge import TOOL_DEFINITIONS, TOOL_HANDLERS  # noqa: E402


PROTOCOL_VERSION = "2024-11-05"


def main() -> None:
    transport = JsonRpcTransport(sys.stdin.buffer, sys.stdout.buffer)
    while True:
        request = transport.read()
        if request is None:
            return
        if "id" not in request:
            continue
        response = dispatch(request)
        transport.write(response)


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    request_id = request.get("id")
    method = request.get("method")
    params = request.get("params") if isinstance(request.get("params"), dict) else {}
    try:
        if method == "initialize":
            result = {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {
                    "name": "malapp-hermes-tools",
                    "version": "1.0.0",
                },
            }
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOL_DEFINITIONS}
        elif method == "tools/call":
            result = call_tool(params)
        else:
            return error_response(request_id, -32601, f"Method not found: {method}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    except Exception as exc:
        traceback.print_exc(file=sys.stderr)
        return error_response(request_id, -32000, str(exc))


def call_tool(params: dict[str, Any]) -> dict[str, Any]:
    name = str(params.get("name") or "")
    arguments = params.get("arguments")
    if name not in TOOL_HANDLERS:
        raise ValueError(f"Unknown tool: {name}")
    if not isinstance(arguments, dict):
        arguments = {}
    result = TOOL_HANDLERS[name](arguments)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    return {
        "content": [{"type": "text", "text": text}],
        "structuredContent": result,
        "isError": False,
    }


def error_response(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class JsonRpcTransport:
    def __init__(self, reader: BinaryIO, writer: BinaryIO):
        self.reader = reader
        self.writer = writer
        self.framing = "newline"

    def read(self) -> dict[str, Any] | None:
        first = self.reader.readline()
        if not first:
            return None
        if first.lower().startswith(b"content-length:"):
            self.framing = "content-length"
            length = int(first.split(b":", 1)[1].strip())
            while True:
                header = self.reader.readline()
                if header in {b"\r\n", b"\n", b""}:
                    break
            payload = self.reader.read(length)
        else:
            self.framing = "newline"
            payload = first.strip()
        if not payload:
            return {}
        value = json.loads(payload.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("JSON-RPC request must be an object")
        return value

    def write(self, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if self.framing == "content-length":
            self.writer.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii"))
            self.writer.write(encoded)
        else:
            self.writer.write(encoded + b"\n")
        self.writer.flush()


if __name__ == "__main__":
    main()
