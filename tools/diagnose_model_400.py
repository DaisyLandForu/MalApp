from __future__ import annotations

import json
import urllib.error
import urllib.request


CASES = [
    ("A-min", "http://10.0.11.55:10000/v1", "Qwen3.6-35B-A3B-FP8", {}),
    (
        "A-extra",
        "http://10.0.11.55:10000/v1",
        "Qwen3.6-35B-A3B-FP8",
        {"chat_template_kwargs": {"enable_thinking": False}, "response_format": {"type": "json_object"}},
    ),
    ("B-min", "http://10.0.11.82:18012/v1", "malapp-model-b", {}),
    (
        "B-extra",
        "http://10.0.11.82:18012/v1",
        "malapp-model-b",
        {"chat_template_kwargs": {"enable_thinking": False}, "response_format": {"type": "json_object"}},
    ),
]


def main() -> None:
    for name, url, model, extra in CASES:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": '输出JSON：{"ok":true}'}],
            "temperature": 0,
            "max_tokens": 32,
        }
        payload.update(extra)
        request = urllib.request.Request(
            url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer EMPTY"},
        )
        try:
            with urllib.request.urlopen(request, timeout=40) as response:
                body = response.read().decode("utf-8", "replace")
            print(f"\n{name} OK {response.status}\n{body[:500]}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            print(f"\n{name} HTTP {exc.code}\n{body[:1200]}")
        except Exception as exc:
            print(f"\n{name} ERROR {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()
