import json
import sys

import requests


TARGETS = [
    ("model_a", "http://10.0.11.55:10000/v1", "Qwen3.6-35B-A3B-FP8"),
    ("model_b", "http://10.0.11.82:18012/v1", "malapp-model-b"),
]


def check_models(name, base_url):
    url = base_url.rstrip("/") + "/models"
    r = requests.get(url, timeout=15)
    print(f"\n[{name}] GET {url}")
    print("status:", r.status_code)
    print(r.text[:1000])


def check_chat(name, base_url, model):
    url = base_url.rstrip("/") + "/chat/completions"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": '只输出JSON：{"ok":true}'}],
        "max_tokens": 32,
        "temperature": 0,
        "chat_template_kwargs": {"enable_thinking": False},
    }
    print(f"\n[{name}] POST {url}")
    print("request:", json.dumps(body, ensure_ascii=False))
    try:
        r = requests.post(url, json=body, timeout=60)
    except Exception as exc:
        print("exception:", repr(exc))
        return
    print("status:", r.status_code)
    print(r.text[:2000])


def main():
    for name, base_url, model in TARGETS:
        try:
            check_models(name, base_url)
            check_chat(name, base_url, model)
        except Exception as exc:
            print(f"\n[{name}] failed:", repr(exc), file=sys.stderr)


if __name__ == "__main__":
    main()
