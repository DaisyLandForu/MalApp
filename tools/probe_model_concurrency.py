import argparse
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def request_once(base_url: str, model: str, index: int, timeout: float, max_tokens: int, prompt_repeat: int) -> dict:
    extra_context = " ".join(
        [
            "样本包含签名、包名、控制域名、下载地址、SDK、权限、涉诈分类、黑产家族、XGBoost概率等字段。"
            for _ in range(max(1, prompt_repeat))
        ]
    )
    payload = {
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": (
                    f"并发测试请求 {index}：请模拟恶意APP研判模型，输出结构化中文判断，"
                    f"说明证据链、矛盾点和最终倾向。{extra_context}"
                ),
            }
        ],
        "temperature": 0,
        "max_tokens": max_tokens,
    }
    started = time.perf_counter()
    try:
        request = Request(
            base_url.rstrip("/") + "/chat/completions",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=timeout) as response:
            body = response.read(1200).decode("utf-8", errors="replace")
        elapsed = time.perf_counter() - started
        text = body[:300].replace("\n", " ")
        return {
            "index": index,
            "ok": response.status == 200,
            "status_code": response.status,
            "elapsed_sec": round(elapsed, 3),
            "body_preview": text,
        }
    except HTTPError as exc:
        elapsed = time.perf_counter() - started
        body = exc.read(1200).decode("utf-8", errors="replace")
        return {
            "index": index,
            "ok": False,
            "status_code": exc.code,
            "elapsed_sec": round(elapsed, 3),
            "body_preview": body[:300].replace("\n", " "),
        }
    except URLError as exc:
        elapsed = time.perf_counter() - started
        return {
            "index": index,
            "ok": False,
            "status_code": "url_error",
            "elapsed_sec": round(elapsed, 3),
            "body_preview": str(exc.reason)[:300],
        }
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return {
            "index": index,
            "ok": False,
            "status_code": "exception",
            "elapsed_sec": round(elapsed, 3),
            "body_preview": str(exc)[:300],
        }


def run_probe(base_url: str, model: str, concurrency: int, timeout: float, max_tokens: int, prompt_repeat: int) -> dict:
    started = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(request_once, base_url, model, index + 1, timeout, max_tokens, prompt_repeat)
            for index in range(concurrency)
        ]
        for future in as_completed(futures):
            results.append(future.result())
    total = time.perf_counter() - started
    ok_times = [item["elapsed_sec"] for item in results if item["ok"]]
    return {
        "base_url": base_url,
        "model": model,
        "concurrency": concurrency,
        "total_elapsed_sec": round(total, 3),
        "success": sum(1 for item in results if item["ok"]),
        "failed": sum(1 for item in results if not item["ok"]),
        "avg_success_elapsed_sec": round(statistics.mean(ok_times), 3) if ok_times else None,
        "max_success_elapsed_sec": round(max(ok_times), 3) if ok_times else None,
        "results": sorted(results, key=lambda item: item["index"]),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://10.0.11.55:10000/v1")
    parser.add_argument("--model", default="Qwen3.6-35B-A3B-FP8")
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--max-tokens", type=int, default=120)
    parser.add_argument("--prompt-repeat", type=int, default=1)
    args = parser.parse_args()
    report = run_probe(args.base_url, args.model, args.concurrency, args.timeout, args.max_tokens, args.prompt_repeat)
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
