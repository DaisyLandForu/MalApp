from __future__ import annotations

import json
import os
import re
import urllib.request
from functools import lru_cache
from typing import Any


DEFAULT_MODEL_ID = os.getenv("MALAPP_QWEN_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


def local_qwen_enabled() -> bool:
    return os.getenv("MALAPP_USE_LOCAL_QWEN", "0").lower() in {"1", "true", "yes", "y"}


@lru_cache(maxsize=4)
def _load_model(model_id: str = DEFAULT_MODEL_ID):
    try:
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
    except ImportError as exc:
        raise RuntimeError(
            "本地 Qwen 依赖未安装。请先安装 torch、transformers、accelerate。"
        ) from exc

    use_cuda = torch.cuda.is_available()
    dtype = torch.bfloat16 if use_cuda and torch.cuda.is_bf16_supported() else (
        torch.float16 if use_cuda else torch.float32
    )
    tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True, local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        dtype=dtype,
        device_map={"": "cuda:0"} if use_cuda else {"": "cpu"},
        trust_remote_code=True,
        local_files_only=True,
    )
    model.eval()
    return tokenizer, model


def qwen_generate(
    system_prompt: str,
    user_prompt: str,
    *,
    max_new_tokens: int = 320,
    model_id: str | None = None,
) -> str:
    worker_url = os.getenv("MALAPP_QWEN_WORKER_URL", "").strip()
    if worker_url:
        payload = json.dumps(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "max_new_tokens": max_new_tokens,
                "model": model_id or DEFAULT_MODEL_ID,
            },
            ensure_ascii=False,
        ).encode("utf-8")
        request = urllib.request.Request(
            worker_url.rstrip("/") + "/generate",
            data=payload,
            headers={"Content-Type": "application/json; charset=utf-8"},
            method="POST",
        )
        timeout_seconds = max(
            30.0, float(os.getenv("MALAPP_QWEN_REQUEST_TIMEOUT", "600"))
        )
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            result = json.loads(response.read().decode("utf-8"))
        return str(result.get("text") or "").strip()
    tokenizer, model = _load_model(model_id or DEFAULT_MODEL_ID)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]
    text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer([text], return_tensors="pt").to(model.device)

    import torch

    with torch.inference_mode():
        output_ids = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            repetition_penalty=1.05,
        )
    generated_ids = output_ids[0][inputs.input_ids.shape[-1] :]
    return tokenizer.decode(generated_ids, skip_special_tokens=True).strip()


def parse_model_json(text: str) -> dict[str, Any]:
    text = strip_thinking_text(str(text or ""))
    fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", text)
    candidate = fenced.group(1) if fenced else text
    extracted = extract_first_json_object(candidate)
    if extracted:
        candidate = extracted
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        data = repair_common_json_errors(candidate)
    return data if isinstance(data, dict) else {}


def strip_thinking_text(text: str) -> str:
    text = re.sub(r"<think>[\s\S]*?</think>", "", text, flags=re.IGNORECASE).strip()
    if text.lower().startswith("<think>"):
        closing = text.lower().find("</think>")
        if closing >= 0:
            return text[closing + len("</think>") :].strip()
        first_json = text.find("{")
        return text[first_json:].strip() if first_json >= 0 else text
    return text


def extract_first_json_object(text: str) -> str:
    start = text.find("{")
    if start < 0:
        return ""
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text[start:], start=start):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    end = text.rfind("}")
    return text[start : end + 1] if end > start else ""


def repair_common_json_errors(text: str) -> dict[str, Any]:
    candidate = text
    # Small instruction models sometimes emit a JSON-like set for list fields.
    for field in (
        "arguments",
        "evidence_refs",
        "omissions",
        "contradictions",
        "evidence_chain",
        "feature_relations",
        "accepted_challenges",
        "rejected_challenges",
        "accepted_corrections",
        "discarded_claims",
    ):
        pattern = rf'("{field}"\s*:\s*)\{{([^{{}}]*)\}}'
        candidate = re.sub(pattern, lambda match: match.group(1) + "[" + match.group(2) + "]", candidate)
    candidate = re.sub(r"[\u201c\u201d]", '"', candidate)
    candidate = re.sub(r"[\u2018\u2019]", "'", candidate)
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)
    try:
        data = json.loads(candidate)
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def normalize_llm_result(raw_text: str, fallback_score: float, fallback_verdict: str) -> dict[str, Any]:
    data = parse_model_json(raw_text)
    try:
        score = float(data.get("score", fallback_score))
    except (TypeError, ValueError):
        score = fallback_score
    score = max(0.0, min(1.0, score))

    verdict = str(data.get("verdict", fallback_verdict)).strip().lower()
    if verdict not in {"malicious", "suspicious", "benign"}:
        verdict = fallback_verdict

    reasons = data.get("arguments") or data.get("reasons") or data.get("理由") or []
    if isinstance(reasons, str):
        reasons = [reasons]
    if not isinstance(reasons, list):
        reasons = []

    return {
        "score": round(score, 4),
        "verdict": verdict,
        "arguments": [str(item) for item in reasons[:4]],
        "raw_text": raw_text,
    }
