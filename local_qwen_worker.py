from __future__ import annotations

import json
import os
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


HOST = "127.0.0.1"
PORT = int(os.getenv("MALAPP_QWEN_WORKER_PORT", "8793"))
DEFAULT_MODEL = os.getenv("MALAPP_QWEN_MODEL", "Qwen/Qwen2.5-0.5B-Instruct")
os.environ.setdefault("HF_HUB_OFFLINE", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")


@lru_cache(maxsize=2)
def load_model(model_id: str):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    use_cuda = torch.cuda.is_available()
    dtype = torch.bfloat16 if use_cuda and torch.cuda.is_bf16_supported() else (
        torch.float16 if use_cuda else torch.float32
    )
    tokenizer = AutoTokenizer.from_pretrained(
        model_id,
        trust_remote_code=True,
        local_files_only=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        model_id,
        dtype=dtype,
        device_map={"": "cuda:0"} if use_cuda else {"": "cpu"},
        trust_remote_code=True,
        local_files_only=True,
    )
    model.eval()
    return tokenizer, model


def generate(system_prompt: str, user_prompt: str, max_new_tokens: int, model_id: str) -> str:
    tokenizer, model = load_model(model_id)
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
            max_new_tokens=max(1, min(int(max_new_tokens), 512)),
            do_sample=False,
            repetition_penalty=1.05,
        )
    generated_ids = output_ids[0][inputs.input_ids.shape[-1] :]
    return tokenizer.decode(generated_ids, skip_special_tokens=True).strip()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/health":
            import torch

            self.send_json(
                {
                    "status": "ok",
                    "model": DEFAULT_MODEL,
                    "device": "cuda:0" if torch.cuda.is_available() else "cpu",
                    "device_name": (
                        torch.cuda.get_device_name(0)
                        if torch.cuda.is_available()
                        else "CPU"
                    ),
                    "cuda_version": torch.version.cuda or "",
                }
            )
            return
        self.send_json({"error": "not found"}, 404)

    def do_POST(self) -> None:
        if self.path != "/generate":
            self.send_json({"error": "not found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            text = generate(
                str(payload.get("system_prompt") or ""),
                str(payload.get("user_prompt") or ""),
                int(payload.get("max_new_tokens") or 320),
                str(payload.get("model") or DEFAULT_MODEL),
            )
            self.send_json({"text": text})
        except Exception as exc:
            self.send_json({"error": f"{type(exc).__name__}: {exc}"}, 500)

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            return

    def log_message(self, fmt: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
