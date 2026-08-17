from __future__ import annotations

import hashlib
import math
import os
import re
from functools import lru_cache
from typing import Any

DEFAULT_HASH_DIM = int(os.getenv("MALAPP_RAG_EMBED_DIM", "384") or "384")
DEFAULT_DIM = DEFAULT_HASH_DIM
DEFAULT_CHINESE_MODEL = os.getenv("MALAPP_RAG_EMBED_MODEL", "BAAI/bge-small-zh-v1.5")
EMBED_BACKEND = os.getenv("MALAPP_RAG_EMBED_BACKEND", "chinese_transformer").strip().lower()
LOCAL_FILES_ONLY = os.getenv("MALAPP_RAG_EMBED_LOCAL_FILES_ONLY", "1").strip().lower() not in {
    "0",
    "false",
    "no",
    "n",
}
TOKEN_RE = re.compile(r"[A-Za-z0-9_.:/@-]+|[\u4e00-\u9fff]{1,4}")
_MODEL_LOAD_ERROR = ""


def embedding_backend_name() -> str:
    if _get_transformer_model() is not None:
        return f"chinese_transformer:{DEFAULT_CHINESE_MODEL}"
    return "local_hash_embedding"


def embedding_load_error() -> str:
    return _MODEL_LOAD_ERROR


def embedding_dim() -> int:
    model = _get_transformer_model()
    if model is not None:
        return int(getattr(model.config, "hidden_size", 0) or DEFAULT_HASH_DIM)
    return DEFAULT_HASH_DIM


def tokenize(text: Any) -> list[str]:
    value = str(text or "").lower()
    tokens = TOKEN_RE.findall(value)
    # Add overlapping Chinese character bigrams when the source is mostly CJK.
    cjk = re.findall(r"[\u4e00-\u9fff]", value)
    if len(cjk) >= 2:
        tokens.extend("".join(cjk[i : i + 2]) for i in range(len(cjk) - 1))
    return tokens


def embed_text(text: Any, dim: int | None = None) -> list[float]:
    """Return an embedding for RAG retrieval.

    Prefer a local Chinese transformer embedding model, for example
    BAAI/bge-small-zh-v1.5. If the model files are not available locally, fall
    back to the old deterministic hash vector so the desktop app still works.
    """
    model = _get_transformer_model()
    tokenizer = _get_transformer_tokenizer()
    if model is not None and tokenizer is not None:
        return _embed_with_transformer(text, model=model, tokenizer=tokenizer)
    return embed_hash_text(text, dim=dim or DEFAULT_HASH_DIM)


def embed_hash_text(text: Any, dim: int = DEFAULT_HASH_DIM) -> list[float]:
    vector = [0.0] * dim
    for token in tokenize(text):
        digest = hashlib.blake2b(token.encode("utf-8", "ignore"), digest_size=8).digest()
        number = int.from_bytes(digest, "little", signed=False)
        index = number % dim
        sign = -1.0 if (number >> 8) & 1 else 1.0
        vector[index] += sign * (1.0 + math.log1p(len(token)))
    norm = math.sqrt(sum(value * value for value in vector))
    if norm <= 0:
        return vector
    return [round(value / norm, 8) for value in vector]


def cosine(left: list[float], right: list[float]) -> float:
    if not left or not right:
        return 0.0
    size = min(len(left), len(right))
    return float(sum(left[i] * right[i] for i in range(size)))


@lru_cache(maxsize=4096)
def cached_embed(text: str, dim: int | None = None) -> tuple[float, ...]:
    return tuple(embed_text(text, dim=dim))


@lru_cache(maxsize=1)
def _get_transformer_tokenizer() -> Any:
    if EMBED_BACKEND in {"hash", "local_hash", "local_hash_embedding"}:
        return None
    try:
        from transformers import AutoTokenizer

        return AutoTokenizer.from_pretrained(
            DEFAULT_CHINESE_MODEL,
            trust_remote_code=True,
            local_files_only=LOCAL_FILES_ONLY,
        )
    except Exception as exc:
        global _MODEL_LOAD_ERROR
        _MODEL_LOAD_ERROR = str(exc)
        return None


@lru_cache(maxsize=1)
def _get_transformer_model() -> Any:
    if EMBED_BACKEND in {"hash", "local_hash", "local_hash_embedding"}:
        return None
    try:
        import torch
        from transformers import AutoModel

        model = AutoModel.from_pretrained(
            DEFAULT_CHINESE_MODEL,
            trust_remote_code=True,
            local_files_only=LOCAL_FILES_ONLY,
        )
        model.eval()
        if torch.cuda.is_available() and os.getenv("MALAPP_RAG_EMBED_DEVICE", "cpu").lower() == "cuda":
            model.to("cuda")
        return model
    except Exception as exc:
        global _MODEL_LOAD_ERROR
        _MODEL_LOAD_ERROR = str(exc)
        return None


def _embed_with_transformer(text: Any, *, model: Any, tokenizer: Any) -> list[float]:
    import torch

    encoded = tokenizer(
        str(text or ""),
        max_length=int(os.getenv("MALAPP_RAG_EMBED_MAX_LENGTH", "512") or "512"),
        truncation=True,
        padding=True,
        return_tensors="pt",
    )
    device = next(model.parameters()).device
    encoded = {key: value.to(device) for key, value in encoded.items()}
    with torch.no_grad():
        output = model(**encoded)
        hidden = output.last_hidden_state
        mask = encoded["attention_mask"].unsqueeze(-1).expand(hidden.size()).float()
        pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
        pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
    return [round(float(value), 8) for value in pooled[0].detach().cpu().tolist()]
