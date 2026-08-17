from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request, status

from apps.server.auth import require_authenticated, server_config
from apps.server.limits import bounded_int, payload_object
from malapp.rag import hybrid_search as rag_hybrid_search
from malapp.rag import rag_context_for_sample, rag_status, rebuild_graph_index
from malapp.rag import search as rag_search
from malapp.rag import search_graph as rag_search_graph

router = APIRouter(dependencies=[Depends(require_authenticated)])


def _top_k(request: Request, payload: dict[str, Any]) -> int:
    return bounded_int(
        payload.get("top_k"),
        name="top_k",
        default=6,
        maximum=server_config(request).max_rag_top_k,
    )


@router.get("/api/rag/status")
def get_rag_status() -> dict[str, Any]:
    return rag_status()


@router.post("/api/rag/search")
def search(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    query = str(item.get("query") or "").strip()
    if not query:
        raise ValueError("query is required")
    source_types = item.get("source_types")
    if source_types is not None and not isinstance(source_types, list):
        raise ValueError("source_types must be an array")
    return {"items": rag_search(query, top_k=_top_k(request, item), source_types=source_types)}


@router.post("/api/rag/hybrid-search")
def hybrid_search(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    sample = item.get("sample") or {}
    evidence_blocks = item.get("evidence_blocks") or []
    raw_evidence = item.get("raw_evidence") or {}
    if not isinstance(sample, dict) or not isinstance(evidence_blocks, list) or not isinstance(raw_evidence, dict):
        raise ValueError("sample, evidence_blocks and raw_evidence must be structured data")
    return rag_context_for_sample(
        sample,
        evidence_blocks,
        raw_evidence,
        top_k=_top_k(request, item),
        allow_remote=False,
    )


@router.post("/api/rag/graph-search")
def graph_search(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    config = server_config(request)
    max_hops = bounded_int(
        item.get("max_hops"),
        name="max_hops",
        default=1,
        maximum=config.max_graph_hops,
    )
    return {
        "items": rag_search_graph(
            item.get("sample") or {},
            item.get("evidence_blocks") or [],
            item.get("raw_evidence") or {},
            top_k=_top_k(request, item),
            max_hops=max_hops,
        )
    }


@router.post("/api/rag/text-search")
def text_search(request: Request, payload: Any = Body(default_factory=dict)) -> dict[str, Any]:
    item = payload_object(payload)
    query = str(item.get("query") or "").strip()
    if not query:
        raise ValueError("query is required")
    return rag_hybrid_search(query, top_k=_top_k(request, item))


@router.post("/api/rag/rebuild-graph", status_code=status.HTTP_201_CREATED)
def rebuild_graph() -> dict[str, Any]:
    return rebuild_graph_index()
