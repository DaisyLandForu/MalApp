from __future__ import annotations

import json
import os
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from malapp.rag.embedding import (
    cached_embed,
    cosine,
    embed_text,
    embedding_backend_name,
    embedding_dim,
    embedding_load_error,
)
from malapp.rag.graph import extract_entities, graph_retrieve, graph_status, index_document_graph, init_graph_db

ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = Path(os.getenv("MALAPP_DATA_DIR", str(ROOT / "data"))).expanduser().resolve()
RAG_DB_PATH = Path(os.getenv("MALAPP_RAG_DB", str(DATA_DIR / "rag" / "rag_store.db"))).expanduser().resolve()
DEFAULT_TOP_K = int(os.getenv("MALAPP_RAG_TOP_K", "6") or "6")
DEFAULT_GRAPH_HOPS = int(os.getenv("MALAPP_KG_MAX_HOPS", "1") or "1")


def init_rag_db(path: Path = RAG_DB_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rag_documents (
                doc_id TEXT PRIMARY KEY,
                source_type TEXT NOT NULL,
                source_name TEXT NOT NULL,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                embedding_json TEXT NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_source_type ON rag_documents(source_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_rag_source_name ON rag_documents(source_name)")
        init_graph_db(conn)
        conn.commit()


def add_document(
    *,
    doc_id: str,
    source_type: str,
    source_name: str,
    title: str,
    content: str,
    metadata: dict[str, Any] | None = None,
    path: Path = RAG_DB_PATH,
) -> None:
    if not str(content or "").strip():
        return
    init_rag_db(path)
    vector = embed_text(f"{title}\n{content}")
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO rag_documents
            (doc_id, source_type, source_name, title, content, metadata_json, embedding_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                doc_id,
                source_type,
                source_name,
                title,
                content,
                json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True),
                json.dumps(vector, ensure_ascii=False, separators=(",", ":")),
                time.time(),
            ),
        )
        index_document_graph(
            conn,
            doc_id=doc_id,
            metadata=metadata or {},
            content=content,
            source_type=source_type,
        )
        conn.commit()


def rebuild_graph_index(path: Path = RAG_DB_PATH) -> dict[str, Any]:
    """Backfill KG relations for documents indexed before KG+VS was introduced."""
    init_rag_db(path)
    processed = 0
    indexed = 0
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        node_count = int(conn.execute("SELECT COUNT(*) FROM kg_nodes").fetchone()[0])
        edge_count = int(conn.execute("SELECT COUNT(*) FROM kg_edges").fetchone()[0])
        document_count = int(
            conn.execute("SELECT COUNT(*) FROM rag_documents").fetchone()[0]
        )
        # Older builds could mark every document as indexed with entity_count=0
        # before any graph nodes/edges were persisted.  That state prevents the
        # normal NOT EXISTS backfill from ever rebuilding the graph.
        if document_count and node_count == 0 and edge_count == 0:
            conn.execute("DELETE FROM kg_index_state")
            conn.execute("DELETE FROM kg_document_links")
        for row in conn.execute(
            """
            SELECT d.doc_id,d.source_type,d.content,d.metadata_json
            FROM rag_documents d
            WHERE NOT EXISTS (SELECT 1 FROM kg_index_state s WHERE s.doc_id=d.doc_id)
            """
        ):
            processed += 1
            indexed += int(
                index_document_graph(
                    conn,
                    doc_id=row["doc_id"],
                    metadata=_loads(row["metadata_json"], {}),
                    content=row["content"],
                    source_type=row["source_type"],
                )
                > 0
            )
        conn.commit()
        status = graph_status(conn)
    return {
        "processed_documents": processed,
        "documents_with_entities": indexed,
        **status,
    }


def search(
    query: str,
    *,
    top_k: int = DEFAULT_TOP_K,
    source_types: list[str] | None = None,
    path: Path = RAG_DB_PATH,
) -> list[dict[str, Any]]:
    if not path.exists() or not str(query or "").strip():
        return []
    init_rag_db(path)
    query_vector = list(cached_embed(str(query)))
    params: list[Any] = []
    where = ""
    if source_types:
        marks = ",".join("?" for _ in source_types)
        where = f"WHERE source_type IN ({marks})"
        params.extend(source_types)
    rows: list[dict[str, Any]] = []
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(
            f"SELECT doc_id, source_type, source_name, title, content, metadata_json, embedding_json FROM rag_documents {where}",
            params,
        ):
            try:
                vector = json.loads(row["embedding_json"])
            except Exception:
                vector = []
            if len(vector) != len(query_vector):
                continue
            score = cosine(query_vector, vector)
            if score <= 0:
                continue
            rows.append(
                {
                    "doc_id": row["doc_id"],
                    "source_type": row["source_type"],
                    "source_name": row["source_name"],
                    "title": row["title"],
                    "content": row["content"],
                    "metadata": _loads(row["metadata_json"], {}),
                    "similarity": round(score, 4),
                }
            )
    rows.sort(key=lambda item: item["similarity"], reverse=True)
    return rows[: max(1, min(int(top_k), 30))]


def rag_status(path: Path = RAG_DB_PATH) -> dict[str, Any]:
    backend = embedding_backend_name()
    dim = embedding_dim()
    load_error = embedding_load_error()
    if not path.exists():
        return {
            "ready": False,
            "database": str(path),
            "documents": 0,
            "embedding": backend,
            "embedding_dim": dim,
            "embedding_load_error": load_error,
            "embedding_mismatched_documents": 0,
            "rebuild_required": False,
            "sources": {},
        }
    init_rag_db(path)
    with closing(sqlite3.connect(path)) as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM rag_documents").fetchone()[0])
        mismatched = 0
        for row in conn.execute("SELECT embedding_json FROM rag_documents"):
            try:
                mismatched += int(len(json.loads(row[0])) != dim)
            except Exception:
                mismatched += 1
        sources = {
            row[0]: int(row[1])
            for row in conn.execute(
                "SELECT source_type, COUNT(*) FROM rag_documents GROUP BY source_type ORDER BY source_type"
            )
        }
        graph = graph_status(conn)
    return {
        "ready": total > 0 and mismatched < total,
        "database": str(path),
        "documents": total,
        "embedding": backend,
        "embedding_dim": dim,
        "embedding_load_error": load_error,
        "embedding_mismatched_documents": mismatched,
        "rebuild_required": mismatched > 0,
        "sources": sources,
        "graph": graph,
        "mode": "hybrid_kg_vector",
    }


def build_query_from_sample(
    sample: dict[str, Any],
    evidence_blocks: list[Any] | None = None,
    raw_evidence: dict[str, Any] | None = None,
) -> str:
    parts: list[str] = []
    for key in (
        "md5",
        "sha1",
        "sha256",
        "app_name",
        "package_name",
        "control_url",
        "download_url",
        "control_mailbox",
        "control_phone",
        "fraud_family",
        "fraud_category_big",
        "fraud_category_small",
        "harm_type",
        "virus_name",
        "risk_type",
        "official_app_name",
        "official_pkg",
    ):
        value = sample.get(key)
        if value not in (None, "", [], {}):
            parts.append(f"{key}:{_short(value)}")
    for key in ("domains", "ips", "permissions", "sdk_list"):
        value = sample.get(key)
        if value:
            parts.append(f"{key}:{_short(value)}")
    for block in evidence_blocks or []:
        data = _to_dict(block)
        parts.append(f"agent:{data.get('agent')} claim:{data.get('claim')} score:{data.get('score')}")
        for evidence in data.get("evidence", [])[:3] if isinstance(data.get("evidence"), list) else []:
            parts.append(_short(evidence, 180))
        for item in data.get("evidence_items", [])[:3] if isinstance(data.get("evidence_items"), list) else []:
            if isinstance(item, dict):
                parts.append(
                    " ".join(
                        str(item.get(field, ""))
                        for field in ("evidence_type", "direction", "description")
                    )
                )
    if raw_evidence:
        parts.append(_short(raw_evidence, 600))
    return "\n".join(str(part) for part in parts if str(part).strip())


def rag_context_for_sample(
    sample: dict[str, Any],
    evidence_blocks: list[Any] | None = None,
    raw_evidence: dict[str, Any] | None = None,
    *,
    top_k: int = DEFAULT_TOP_K,
    allow_remote: bool = True,
) -> dict[str, Any]:
    if str(os.getenv("MALAPP_RAG_ENABLED", "1")).lower() not in {"1", "true", "yes", "y"}:
        return {"enabled": False, "ready": False, "query": "", "items": [], "status": rag_status()}
    query = build_query_from_sample(sample, evidence_blocks, raw_evidence)
    remote_url = str(os.getenv("MALAPP_RAG_REMOTE_BASE_URL", "")).strip().rstrip("/")
    if remote_url and allow_remote:
        remote = _remote_hybrid_context(remote_url, sample, evidence_blocks, raw_evidence, top_k)
        if remote is not None:
            return remote
    # Existing RAG databases are upgraded lazily, so users do not have to
    # manually rebuild their index after updating the desktop application.
    rebuild_graph_index()
    vector_items = search(query, top_k=max(top_k, 3))
    retrieval_mode = str(os.getenv("MALAPP_RAG_MODE", "hybrid") or "hybrid").strip().lower()
    if retrieval_mode in {"vector", "vector_only"}:
        return {
            "enabled": True,
            "ready": bool(vector_items),
            "query": query[:2000],
            "items": [compact_rag_item(item) for item in vector_items[:top_k]],
            "vector_items": [compact_rag_item(item) for item in vector_items[:top_k]],
            "graph_paths": [],
            "retrieval_mode": "vector_only",
            "status": rag_status(),
        }
    graph_paths = search_graph(sample, evidence_blocks, raw_evidence, top_k=top_k)
    items = hybrid_items(vector_items, graph_paths, top_k=top_k, path=RAG_DB_PATH)
    return {
        "enabled": True,
        "ready": bool(items or graph_paths),
        "query": query[:2000],
        "items": [compact_rag_item(item) for item in items],
        "vector_items": [compact_rag_item(item) for item in vector_items[:top_k]],
        "graph_paths": graph_paths,
        "retrieval_mode": "hybrid_kg_vector",
        "status": rag_status(),
    }


def search_graph(
    sample: dict[str, Any] | None = None,
    evidence_blocks: list[Any] | None = None,
    raw_evidence: dict[str, Any] | None = None,
    *,
    top_k: int = DEFAULT_TOP_K,
    max_hops: int = DEFAULT_GRAPH_HOPS,
    path: Path = RAG_DB_PATH,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    entities = extract_entities(sample or {})
    for block in evidence_blocks or []:
        data = _to_dict(block)
        entities.extend(extract_entities(data))
    entities.extend(extract_entities(raw_evidence or {}))
    if not entities:
        return []
    with closing(sqlite3.connect(path)) as conn:
        conn.row_factory = sqlite3.Row
        return graph_retrieve(conn, entities=entities, top_k=top_k, max_hops=max_hops)


def hybrid_items(
    vector_items: list[dict[str, Any]], graph_paths: list[dict[str, Any]], *, top_k: int, path: Path = RAG_DB_PATH
) -> list[dict[str, Any]]:
    """Fuse semantic recall and exact graph links with graph provenance first."""
    graph_scores = {str(item.get("doc_id")): float(item.get("confidence") or 0) for item in graph_paths if item.get("doc_id")}
    merged: dict[str, dict[str, Any]] = {}
    for item in vector_items:
        doc_id = str(item.get("doc_id") or "")
        if not doc_id:
            continue
        copy = dict(item)
        vector_score = float(copy.get("similarity") or 0)
        graph_score = graph_scores.get(doc_id, 0.0)
        copy["retrieval_source"] = "hybrid" if graph_score else "vector"
        copy["similarity"] = round(max(vector_score, graph_score), 4)
        merged[doc_id] = copy
    if graph_scores:
        with closing(sqlite3.connect(path)) as conn:
            conn.row_factory = sqlite3.Row
            for doc_id, graph_score in graph_scores.items():
                if doc_id in merged:
                    continue
                row = conn.execute(
                    "SELECT doc_id,source_type,source_name,title,content,metadata_json FROM rag_documents WHERE doc_id=?", (doc_id,)
                ).fetchone()
                if not row:
                    continue
                merged[doc_id] = {
                    "doc_id": row["doc_id"], "source_type": row["source_type"], "source_name": row["source_name"],
                    "title": row["title"], "content": row["content"], "metadata": _loads(row["metadata_json"], {}),
                    "similarity": round(graph_score, 4), "retrieval_source": "knowledge_graph",
                }
    return sorted(merged.values(), key=lambda item: float(item.get("similarity") or 0), reverse=True)[: max(1, min(int(top_k), 30))]


def hybrid_search(query: str, *, top_k: int = DEFAULT_TOP_K, source_types: list[str] | None = None) -> dict[str, Any]:
    """Public query API used by desktop clients and optional central RAG service."""
    vector_items = search(query, top_k=max(top_k, 3), source_types=source_types)
    graph_paths: list[dict[str, Any]] = []
    # Query text is deliberately not converted into graph facts. Exact graph
    # search is driven by explicit structured entities from a sample payload.
    return {
        "items": hybrid_items(vector_items, graph_paths, top_k=top_k),
        "vector_items": vector_items[:top_k],
        "graph_paths": graph_paths,
        "retrieval_mode": "vector_text_query",
        "status": rag_status(),
    }


def _remote_hybrid_context(
    remote_url: str,
    sample: dict[str, Any],
    evidence_blocks: list[Any] | None,
    raw_evidence: dict[str, Any] | None,
    top_k: int,
) -> dict[str, Any] | None:
    payload = json.dumps(
        {"sample": sample, "evidence_blocks": [_to_dict(item) for item in evidence_blocks or []], "raw_evidence": raw_evidence or {}, "top_k": top_k},
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    api_key = str(os.getenv("MALAPP_RAG_REMOTE_API_KEY", "")).strip()
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    try:
        request = Request(f"{remote_url}/api/rag/hybrid-search", data=payload, headers=headers, method="POST")
        with urlopen(request, timeout=float(os.getenv("MALAPP_RAG_REMOTE_TIMEOUT", "12"))) as response:
            result = json.loads(response.read().decode("utf-8"))
        if isinstance(result, dict):
            result["remote"] = True
            return result
    except (URLError, TimeoutError, ValueError, OSError, json.JSONDecodeError):
        return None
    return None


def compact_rag_item(item: dict[str, Any], content_limit: int = 520) -> dict[str, Any]:
    return {
        "doc_id": item.get("doc_id"),
        "source_type": item.get("source_type"),
        "source_name": item.get("source_name"),
        "title": _short(item.get("title"), 120),
        "content": _short(item.get("content"), content_limit),
        "similarity": item.get("similarity"),
        "metadata": item.get("metadata") or {},
    }


def _loads(value: str, fallback: Any) -> Any:
    try:
        return json.loads(value)
    except Exception:
        return fallback


def _to_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import asdict

        return asdict(value)
    return dict(value) if isinstance(value, dict) else {}


def _short(value: Any, limit: int = 260) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
    text = " ".join(text.split())
    return text[:limit]
