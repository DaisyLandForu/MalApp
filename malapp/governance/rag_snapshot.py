from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any

from malapp.governance.artifacts import canonical_json, now_iso, resolve_git_commit

RAG_SNAPSHOT_VERSION = 1
RAG_INDEX_VERSION = "rag-sqlite-v2"
RAG_GRAPH_VERSION = "knowledge-graph-v1"
DEFAULT_CHUNK_STRATEGY = {
    "documents": {"size": 900, "overlap": 120},
    "app_rag": {"size": 1100, "overlap": 160},
}


def snapshot_path(database_path: Path) -> Path:
    return database_path.with_name(f"{database_path.stem}.snapshot.json")


def invalidate_rag_snapshot(database_path: Path) -> None:
    try:
        snapshot_path(database_path).unlink(missing_ok=True)
    except OSError:
        pass


def capture_rag_snapshot(
    database_path: Path,
    *,
    embedding_model: str,
    embedding_backend: str,
    embedding_dim: int,
    chunk_strategy: dict[str, Any] | None = None,
    corpus_version: str = "",
    build_commit: str = "",
    persist: bool = False,
) -> dict[str, Any] | None:
    database_path = database_path.resolve()
    if not database_path.is_file():
        return None
    previous = _read_snapshot(snapshot_path(database_path))
    inherited_chunks = previous.get("chunk_strategy") if isinstance(previous, dict) else None
    chunks = dict(chunk_strategy or inherited_chunks or DEFAULT_CHUNK_STRATEGY)
    digest, counts = _logical_index_digest(database_path)
    identity = {
        "snapshot_version": RAG_SNAPSHOT_VERSION,
        "corpus_version": corpus_version
        or str(os.getenv("MALAPP_RAG_CORPUS_VERSION", "")).strip()
        or str(previous.get("corpus_version") or "").strip()
        or f"corpus-{digest[:16]}",
        "embedding_model": embedding_model,
        "embedding_backend": embedding_backend,
        "embedding_dim": int(embedding_dim),
        "chunk_strategy": chunks,
        "index_version": RAG_INDEX_VERSION,
        "graph_version": RAG_GRAPH_VERSION,
        "build_commit": build_commit
        or str(previous.get("build_commit") or "").strip()
        or resolve_git_commit(database_path.parent),
        "document_count": counts["documents"],
        "graph": {
            "nodes": counts["nodes"],
            "edges": counts["edges"],
            "document_links": counts["document_links"],
        },
        "sha256": digest,
    }
    snapshot_id = f"rag-{hashlib.sha256(canonical_json(identity).encode('utf-8')).hexdigest()[:16]}"
    created_at = now_iso()
    if previous.get("snapshot_id") == snapshot_id and previous.get("created_at"):
        created_at = str(previous["created_at"])
    snapshot = {
        **identity,
        "snapshot_id": snapshot_id,
        "created_at": created_at,
    }
    if persist:
        path = snapshot_path(database_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(snapshot, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    return snapshot


def _logical_index_digest(database_path: Path) -> tuple[str, dict[str, int]]:
    digest = hashlib.sha256()
    counts = {"documents": 0, "nodes": 0, "edges": 0, "document_links": 0}
    queries = {
        "documents": (
            "SELECT doc_id,source_type,source_name,title,content,metadata_json,embedding_json "
            "FROM rag_documents ORDER BY doc_id"
        ),
        "nodes": (
            "SELECT node_id,node_type,normalized_value,display_value,metadata_json "
            "FROM kg_nodes ORDER BY node_id"
        ),
        "edges": (
            "SELECT edge_id,subject_id,predicate,object_id,source_doc_id,confidence,metadata_json "
            "FROM kg_edges ORDER BY edge_id"
        ),
        "document_links": (
            "SELECT doc_id,node_id,role FROM kg_document_links ORDER BY doc_id,node_id,role"
        ),
    }
    uri = f"file:{database_path.as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        for section, query in queries.items():
            digest.update(section.encode("utf-8"))
            try:
                cursor = conn.execute(query)
            except sqlite3.DatabaseError as exc:
                raise ValueError(f"RAG database does not contain a valid {section} index") from exc
            for row in cursor:
                counts[section] += 1
                digest.update(canonical_json(list(row)).encode("utf-8"))
                digest.update(b"\n")
    return digest.hexdigest(), counts


def _read_snapshot(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
