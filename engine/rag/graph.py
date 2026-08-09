from __future__ import annotations

"""Lightweight knowledge graph for the local/remote hybrid RAG service.

The graph deliberately shares the SQLite database with the document store.  It
keeps the desktop package self-contained while exposing a stable data model
that can later be moved to Neo4j or a managed graph database without changing
the judgement pipeline.
"""

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any


ENTITY_FIELDS: dict[str, tuple[str, ...]] = {
    "sample": ("md5", "sample_id", "sha1", "sha256"),
    "app": ("app_name", "official_app_name", "appname"),
    "package": ("package_name", "package", "official_pkg", "pkg"),
    "domain": ("domains", "domain", "control_url", "download_url", "url"),
    "ip": ("ips", "ip"),
    "mailbox": ("control_mailbox", "mailbox", "email"),
    "phone": ("control_phone", "phone", "mobile"),
    "family": ("fraud_family", "malware_family", "family"),
    "business_category": ("fraud_category_big", "fraud_category_small", "risk_type"),
    "harm_type": ("harm_type", "virus_name"),
    "certificate": ("certificate_fingerprint", "sign_md5", "sign_sha1", "issuer"),
}


def init_graph_db(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS kg_nodes (
            node_id TEXT PRIMARY KEY,
            node_type TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            display_value TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            updated_at REAL NOT NULL,
            UNIQUE(node_type, normalized_value)
        );
        CREATE TABLE IF NOT EXISTS kg_edges (
            edge_id TEXT PRIMARY KEY,
            subject_id TEXT NOT NULL,
            predicate TEXT NOT NULL,
            object_id TEXT NOT NULL,
            source_doc_id TEXT NOT NULL,
            confidence REAL NOT NULL,
            metadata_json TEXT NOT NULL,
            updated_at REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS kg_document_links (
            doc_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            role TEXT NOT NULL,
            PRIMARY KEY(doc_id, node_id, role)
        );
        CREATE TABLE IF NOT EXISTS kg_index_state (
            doc_id TEXT PRIMARY KEY,
            entity_count INTEGER NOT NULL,
            indexed_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_kg_nodes_type_value ON kg_nodes(node_type, normalized_value);
        CREATE INDEX IF NOT EXISTS idx_kg_edges_subject ON kg_edges(subject_id);
        CREATE INDEX IF NOT EXISTS idx_kg_edges_object ON kg_edges(object_id);
        CREATE INDEX IF NOT EXISTS idx_kg_edges_doc ON kg_edges(source_doc_id);
        CREATE INDEX IF NOT EXISTS idx_kg_doc_links_node ON kg_document_links(node_id);
        """
    )


def normalize_value(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())[:500]


def node_key(node_type: str, value: Any) -> str:
    normalized = normalize_value(value)
    digest = hashlib.sha1(f"{node_type}|{normalized}".encode("utf-8", "ignore")).hexdigest()[:24]
    return f"{node_type}:{digest}"


def entity_values(value: Any, node_type: str) -> list[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, (list, tuple, set)):
        result: list[str] = []
        for item in value:
            result.extend(entity_values(item, node_type))
        return result
    if isinstance(value, dict):
        result: list[str] = []
        for item in value.values():
            result.extend(entity_values(item, node_type))
        return result
    text = str(value).strip()
    if node_type == "domain":
        found = re.findall(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[:/][^\s,;]*)?", text)
        return list(dict.fromkeys(found or [item for item in re.split(r"[,;\s|]+", text) if item]))
    if node_type == "ip":
        found = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
        return list(dict.fromkeys(found or [item for item in re.split(r"[,;\s|]+", text) if item]))
    return [item[:500] for item in re.split(r"[,;|\n]+", text) if item.strip()]


def extract_entities(record: dict[str, Any] | None, text: str = "") -> list[dict[str, str]]:
    record = record or {}
    entities: list[dict[str, str]] = []
    for node_type, fields in ENTITY_FIELDS.items():
        for field in fields:
            if field in record:
                for value in entity_values(record.get(field), node_type):
                    entities.append({"type": node_type, "value": value, "field": field})

    # Document chunks frequently use key=value syntax. Extract only known keys;
    # this avoids turning arbitrary prose into unverified graph facts.
    for node_type, fields in ENTITY_FIELDS.items():
        for field in fields:
            pattern = rf"(?:^|[;\n\s]){re.escape(field)}\s*=\s*([^;\n]+)"
            for matched in re.findall(pattern, text, flags=re.IGNORECASE):
                for value in entity_values(matched, node_type):
                    entities.append({"type": node_type, "value": value, "field": field})
    dedup: dict[tuple[str, str], dict[str, str]] = {}
    for entity in entities:
        value = normalize_value(entity["value"])
        if value:
            dedup[(entity["type"], value)] = entity
    return list(dedup.values())


def _upsert_node(conn: sqlite3.Connection, node_type: str, value: str, metadata: dict[str, Any]) -> str:
    key = node_key(node_type, value)
    conn.execute(
        """
        INSERT INTO kg_nodes(node_id,node_type,normalized_value,display_value,metadata_json,updated_at)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(node_type,normalized_value) DO UPDATE SET
            display_value=excluded.display_value, metadata_json=excluded.metadata_json, updated_at=excluded.updated_at
        """,
        (key, node_type, normalize_value(value), str(value)[:500], json.dumps(metadata, ensure_ascii=False), time.time()),
    )
    return key


def _upsert_edge(
    conn: sqlite3.Connection,
    subject_id: str,
    predicate: str,
    object_id: str,
    source_doc_id: str,
    confidence: float,
    metadata: dict[str, Any],
) -> None:
    digest = hashlib.sha1(f"{subject_id}|{predicate}|{object_id}|{source_doc_id}".encode()).hexdigest()[:28]
    conn.execute(
        """
        INSERT OR REPLACE INTO kg_edges(edge_id,subject_id,predicate,object_id,source_doc_id,confidence,metadata_json,updated_at)
        VALUES(?,?,?,?,?,?,?,?)
        """,
        (f"edge:{digest}", subject_id, predicate, object_id, source_doc_id, float(confidence), json.dumps(metadata, ensure_ascii=False), time.time()),
    )


def index_document_graph(
    conn: sqlite3.Connection,
    *,
    doc_id: str,
    metadata: dict[str, Any] | None,
    content: str,
    source_type: str,
) -> int:
    init_graph_db(conn)
    entities = extract_entities(metadata, content)
    if not entities:
        conn.execute(
            "INSERT OR REPLACE INTO kg_index_state(doc_id,entity_count,indexed_at) VALUES(?,?,?)",
            (doc_id, 0, time.time()),
        )
        return 0
    doc_node = _upsert_node(conn, "document", doc_id, {"source_type": source_type})
    entity_nodes: list[tuple[dict[str, str], str]] = []
    for entity in entities:
        entity_node = _upsert_node(conn, entity["type"], entity["value"], {"field": entity["field"]})
        conn.execute("INSERT OR REPLACE INTO kg_document_links(doc_id,node_id,role) VALUES(?,?,?)", (doc_id, entity_node, "mentions"))
        _upsert_edge(
            conn,
            doc_node,
            "mentions",
            entity_node,
            doc_id,
            0.8,
            {"field": entity["field"], "source_type": source_type},
        )
        entity_nodes.append((entity, entity_node))

    # A sample is the subject of the operational facts. When there is no sample
    # identifier, the document node remains the only provenance anchor.
    sample_nodes = [node for entity, node in entity_nodes if entity["type"] == "sample"]
    for sample_node in sample_nodes:
        for entity, target_node in entity_nodes:
            if target_node == sample_node:
                continue
            _upsert_edge(
                conn,
                sample_node,
                f"has_{entity['type']}",
                target_node,
                doc_id,
                0.9,
                {"field": entity["field"], "source_type": source_type},
            )
    entity_count = len(entity_nodes)
    conn.execute(
        "INSERT OR REPLACE INTO kg_index_state(doc_id,entity_count,indexed_at) VALUES(?,?,?)",
        (doc_id, entity_count, time.time()),
    )
    return entity_count


def graph_status(conn: sqlite3.Connection) -> dict[str, Any]:
    init_graph_db(conn)
    node_count = int(conn.execute("SELECT COUNT(*) FROM kg_nodes").fetchone()[0])
    edge_count = int(conn.execute("SELECT COUNT(*) FROM kg_edges").fetchone()[0])
    indexed_documents = int(conn.execute("SELECT COUNT(*) FROM kg_index_state").fetchone()[0])
    return {
        "ready": node_count > 0,
        "nodes": node_count,
        "edges": edge_count,
        "indexed_documents": indexed_documents,
        "node_types": {row[0]: int(row[1]) for row in conn.execute("SELECT node_type,COUNT(*) FROM kg_nodes GROUP BY node_type")},
    }


def graph_retrieve(
    conn: sqlite3.Connection,
    *,
    entities: list[dict[str, str]],
    top_k: int = 6,
    max_hops: int = 1,
) -> list[dict[str, Any]]:
    init_graph_db(conn)
    seed_ids: list[str] = []
    for entity in entities:
        row = conn.execute(
            "SELECT node_id,node_type,display_value FROM kg_nodes WHERE node_type=? AND normalized_value=?",
            (entity["type"], normalize_value(entity["value"])),
        ).fetchone()
        if row:
            seed_ids.append(row[0])
    if not seed_ids:
        return []

    results: list[dict[str, Any]] = []
    visited = set(seed_ids)
    frontier = set(seed_ids)
    for hop in range(max(1, min(int(max_hops), 2))):
        next_frontier: set[str] = set()
        marks = ",".join("?" for _ in frontier)
        rows = conn.execute(
            f"""
            SELECT e.predicate,e.confidence,e.source_doc_id,
                   s.node_type AS subject_type,s.display_value AS subject_value,
                   o.node_id AS object_id,o.node_type AS object_type,o.display_value AS object_value
            FROM kg_edges e
            JOIN kg_nodes s ON s.node_id=e.subject_id
            JOIN kg_nodes o ON o.node_id=e.object_id
            WHERE e.subject_id IN ({marks})
            ORDER BY e.confidence DESC, e.updated_at DESC
            LIMIT ?
            """,
            [*frontier, max(10, int(top_k) * 5)],
        ).fetchall()
        for row in rows:
            next_frontier.add(row["object_id"])
            results.append(
                {
                    "source": "knowledge_graph",
                    "hop": hop + 1,
                    "doc_id": row["source_doc_id"],
                    "predicate": row["predicate"],
                    "subject": {"type": row["subject_type"], "value": row["subject_value"]},
                    "object": {"type": row["object_type"], "value": row["object_value"]},
                    "confidence": round(float(row["confidence"]), 4),
                }
            )
        frontier = next_frontier - visited
        visited.update(next_frontier)
        if not frontier:
            break
    results.sort(key=lambda item: (item["confidence"], -item["hop"]), reverse=True)
    return results[: max(1, min(int(top_k), 30))]
