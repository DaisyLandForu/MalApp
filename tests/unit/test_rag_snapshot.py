from __future__ import annotations

from pathlib import Path

from malapp.governance.rag_snapshot import snapshot_path
from malapp.rag.store import add_document, finalize_rag_snapshot, rag_status


def test_rag_snapshot_binds_corpus_embedding_chunking_graph_and_digest(
    tmp_path: Path,
) -> None:
    database = tmp_path / "rag_store.db"
    add_document(
        doc_id="doc-1",
        source_type="test",
        source_name="fixture",
        title="first document",
        content="package_name=com.example.bad; domain=bad.example.test",
        metadata={"package_name": "com.example.bad"},
        path=database,
    )

    first = finalize_rag_snapshot(path=database, corpus_version="corpus-test-v1")
    status = rag_status(database)

    assert first is not None
    assert first["snapshot_id"] == status["snapshot_id"]
    assert first["corpus_version"] == "corpus-test-v1"
    assert first["document_count"] == 1
    assert first["embedding_model"]
    assert first["embedding_backend"]
    assert first["chunk_strategy"]["documents"] == {"size": 900, "overlap": 120}
    assert first["index_version"] == "rag-sqlite-v2"
    assert first["graph_version"] == "knowledge-graph-v1"
    assert first["graph"]["nodes"] > 0
    assert len(first["sha256"]) == 64
    assert snapshot_path(database).is_file()

    add_document(
        doc_id="doc-2",
        source_type="test",
        source_name="fixture",
        title="second document",
        content="package_name=com.example.safe",
        metadata={"package_name": "com.example.safe"},
        path=database,
    )
    assert not snapshot_path(database).exists()

    second = finalize_rag_snapshot(path=database, corpus_version="corpus-test-v2")
    assert second is not None
    assert second["document_count"] == 2
    assert second["snapshot_id"] != first["snapshot_id"]
    assert second["sha256"] != first["sha256"]
