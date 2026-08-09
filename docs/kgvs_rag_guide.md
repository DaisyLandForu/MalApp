# MalApp KG+VS Hybrid RAG

## Purpose

The project now combines a **Knowledge Graph (KG)** with a **Vector Store (VS)**.

- Vector retrieval recalls semantically similar historical cases, IOC notes, official APP assets and judgement specifications.
- The graph links explicit entities such as samples, packages, domains, IP addresses, fraud families, business categories and certificate fingerprints.
- Hybrid retrieval merges both result sets and keeps the source document ID and graph path for auditability.

The existing local RAG behavior remains available. A central deployment can serve many desktop clients without synchronizing the full RAG database to every client.

## Storage Model

The default SQLite database remains `data/rag/rag_store.db`.

| Layer | Main tables | Purpose |
| --- | --- | --- |
| Vector Store | `rag_documents` | Document text, metadata and embedding vector |
| Knowledge Graph | `kg_nodes` | Canonical entities: sample, domain, family, APP, package and others |
| Knowledge Graph | `kg_edges` | Provenance-preserving relations, for example `sample -> has_family -> family` |
| Knowledge Graph | `kg_document_links` | Which RAG document mentions an entity |
| Index state | `kg_index_state` | Prevents the same document being graph-scanned on every judgement |

Every graph edge includes `source_doc_id`, so the LLM can treat graph recall as background knowledge rather than an unsupported claim about the current sample.

## Local Desktop Mode

No new configuration is needed. `engine.pipeline` calls `rag_context_for_sample()` before the dual-model debate. It now returns:

```json
{
  "retrieval_mode": "hybrid_kg_vector",
  "items": ["merged semantic and graph-backed documents"],
  "vector_items": ["semantic matches"],
  "graph_paths": ["explicit entity relations"]
}
```

The existing `items` field is retained, so the debate prompt compaction logic stays compatible.

## Central Service for Multiple Clients

Run the same application on a central machine where the shared RAG database is located:

```powershell
$env:MALAPP_HOST = "0.0.0.0"
$env:MALAPP_PORT = "8765"
$env:MALAPP_RAG_API_KEY = "set-a-private-service-key"
python run.py
```

On every desktop client, configure:

```powershell
$env:MALAPP_RAG_REMOTE_BASE_URL = "http://rag-server:8765"
$env:MALAPP_RAG_REMOTE_API_KEY = "the-same-private-service-key"
```

When the remote service responds, the client uses it. When it is unreachable, the client safely falls back to its local RAG database.

## HTTP APIs

All shared endpoints accept `X-MalApp-Rag-Key` when `MALAPP_RAG_API_KEY` is configured.

| Endpoint | Request | Result |
| --- | --- | --- |
| `POST /api/rag/hybrid-search` | `sample`, `evidence_blocks`, `raw_evidence`, `top_k` | Vector results, graph paths and merged context |
| `POST /api/rag/graph-search` | `sample`, optional evidence/raw data | Explicit entity relation paths |
| `POST /api/rag/text-search` | `query`, `top_k` | Semantic document recall |
| `POST /api/rag/rebuild-graph` | None | Backfills graph relations for old documents |
| `GET /api/rag/status` | None | Document, embedding and graph counts |

## Initial Graph Build

Existing RAG documents are lazily upgraded on first use. To build the whole graph proactively:

```powershell
python tools\rebuild_kgvs_index.py
```

## Scaling Path

SQLite is intentionally used first: it is portable, offline-capable and easy to package into the desktop application. For high-concurrency deployment, retain the same API and migrate only the storage adapters:

- replace vector scan with Qdrant or Milvus;
- replace SQLite graph tables with Neo4j or a graph-capable PostgreSQL model;
- leave the sample payload, EvidenceBlock schema and `/api/rag/hybrid-search` contract unchanged.
