# MalApp RAG Usage

This file documents the local RAG layer used by the MalApp judgement engine.

## Sources

- historical_case: completed judgement reports saved in the local SQLite database.
- manual_case: manually labelled conflict samples saved in the local SQLite database.
- threat_family_ioc: MISP Galaxy family, threat actor, tool, malware, or IOC-style knowledge.
- official_app_asset: official app asset records extracted from genuine_new.sql or an internal official asset library.
- judgement_spec: judgement rules, debate requirements, four-agent responsibilities, and EvidenceBlock schema notes.

## Runtime Flow

1. The pipeline builds raw evidence from the current sample.
2. The four domain agents generate structured EvidenceBlock records.
3. The RAG query is built from the sample fields, raw evidence, and EvidenceBlock summaries.
4. The vector store returns similar cases and relevant knowledge snippets.
5. RAG snippets are injected into:
   - the four-agent LLM explanation layer,
   - model A initial testimony,
   - model B initial testimony,
   - attack and rebuttal turns through compressed debate memory,
   - the closing judgement turn.

## Safety Rule

RAG is only reference context. It must not be treated as a current sample hit.

The final judgement must still cite current EvidenceBlock records and current sample fields.

## Build Commands

```powershell
cd C:\Users\啤酒肚\Desktop\工作\test1
python tools\build_rag_index.py --limit-per-source 200
python tools\build_rag_index.py --misp-galaxy-dir D:\data\misp-galaxy --limit-per-source 1000
```

## API

Status:

```http
GET /api/rag/status
```

Search:

```http
POST /api/rag/search
Content-Type: application/json

{
  "query": "fake loan black family control url",
  "top_k": 6
}
```

## Environment Variables

- MALAPP_RAG_ENABLED=1 enables retrieval during judgement.
- MALAPP_RAG_ENABLED=0 disables retrieval.
- MALAPP_RAG_TOP_K controls how many snippets are injected into the pipeline.
- MALAPP_RAG_DB overrides the SQLite vector store path.
- MALAPP_RAG_EMBED_BACKEND controls the embedding backend. Use `chinese_transformer` for Chinese semantic embedding, or `hash` for the old deterministic local fallback.
- MALAPP_RAG_EMBED_MODEL controls the Chinese embedding model name or local model path. The default is `BAAI/bge-small-zh-v1.5`.
- MALAPP_RAG_EMBED_LOCAL_FILES_ONLY=1 loads the embedding model only from local files. Set it to `0` only when the machine is allowed to download model files.
- MALAPP_RAG_EMBED_DEVICE controls the embedding device. Use `cpu` by default, or `cuda` if you want embedding inference on GPU.
- MALAPP_RAG_EMBED_DIM controls the old local hash embedding dimension when the transformer model is unavailable.

## Embedding Note

The current implementation prefers a local Chinese transformer embedding model. If the configured model files are not available, it falls back to deterministic local hash embedding so the desktop app can still start.

Recommended Chinese models:

- `BAAI/bge-small-zh-v1.5`: lighter and suitable for local desktop use.
- `BAAI/bge-base-zh-v1.5`: better recall, higher memory use.
- `BAAI/bge-large-zh-v1.5`: stronger recall, best kept on a server GPU.

After changing the embedding backend or model, rebuild the RAG index because old vectors and new vectors are not comparable:

```powershell
cd C:\Users\啤酒肚\Desktop\工作\test1
$env:MALAPP_RAG_EMBED_BACKEND="chinese_transformer"
$env:MALAPP_RAG_EMBED_MODEL="BAAI/bge-small-zh-v1.5"
$env:MALAPP_RAG_EMBED_LOCAL_FILES_ONLY="0"
.\.venv\Scripts\python.exe tools\build_rag_index.py --reset --limit-per-source 200
```

For offline use, put the embedding model folder on disk and point `MALAPP_RAG_EMBED_MODEL` to that folder:

```powershell
$env:MALAPP_RAG_EMBED_MODEL="C:\Users\啤酒肚\Desktop\工作\test1\models\bge-small-zh-v1.5"
.\.venv\Scripts\python.exe tools\build_rag_index.py --reset --limit-per-source 200
```
