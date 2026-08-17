# RAG 使用说明

RAG 由本地文档库、向量检索和知识图谱组成。默认数据库位于 `data/rag/rag_store.db`，可通过 `MALAPP_RAG_DB` 修改。

## 构建索引

```bash
python -m scripts.rag.build_index --help
python -m scripts.rag.build_index --reset
```

重建知识图谱：

```bash
python -m scripts.rag.rebuild_index
```

## Embedding

默认尝试加载本地中文 Transformer；模型不可用时回退到确定性 hash embedding。可显式选择：

```dotenv
MALAPP_RAG_EMBED_BACKEND=hash
```

或配置本地模型目录：

```dotenv
MALAPP_RAG_EMBED_BACKEND=chinese_transformer
MALAPP_RAG_EMBED_MODEL=/models/bge-small-zh-v1.5
MALAPP_RAG_EMBED_LOCAL_FILES_ONLY=1
```

## API

- `GET /api/rag/status`
- `POST /api/rag/search`
- `POST /api/rag/hybrid-search`
- `POST /api/rag/graph-search`
- `POST /api/rag/rebuild-graph`

共享部署统一使用 `MALAPP_API_KEY`/`MALAPP_ADMIN_API_KEY` Bearer 鉴权。远端 RAG 客户端通过 `MALAPP_RAG_REMOTE_API_KEY` 发送同一 Bearer Token，不再使用独立自定义请求头。
