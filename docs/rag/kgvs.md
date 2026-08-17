# KG + Vector Search

MalApp 将向量相似度与轻量知识图谱关系合并为 Hybrid Retrieval：

```text
Sample + Evidence
    ├─ Vector Search：文本语义相似
    └─ Graph Search：域名、IP、证书、包名、家族和品牌关系
              ↓
        去重、排序、压缩
              ↓
          Debate Context
```

实现位于 `malapp/rag/store.py`、`embedding.py` 和 `graph.py`。SQLite 适合本地 Demo；高并发生产环境应保留检索接口并替换存储适配器。

检索评测必须使用冻结的 query、相关文档标注和 hard negative，分别报告 Recall@K、MRR、nDCG 及最终研判增益。
