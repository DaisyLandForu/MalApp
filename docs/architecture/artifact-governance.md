# Artifact Governance

P3 将一次研判实际使用的代码、模型、索引、Prompt 和参数收口为可校验身份，而不是只记录组件类型。

## XGBoost Manifest

训练命令会在模型目录生成 `runtime_manifest.json`。Manifest 绑定：

- 六个 Booster 文件及逐文件 SHA256；
- 参考数据库及 SHA256；
- Feature Schema 版本、完整特征名和 Schema SHA256；
- Dataset 版本、训练指标、训练代码提交和创建时间；
- 整个 Artifact Bundle 的 `artifact_id` 与 SHA256。

Runtime 在反序列化模型前验证 Manifest 版本、Feature Schema、文件大小和摘要。旧格式、文件缺失、内容被修改或特征不兼容都会拒绝加载，不能静默使用来源不明的模型。

## RAG Snapshot

`python -m scripts.rag.build_index` 和 `python -m scripts.rag.rebuild_index` 会生成与 SQLite 索引相邻的 `rag_store.snapshot.json`。快照记录：

- Corpus Version；
- Embedding Model、实际后端和维度；
- Chunk Strategy；
- Index / Graph Version；
- Build Commit；
- Document / Node / Edge 数量；
- 按稳定顺序计算的逻辑索引 SHA256。

文档或图谱内容变化会让旧快照失效。研判结果通过 `rag_snapshot_id` 绑定本次实际检索的索引。

## Prompt Version

双模型 Debate 将 Prompt 分成初判、定向辩论、终局陈述、System Contract 和 Schema Repair 五类。每类都有独立的：

```text
prompt_id / version / sha256 / created_at
```

整体 Prompt Bundle 也有统一身份，记录在 `debate.prompt_version`。修改任何 Prompt 构造函数都会改变对应摘要。

## RuntimeSnapshot

每份新报告都包含顶层 `runtime_snapshot`，并在 `execution.runtime_snapshot_id` 中引用同一身份：

```text
code_commit + code_sha256
model_a + model_b
xgb_artifacts
rag_snapshot
prompt_version
decision_params_version
agent_versions
```

相同组件组合得到稳定的 `snapshot_id`，快照保存在 `data/evaluation/snapshots/`。Agent Trace 直接复用报告中的快照，不会在持久化后重新捕获另一份运行环境。API Key 和 URL Credential 不进入快照。

Docker 构建可通过 `MALAPP_GIT_COMMIT` Build Arg 注入代码提交；GitHub Actions 已自动注入 `${{ github.sha }}`。非 Git 构建环境使用源码摘要作为明确的回退身份。
