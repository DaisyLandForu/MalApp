# MalApp 五层评测体系使用说明

## 1. 已实现范围

本版本已经把五层评测实现为可版本化的数据集、指标计算器、命令行工具、HTTP API 和 APP 页面。每次生成都会固定验证文件 SHA-256、数据目录、数据量、训练重叠、质量问题、基线分数和发布门禁。

五层分别回答不同问题：

| 层级 | 决策问题 | 已生成的数据 |
| --- | --- | --- |
| 基础模型层 | 模型甲、模型乙或候选模型谁更好 | 严格未见集、历史诊断集、格式挑战集 |
| RAG 与证据层 | 无 RAG、向量 RAG、混合 RAG 谁更好，引用是否真实 | 检索集、语料快照、证据忠实度复核集 |
| Agent 轨迹层 | 四个 Agent 是否稳定、各自是否有净贡献 | 轨迹集、故障注入集、五变体消融集 |
| 端到端层 | 完整研判链能否发布 | 严格未见集、全量诊断集、挑战集 |
| 生产运行层 | 应影子、灰度、全量还是回退 | 生产回放集、可靠性场景、漂移基准 |

程序入口：

- APP 左侧“**五层评测**”页面：五层分别使用独立区域，逐层显示测试数据、发布门禁、实际结果、当前结论和下一步操作。
- 每层“开始执行”会创建后台、可恢复、单任务串行的实验作业；刷新或关闭页面不会中断作业。
- RAG 层“进入 RAG 专家标注”可逐条标注相关证据、困难负例或无相关文档；机器预标只作提示，不会自动成为金标准。
- 生产层“进入人工复核闭环”会跳转到现有训练闭环页面。
- `GET /api/evaluation/five-layer`：读取最新五层清单与当前状态。
- `POST /api/evaluation/five-layer/generate`：生成新的不可覆盖版本目录。
- `GET /api/evaluation/five-layer/workflows`：读取任务目录、当前后台任务和历史进度。
- `POST /api/evaluation/five-layer/workflows/start`：启动指定层的下一步实验。
- `POST /api/evaluation/five-layer/workflows/cancel`：取消当前后台实验并保留已落盘检查点。
- `GET/POST /api/evaluation/five-layer/rag-annotations`：读取和保存 RAG 专家检索标注。
- `scripts/evaluation/run_five_layer.py`：生成、校验、模型打分、RAG 打分和漂移检测。

## 2. 当前已冻结数据

当前套件目录：

`%LOCALAPPDATA%\MalApp_AgentTrace_LearningLoop\data\evaluation\five_layer\v1-20260731_114650-86ca2819`

当前数据量：

- 基础模型层：严格未见 168 条、诊断 500 条、格式挑战 56 条。
- RAG 层：检索 200 条、语料快照 2,372 条、证据复核 200 条。
- Agent 层：轨迹 500 条、故障场景 300 条、消融 300 条。
- 端到端层：严格未见 168 条、全量诊断 2,155 条、挑战 300 条。
- 生产层：回放 1,944 条、可靠性 140 条、漂移参考 2,155 条。
- 跨层专家候选：1,000 条。

自动校验覆盖 JSONL 可读性、ID 唯一性、训练/发布隔离、挑战集隔离、候选集隔离，以及结构化 RAG 中是否混入答案字段或评测样本 ID。

## 3. 必须注意的数据结论

现有 2,155 条验证数据中，有 1,987 条 MD5 曾出现在历史训练 JSONL 中，只有 168 条符合“训练未见”的严格发布口径。因此：

- 2,155 条全量结果只用于历史回归、错误诊断和兼容性观察。
- 168 条严格未见集暂时用于发布回归，但样本量仍偏小。
- 1,000 条新候选不能直接当金标准；需要两位专家独立盲审，不一致时仲裁。
- 冻结验证集、挑战集和新候选集均不得加入 RAG、SFT、DPO、阈值调节或提示词优化。

当前应用没有人工复核记录，所以 RAG 证据忠实度、幻觉率、人机一致率和人工推翻率没有有效分母。这是数据缺口，不应填成 0% 或 100%。

## 4. 五层发布门禁

初始门禁已经写入每个套件的 `manifest.json`：

### 4.1 基础模型层

- 严格未见集覆盖率 100%。
- 恶意召回率不低于 99%。
- 良性误报率不高于 1%。
- JSON 结构成功率不低于 99.5%。
- ECE 不高于 0.05。

### 4.2 RAG 与证据层

- 至少 100 条专家批准的检索问题。
- Recall@5 不低于 90%。
- 证据忠实度不低于 98%。
- 幻觉率不高于 1%。
- 图谱必须存在有效节点。

### 4.3 Agent 轨迹层

- 轨迹覆盖率 100%。
- Agent 结构成功率不低于 99.5%。
- Agent 失败率和超时率分别不高于 1%。
- 断点恢复成功率不低于 95%。
- 必须完成完整系统和四个去 Agent 变体。

### 4.4 端到端层

- 严格未见集覆盖率 100%。
- 已决准确率和恶意召回率分别不低于 99.5%。
- 良性误报率不高于 1%。
- 结构成功率不低于 99.5%。
- P95 不高于 120 秒。

### 4.5 生产运行层

- 失败率不高于 2%。
- 模型不可用率不高于 1%。
- Agent 降级率不高于 2%。
- PSI 达到 0.10 告警，达到 0.25 阻断。
- 至少完成 100 条人工复核。
- 七类可靠性场景全部通过。

阈值是 v1 起点。以后可以根据误判成本调整，但必须创建新门禁版本，不能为了让候选模型过关而修改当前阈值。

## 5. 结构化 RAG 语料

系统已从现有 `app_md5_labels` 和 `engine_detections` 生成 1,996 条结构化 operational 文档，当前混合 KG+向量库共有 2,372 条文档、5,857 个节点和 8,472 条边。

语料生成遵守以下隔离：

- 排除全部 2,155 条冻结验证样本。
- 排除基于验证集哈希稳定选择的 1,000 条新专家候选；重新生成套件不会更换候选。
- 不写入真实标签、候选弱标签、历史模型结论、XGBoost 概率或人工复核答案。
- 仅保存 MD5、包名、应用名、证书、域名、检测名称和业务类别等研判输入证据。
- 每次构建都会清除与评测候选重叠的旧结构化文档并重建图谱，防止孤立节点残留。

重新生成结构化语料：

```powershell
python scripts\evaluation\run_five_layer.py build-rag-corpus --size 2000
```

该操作会更新 RAG 数据库。正式操作前应备份：

`%LOCALAPPDATA%\MalApp_AgentTrace_LearningLoop\data\rag\rag_store.db`

## 6. 标准执行流程

### 6.1 生成与校验

```powershell
python scripts\evaluation\run_five_layer.py generate --name v1
python scripts\evaluation\run_five_layer.py validate "<套件目录>"
python scripts\evaluation\run_five_layer.py overview
```

校验失败时禁止开始模型对比或发布。

### 6.2 基础模型对比

正式质量指标只使用冻结专家金标。来源扩展样本在完成双人盲审和仲裁前，只计算“来源标签一致率”，不得与专家金标准确率合并。APP 在基础模型层提供“运行专家金标四路对照”，在同一批样本、同一运行环境下累计比较：

- 完整融合终判（XGBoost、完整 Agent 流程和可信证据融合）。
- 模型甲单路输出。
- 模型乙单路输出。
- XGBoost 单路输出。

默认每批 10 条，可以修改批量；同一套件会按样本 ID 跳过已完成记录并继续累计，直至覆盖当前冻结金标全集。每条样本只执行一次完整流程，四路结果从同一份报告中提取，避免重复模型调用和不同运行条件造成偏差。金标只用于运行完成后的评分，不会传入提示词、RAG 或 Agent，避免答案泄漏。

本版本还统一了四项研判口径：

- `malicious` 为恶意，`benign` 为良性，`suspicious` 和 `manual_review` 均为未决；未决恶意样本仍保留在恶意召回率的分母中。
- Agent 的 `score` 表示当前可观察证据风险，XGBoost 先验单独保存在 `ml_prior`，不再覆盖 Agent 声明或重复计权。
- 最终融合同时覆盖 XGBoost、完整 Agent/仲裁流水线和可信证据；原生模型或可信 Agent 已给出风险信号时，不允许因不同分数尺度被静默改判为良性，而是进入可疑/人工复核。
- XGBoost 原生阈值、Agent 阈值和最终融合阈值分别记录；阈值调整必须建立在冻结金标的交叉验证结果上，不能按本次测试答案逐条调参。

候选模型输出使用 JSONL，每条至少包含：

```json
{
  "id": "32位MD5",
  "verdict": "malicious",
  "score": 0.98,
  "evidence_refs": ["证据ID"],
  "latency_ms": 1234
}
```

评分：

```powershell
python scripts\evaluation\run_five_layer.py score-model `
  "<套件>\layer1_model\model_release_holdout.jsonl" `
  "<候选模型输出.jsonl>" `
  --output "<模型记分卡.json>"
```

必须同时报告覆盖率、待复核率和样本数。“只对已决样本算准确率”不能替代恶意召回、误报和覆盖率。

### 6.3 RAG 标注与评分

`rag_retrieval_eval.jsonl` 中的 `weak_relevant_doc_ids` 只是机器预标。专家确认后：

1. 把正确文档写入 `relevant_doc_ids`。
2. 把相似但错误的文档写入 `hard_negative_doc_ids`。
3. 把 `annotation_status` 改为 `approved` 或 `adjudicated`。
4. 运行：

```powershell
python scripts\evaluation\run_five_layer.py score-rag `
  "<套件>\layer2_rag\rag_retrieval_eval.jsonl" `
  --output "<RAG记分卡.json>"
```

### 6.4 Agent 消融与故障评测

消融要保持同一模型、同一提示词、同一 RAG 快照和同一输入：

```powershell
python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-full --limit 300
python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-static --disabled-agent static_analysis --limit 300
python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-threat --disabled-agent threat_intel --limit 300
python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-impersonation --disabled-agent impersonation --limit 300
python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-business --disabled-agent business_label --limit 300
```

可靠性场景必须在独立 `MALAPP_DATA_DIR` 下运行，防止故障注入污染生产报告。

### 6.5 漂移检测

```powershell
python scripts\evaluation\run_five_layer.py drift `
  "<套件目录>" `
  "<当前批次CSV>" `
  --output "<漂移报告.json>"
```

## 7. 人工金标准闭环

APP 基础模型层现提供“进入金标扩充”独立区域：

1. 设置目标金标总数，当前建议先从 95 条扩至 500 条，以后可继续扩至 1,000 条。
2. 点击“生成/补齐分层候选”。500 条目标采用约 300 条恶意、200 条良性的结构；基于当前 92 条恶意、3 条良性金标，会从严格来源池抽取 208 条恶意参考候选和 197 条良性参考候选。
3. 复核人 A 使用自己的姓名或工号逐条独立盲审。系统不会向页面返回来源参考标签。
4. 复核人 B 更换姓名或工号进行二审。系统禁止同一人重复提交同一样本，也不会向二审人显示一审答案。
5. 两人一致时自动批准；不一致时进入“争议仲裁”，由与前两人不同的第三位专家决定最终标签或排除样本。
6. 被排除的无效样本会自动从严格来源池补位。达到目标数量前，冻结按钮不可用。
7. 达到目标后点击“冻结新版本并生成五层套件”。系统写入不可覆盖的 `gold_sets` 版本，保留 SHA-256 和复核来源，并生成新的 `v2-gold500-*` 五层套件；旧 95 条套件及其结果不会被覆盖。

复核状态保存在：

`%LOCALAPPDATA%\MalApp_AgentTrace_LearningLoop\data\evaluation\gold_expansion\review_state.json`

冻结版本保存在：

`%LOCALAPPDATA%\MalApp_AgentTrace_LearningLoop\data\evaluation\gold_sets\<版本号>`

1,000 条 `fresh_expert_holdout_candidates.jsonl` 建议执行：

1. 复核人 A 独立盲审。
2. 复核人 B 独立盲审。
3. 一致样本直接批准。
4. 不一致样本由第三人仲裁。
5. 记录错误类型、证据是否支持、JSON 是否合格、是否简洁、标点是否合格、是否幻觉。
6. 批准后的样本按实体组切分，避免同包名、证书、家族或近重复样本跨训练集和测试集。

分流规则：

- 事实知识缺失：进入 RAG 候选库。
- 决策错误且有高质量正确答案：进入 SFT 候选。
- 原回答与改写答案形成明显偏好：进入 DPO 候选。
- 工具、超时或恢复问题：进入 Agent/生产可靠性集。
- 冻结测试样本：永远不进入训练。

## 8. 当前状态解释

页面显示“阻塞”不是程序失败，而是发布门禁在正确工作：

- 基础模型层：168 条严格未见集中，模型甲和模型乙各有 149 条已保存输出，仍缺 19 条。
- RAG 层：图谱已就绪，但证据人工复核为 0。
- Agent 层：轨迹基线已生成，五个消融变体尚未全部运行。
- 端到端层：严格未见集尚未 100% 完成。
- 生产层：人工复核为 0，可靠性场景尚未完整实跑，历史批任务仍有暂停记录。

只有五层全部达到 `ready`，才进入“影子 → 5% → 20% → 50% → 100%”灰度。任一质量、可靠性或漂移门禁失败，都应停止扩量并回退到上一个已批准版本。
