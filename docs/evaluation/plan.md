# MalApp 大模型与 Agent 评测实施规划

## 1. 目标与原则

本规划把评测分成五层：

1. 基础模型层：模型甲、模型乙在相同输入下的单次研判能力。
2. RAG 与证据层：召回、重排、引用和答案忠实度。
3. Agent 轨迹层：四个领域 Agent 的工具、重试、停止和边际贡献。
4. 端到端层：XGBoost、RAG、Agent、双模型辩论和终审的整体结果。
5. 生产层：端点、GPU、网络、超时、吞吐、漂移和人工推翻。

训练集、开发集和冻结测试集必须隔离。任何用于调参、提示词修改、DPO
或阈值选择的样本，都不能继续作为冻结发布测试样本。

程序生成的 `expert_core_candidates.jsonl` 只是专家标注候选，不是金标准。
只有双人独立复核并完成争议仲裁后，才能把 `annotation_status` 改为
`approved`。

## 2. 已实现组件

### 2.1 统一评测模块

文件：`malapp/evaluation/framework.py`

能力：

- 读取验证 CSV 和 APP 已保存报告；
- 计算覆盖率、混淆矩阵、恶意召回、良性误报率、宏 F1；
- 计算 Brier Score、ECE 和校准分箱；
- 计算结构成功率、无效 fallback 率以及延迟 P50/P90/P95/P99；
- 自动归类恶意漏判、良性误报、RAG 漏检、Agent 超时、模型不可用等错误；
- 冻结版本化评测清单；
- 保存模型、端点、RAG、代码哈希和 GPU 声明快照；
- 生成核心集、挑战集和 RAG 检索集的待标注文件；
- 检查核心集和挑战集的 ID、实体组重叠。

### 2.2 人工复核扩展

`human_reviews` 已增加：

- `error_types`
- `evidence_supported`
- `json_valid`
- `concise`
- `punctuation_valid`
- `hallucination`
- `corrected_output`
- `review_status`
- `second_reviewer`
- `adjudication_notes`

训练导出现在只接收已复核或已仲裁的数据。未人工复核的生产回答不再自动
作为 SFT 金答案，避免自训练污染。

标签正确但格式、简洁度、标点或证据质量不合格的回答，可以在提供
`corrected_output` 后生成 DPO 偏好对。

### 2.3 运行轨迹版本快照

新生成的 `agent_trace` 包含 `runtime_snapshot`：

- 模型甲乙名称和端点；
- 本地模型名称；
- RAG 开关、模式、embedding 和 Top-K；
- Python、系统和机器架构；
- GPU 声明；
- pipeline、debate、RAG 和决策代码 SHA-256；
- 评测计划版本和实验变体。

API Key 不会写入快照。

### 2.4 API

- `GET /api/evaluation/overview`
- `GET /api/evaluation/scorecard`
- `POST /api/evaluation/freeze`
- `POST /api/evaluation/datasets`

示例：

```powershell
Invoke-RestMethod http://127.0.0.1:8765/api/evaluation/scorecard

Invoke-RestMethod `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"name":"v1"}' `
  http://127.0.0.1:8765/api/evaluation/freeze

Invoke-RestMethod `
  -Method Post `
  -ContentType 'application/json' `
  -Body '{"core_size":500,"challenge_size":300,"rag_size":200}' `
  http://127.0.0.1:8765/api/evaluation/datasets
```

## 3. 第一阶段：冻结与可审计基础，1周

### 第1天：冻结评测定义

确定：

- 主标签：恶意、可疑、良性；
- 可疑是否进入准确率分母；
- 恶意漏判与良性误报成本比例；
- 主KPI和发布门禁；
- 时间口径统一为 Asia/Shanghai，保存时间仍使用 UTC ISO-8601；
- v1训练截止日期和知识库快照日期。

执行：

```powershell
python scripts\evaluation\run_evaluation.py freeze --name v1
```

输出：

- `data/evaluation/manifests/<manifest_id>.json`
- `data/evaluation/snapshots/<snapshot_id>.json`

退出条件：

- 验证集文件 SHA-256 已固定；
- 2,155条样本都有唯一ID和实体组；
- 已研判、待研判、错误数能够复算；
- 模型、端点、RAG和代码版本可追溯。

### 第2至4天：完成剩余样本

先做10条冒烟：

```powershell
python scripts\evaluation\run_evaluation.py run `
  --variant full `
  --run-id v1-full-smoke `
  --limit 10
```

确认模型端点、失败率、P95和报告保存正常后，再扩大：

```powershell
python scripts\evaluation\run_evaluation.py run `
  --variant full `
  --run-id v1-full-remaining `
  --pending-only `
  --limit 306
```

同一个 `run-id` 重复执行会读取 `checkpoint.json`，已经完成的MD5会跳过，
失败项会重试，因此程序中断后不需要从头开始。
`--pending-only` 会读取当前应用数据库，按MD5自动排除已有有效结论的样本，
不依赖CSV中“前1849条已完成”的顺序假设。若要读取另一套应用数据，
可显式传入 `--source-data-dir <目录>`。
正式运行前可先追加 `--dry-run`，只检查候选数量、样本ID和实验配置，
不会调用模型。

注意：不要按“前1849条”假定剩余样本位置。正式运行前以
`--pending-only --dry-run` 返回的实时数量为准。

### 第3至5天：人工复核错误与高不确定样本

必须优先复核：

1. 恶意判良性；
2. 良性判恶意；
3. 模型甲乙冲突；
4. XGBoost与终审冲突；
5. final_score在0.35至0.65；
6. RAG无结果或引用不支持结论；
7. Agent超时、降级或重启；
8. 高置信错误。

人工复核流程：

```text
复核人1盲审
→ 复核人2独立盲审
→ 标签一致则通过
→ 标签不一致则仲裁
→ 错误分类
→ 人工修正输出
→ 决定进入RAG、SFT、DPO、阈值修复或工具修复
```

### 第5天：第一阶段验收

- 全部样本具有已研判或明确失败状态；
- 所有错误具有根因分类；
- 每条新轨迹具有运行时快照；
- 断点恢复通过；
- 生成第一份v1 scorecard。

```powershell
python scripts\evaluation\run_evaluation.py scorecard `
  --output outputs\evaluation_v1_scorecard.json
```

## 4. 第二阶段：金标准、挑战集、RAG集和完整指标，1至2周

### 4.1 生成标注候选

```powershell
python scripts\evaluation\run_evaluation.py datasets `
  --core-size 500 `
  --challenge-size 300 `
  --rag-size 200
```

输出：

- `expert_core_candidates.jsonl`
- `challenge_candidates.jsonl`
- `rag_retrieval_candidates.jsonl`
- `summary.json`

### 4.2 核心金标准集

建议500条：

- 恶意约250条；
- 良性约250条；
- 覆盖不同病毒家族、证书、包名、开发者和APP类型；
- 历史误判必须包含；
- 同源变体按 `group_key` 放在同一数据分区；
- 双人盲审和仲裁。

核心集版本内禁止用于：

- 调整提示词；
- 调整阈值；
- 选择模型；
- DPO或SFT；
- 修复后反复观察并继续调参。

### 4.3 挑战集

应包括：

- 360与cm分数冲突；
- 仿冒但无明确病毒行为；
- 恶意行为明显但情报为空；
- RAG检索到相似但错误的APP；
- 字段缺失；
- 过期情报；
- 包名、名称或描述扰动；
- Prompt injection文本；
- 超长字段；
- 模型输出格式诱导。

挑战集单独报告结果，不与普通测试集混成一个准确率。

### 4.4 RAG检索集

每条需要人工填写：

- `relevant_doc_ids`
- `hard_negative_doc_ids`
- 关键证据字段；
- 证据有效期；
- 是否允许“无相关文档”。

计算：

- Recall@5、Recall@10；
- MRR；
- nDCG@10；
- Context Precision；
- 错误引用率；
- RAG加入后的答案准确率增益；
- RAG加入后的幻觉变化；
- 检索P50/P95。

专家完成 `annotation_status=approved` 或 `adjudicated` 后执行：

```powershell
python scripts\evaluation\run_evaluation.py rag-scorecard `
  data\evaluation\datasets\<批次>\rag_retrieval_candidates.jsonl `
  --output outputs\rag_scorecard.json
```

未批准的行不会进入 Recall@K、MRR、nDCG 和 Context Precision 的分母。

### 4.5 第二阶段门禁

建议初始门禁：

- 恶意召回不得低于已批准基线；
- 良性误报率不得显著增加；
- JSON/结构成功率不低于99.5%；
- 高置信错误不得增加；
- RAG错误引用率不得增加；
- 所有指标必须同时报告样本数和分母；
- 人工标签一致性使用 Cohen's Kappa 或百分比一致率。

## 5. 第三阶段：消融、模型/RAG对比和故障恢复，2至4周

### 5.1 四Agent消融

完整系统作为baseline，然后分别运行：

```powershell
python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-full --limit 500

python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-static `
  --disabled-agent static_analysis --limit 500

python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-threat `
  --disabled-agent threat_intel --limit 500

python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-impersonation `
  --disabled-agent impersonation --limit 500

python scripts\evaluation\run_evaluation.py run --variant full --run-id ablation-no-business `
  --disabled-agent business_label --limit 500
```

比较：

- 恶意召回差值；
- 良性误报差值；
- 宏F1差值；
- P95差值；
- token和GPU成本差值；
- Agent失败率；
- 每个Agent避免了多少恶意漏判。

### 5.2 RAG对比

```powershell
python scripts\evaluation\run_evaluation.py run --variant rag_off --run-id rag-off --limit 500
python scripts\evaluation\run_evaluation.py run --variant rag_vector --run-id rag-vector --limit 500
python scripts\evaluation\run_evaluation.py run --variant rag_hybrid --run-id rag-hybrid --limit 500
```

### 5.3 完整辩论与快速验证

```powershell
python scripts\evaluation\run_evaluation.py run --variant full --run-id debate-full --limit 500
python scripts\evaluation\run_evaluation.py run --variant verification --run-id debate-short --limit 500
```

只有在快速验证的恶意召回和良性误报不退化时，才能用延迟优势支持上线。

### 5.4 模型甲乙替换

通过环境变量或独立模型设置文件固定每个实验的：

- API URL；
- 模型ID；
-量化格式；
- vLLM版本；
- 最大上下文；
- GPU型号；
-生成参数。

模型比较必须使用相同冻结样本和RAG快照，不能一边换模型一边更新知识库。

CLI可以直接覆盖模型端点与模型ID，API Key仍从当前应用设置或环境变量读取，
不会写入实验配置：

```powershell
python scripts\evaluation\run_evaluation.py run `
  --variant full `
  --run-id model-ab `
  --model-a-url http://<模型甲端点>/v1 `
  --model-a-model <模型甲ID> `
  --model-b-url http://<模型乙端点>/v1 `
  --model-b-model <模型乙ID> `
  --limit 500
```

### 5.5 故障注入

单Agent一次瞬时失败：

```powershell
python scripts\evaluation\run_evaluation.py run `
  --variant full `
  --run-id fault-threat `
  --inject-agent-failure threat_intel `
  --limit 100
```

还应逐步增加：

- 模型连接拒绝；
- 请求超时；
- 非法JSON；
- RAG数据库锁；
- 空检索结果；
-磁盘写入失败；
-进程中断后恢复。

故障结果必须分为环境故障、模型推理故障、工具故障和数据质量故障。

## 6. 长期运行

### 每周

- 回放所有新增误判；
- 回放高不确定样本；
- 按来源、家族、端点和模型版本分层；
- 检查P95、失败率、重试率和人工推翻率；
- 将误判路由到RAG、SFT、DPO、阈值或工具修复。

### 每月

- 冻结新的回归快照；
- 检查新旧样本分布漂移；
- 对当前冠军版本和候选版本做影子比较；
- 更新挑战集，但不修改当前发布测试集答案。

### 上线

```text
离线冻结集通过
→ 影子流量
→ 5%
→ 20%
→ 50%
→ 100%
```

每个阶段至少观察：

- 一个完整业务周期；
- 足够数量恶意和良性样本；
- 恶意召回；
- 良性误报；
- 人工推翻率；
- 端到端失败率；
- P95延迟；
- GPU成本。

任一门禁失败，回滚模型、Prompt、RAG索引、阈值和代码到同一个已验证快照，
不能只回滚模型参数。

## 7. 测试

```powershell
python -m unittest tests.test_evaluation_framework
python -m unittest discover -s tests
```

在正式批量评测前：

1. 运行1条；
2. 运行10条；
3. 验证断点恢复；
4. 验证模型端点；
5. 确认输出目录和GPU成本；
6. 再运行完整冻结集。
