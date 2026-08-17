# 可观测性与决策溯源

MalApp 的可观测性以一次研判调用为边界。服务在入口生成不可由请求方指定的 `run_id`，并将它绑定到 Pipeline、四智能体 Runtime、模型调用、最终报告、指标和 Agent Trace。

## 统一 Trace

运行链路如下：

```text
Run → Pipeline Stage → Agent / Tool / Model Call → Decision → Final Label
```

`execution.pipeline.stages` 中的每个阶段都记录：

- `started_at`、`completed_at`、`latency_ms` 和终态；
- `input_digest`、`output_digest`，只保存 SHA256 摘要，不复制阶段输入；
- `error_type`、错误信息与降级原因。

`debate.model_calls` 为每个逻辑模型调用记录 Provider、模型、Prompt 版本、输入/输出 Token、延迟、请求与重试次数、结束原因和状态。模型调用记录不保存 Prompt 原文、Authorization、API Key 或其他 Secret。

持久化 Trace 可通过以下受 Bearer 鉴权的接口查询：

```text
GET /api/agent-trace?run_id=...
GET /api/agent-trace?trace_id=...
GET /api/agent-trace?report_id=...
GET /api/agent-traces?limit=100
```

## 长期指标

SQLite 使用三张低基数表保存 `observability_runs`、`observability_agent_runs` 和 `observability_model_calls`。同一 `run_id` 重写时保持幂等，不会重复累计。

```text
GET /api/observability/metrics?limit=100
```

接口返回指定最近 Run 窗口中的：

- Run 与各 Agent 的成功率、失败率、超时率和重试率；
- Run、Agent 与模型调用延迟 P50/P95；
- 平均 Evidence Count、平均 Confidence；
- 最新人工复核结果计算的 Human Override Rate；
- 模型调用数、Token 总量和重试率。

Dashboard 的 `observability` 字段复用同一聚合结果，不另建第二套统计逻辑。

## Decision Provenance

报告和 Agent Trace 都包含 `decision_provenance`。它是带摘要校验的有向图，而不是一段不可验证的说明文本：

```text
Agent Evidence ─→ Canonical Evidence ─┬→ RAG ───────┐
                                     ├→ XGBoost ──┤
                                     ├→ Model A ──┤
                                     └→ Model B ──┤
                                      Model A/B → Debate
Engine A + Engine B + Evidence + XGB + Debate → Dynamic WEC → Final Label
```

每个 Node 都有 `node_id`、`kind`、`status`、`input_refs`、`artifact_refs`、`output_digest` 和脱敏后的 `summary`；每条 Edge 都明确来源、目标和关系。`reconstruction_order` 提供确定性的审计顺序，`final_node_id` 指向最终标签。

Engine C 未准入时，Agent、RAG、XGBoost 和双模型节点明确标为 `skipped`，并记录 Admission 到 A/B 直接决策的边。缓存命中会生成新的 `run_id`，同时把复用节点标为 `reused` 并引用原始 Run，避免把缓存结果伪装成本次重新执行。

## 安全边界

可观测性数据在持久化前会递归脱敏 `api_key`、`authorization`、`credential`、`password`、`secret` 和访问令牌字段。Token 计数（如 `prompt_tokens`）不属于 Secret，会正常保留。阶段与 Provenance 摘要使用规范化 JSON 的 SHA256，可用于一致性检查，但不能用于恢复原始输入。
