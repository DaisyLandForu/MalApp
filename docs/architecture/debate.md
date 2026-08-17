# 多轮辩论说明

当前版本已经支持多轮辩论。

## 开启方式

`start.ps1` 里已经加入：

```powershell
$env:MALAPP_DEBATE_ROUNDS = "2"
```

含义：

- `1`：只做模型甲、模型乙初判，并使用默认交叉质询占位。
- `2`：模型甲、模型乙初判后，增加一轮互相质询，再增加一轮反驳。
- `3`：代码里预留了上限，但本地 CPU 运行会明显变慢，暂不建议默认使用。

## 当前两轮流程

1. Engine C 准入后，四个智能体在统一 Runtime 内完成确定性工具分析和共享专家模型复核，生成证据块。
2. 系统生成带稳定 ID/SHA256 的完整 `CanonicalEvidenceEnvelope`。
3. 模型甲、模型乙读取完全相同、未经压缩的初始 Evidence 快照，分别从“保守复核”和“风险优先”角度独立判断。
4. 第一轮辩论：模型乙质询模型甲，模型甲质询模型乙。
5. 第二轮辩论：模型甲针对乙的质询反驳或修正，模型乙针对甲的质询反驳或修正。
6. 仲裁器综合模型甲、模型乙和最高风险证据块，生成 Engine C 分数。
7. WEC 再融合 Engine A、Engine B、Engine C，输出最终研判结果。

初始 Evidence 超出上下文时流程明确返回 `evidence_context_overflow`，不会静默 Top-K 或截断。第二轮以后的历史消息可以压缩。Production 中两模型必须具有不同的 `provider:model_id`；开发环境同模型双角色会标记为 `single-model-simulation`。

## 页面展示

页面的“模型辩论”区域现在会显示：

- 模型甲结果
- 模型乙结果
- 仲裁器结果
- 第 1 轮质询
- 第 2 轮反驳

## 速度影响

使用本地 `Qwen2.5-0.5B` 且开启两轮辩论时，一次研判会比之前更慢，因为模型调用次数从约 2 次增加到约 6 次。

如果只是快速测试页面，可以临时关掉本地模型：

```powershell
$env:MALAPP_USE_LOCAL_QWEN = "0"
python -m apps.server.main
```

如果要恢复真实本地小模型多轮辩论，运行：

```powershell
.\start.ps1
```
