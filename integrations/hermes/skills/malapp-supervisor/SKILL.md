---
name: malapp-supervisor
description: 将恶意 APP 样本提交到 MalApp 权威 JudgementService，并解释其可追溯报告。
---

# MalApp 权威研判入口

当用户提交 APK 路径、APK Base64 或样本 JSON 并要求研判时使用。

## 执行

1. 将完整样本传给唯一允许的工具 `malapp_full_judgement`。
2. 不在 Hermes 内派生领域子代理或自行重算结论。
3. 检查四个 `agent` 值是否分别为：
   `static_analysis`、`threat_intel`、`impersonation`、`business_label`。
4. 检查每个 Agent Trace、Pipeline Stage 状态和降级原因。
5. 不要自行替代 Runtime、双模型辩论或最终决策。

## 安全

- 禁止运行或安装 APK。
- 禁止使用终端执行 APK 内容。
- 不允许修改服务返回的证据块。
- 更新正版资产库、决策参数和情报库必须人工确认。
