---
name: malapp-supervisor
description: 并行调度静态解析、情报溯源、仿冒研判和业务打标四个子代理，汇总恶意 APP 标准证据块。
---

# 恶意 APP 四智能体主管

当用户提交 APK 路径、APK Base64 或样本 JSON 并要求研判时使用。

## 执行

1. 将同一份样本分别交给四个隔离子代理并行处理。
2. 子代理任务和唯一允许工具：
   - 静态解析：`malapp_static_analysis`
   - 情报溯源：`malapp_threat_intelligence`
   - 仿冒研判：`malapp_impersonation_analysis`
   - 业务打标：`malapp_business_labeling`
3. 每个子代理只返回 `evidence_block` 和必要的分析摘要。
4. 汇总前检查四个 `agent` 值是否分别为：
   `static_analysis`、`threat_intel`、`impersonation`、`business_label`。
5. 缺失或失败时调用 `malapp_run_all_agents` 进行回退，不要虚构缺失结果。
6. 需要最终研判时调用 `malapp_full_judgement`，不要自行替代三引擎决策。

## 安全

- 禁止运行或安装 APK。
- 禁止子代理使用终端执行 APK 内容。
- 不允许模型修改证据块中的工具输出。
- 更新正版资产库、决策参数和情报库必须人工确认。
