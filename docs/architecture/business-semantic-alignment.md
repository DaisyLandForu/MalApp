# Business Semantic Alignment

P3.5 恢复原始需求中 Engine A、Engine B、Engine C 与最终 WEC 的业务边界。原始 Word/Excel 需求是本设计的业务依据；本页同时明确哪些数值是可配置的工程默认值，避免把工程选择误写成业务事实。

## 顶层业务链

```text
JudgementService
  -> A/B Input Validation
  -> EngineCAdmissionPolicy
     -> CLEAR_CONSENSUS: 直接输出 A/B 共识，不运行 Engine C
     -> CONFLICT / AMBIGUOUS_HIGH_RISK / MANUAL_FORCE
        -> Engine C Internal Pipeline
        -> Score C
        -> (A*Wa+B*Wb+C*Wc)/(Wa+Wb+Wc)
```

生产环境必须显式提供 Engine A 和 Engine B 分数，缺失时返回 `missing_upstream_engine_input`，不得合成 50 分。Demo/测试允许合成输入，但报告必须带 `ab_input_mode: synthetic`，不能视为生产合规结果。

准入原因固定为 `CONFLICT`、`AMBIGUOUS_HIGH_RISK`、`CLEAR_CONSENSUS` 和 `MANUAL_FORCE`。冲突与人工强制来自原始业务边界；以下数值只是版本化、可覆盖的工程默认值，不是原需求给出的业务阈值：

- 清晰共识最小置信度：`0.8`
- 高风险阈值：`0.7`
- 共识最大分数差：`0.15`

它们与策略 ID、策略版本一起进入 Decision Params 和 RuntimeSnapshot。

## 完整证据契约

四个 Agent 输出后构造 `CanonicalEvidenceEnvelope`。信封包含 sample ID、全部原始 EvidenceBlock、AgentResult 摘要、稳定 evidence ID、schema version、创建时间和 SHA256 快照身份。身份计算使用固定 Agent/evidence 顺序和 canonical JSON；时间戳不参与身份哈希。

模型甲、模型乙第一阶段收到同一份完整信封，二者的 `evidence_snapshot_id` 必须相同。第一阶段禁止 Top-K、语义压缩或静默截断；上下文不足时明确失败为 `evidence_context_overflow`。只有第二轮及之后的辩论历史允许压缩。模型引用必须属于信封的 `evidence_ids`，无效引用会被拒绝。

## 四领域专家 Agent

四个 Agent 保留确定性分析器，并在各自 `Agent.run()` 内调用同一个 `ExpertModelProvider`。因此重试、超时、故障隔离和 Trace 覆盖完整专家调用。四个角色共享 provider/model identity，但分别声明不同的 role ID、prompt ID、feature scope 和 tool scope：

- Static：APK 元数据、哈希、签名/证书、加固、SDK 和静态权限。
- Threat Intel：控制/下载地址、邮箱、手机号、IOC 和家族关联。
- Impersonation：正版名称/包名/MD5/证书、品牌与仿冒相似度。
- Business Label：技术结论到反诈分类、危害链、家族与变种标签的映射。

LLM 只能解释和关联确定性事实，不能增加 IOC、证书、家族或其他 Evidence。字段不足时 EvidenceBlock 标记 `missing_fields` 且置信度为 0。

## 双模型生产约束

模型身份按 `provider:model_id` 比较，不按 endpoint 比较。Production 要求模型甲与模型乙身份不同；相同模型即使部署在两个 URL 也会在启动配置校验或辩论入口处拒绝。Demo/测试允许同模型双角色，但报告明确标记 `single-model-simulation`；真实异构生产标记为 `heterogeneous-production`。

## Score C 与 WEC

XGBoost 是 Engine C 内部的先验/校准器，不是 WEC 后的第四个覆盖层。Engine C 先形成 Score C；如果存在已治理的 XGBoost artifact，可按 `score_c_xgb_calibration_weight` 在 Engine C 内校准 Score C。最终分数始终严格为：

```text
(Score_A*Weight_A + Score_B*Weight_B + Score_C*Weight_C)
---------------------------------------------------------
             Weight_A + Weight_B + Weight_C
```

动态权重继续由版本化 Decision Params 根据冲突与关键证据调整。XGBoost、证据概率或旧 pipeline fusion 都不能在 WEC 之后覆盖最终分数。Engine C 未准入时不生成虚假 Score C，结果只按 A/B 清晰共识计算。

## 治理与缓存

报告 schema 为 `agent-runtime-pipeline-v5.1-business-semantic-alignment`，旧语义缓存不会复用。RuntimeSnapshot 增加准入策略、Evidence 快照、专家模型和 prompt/tool 边界、双模型 conformance 与 WEC policy；API key/credential 不进入报告、快照或 Trace。
