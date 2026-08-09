# MalApp RAG 使用说明

本文档说明当前项目中的 RAG 如何构建、存放、调用，以及 `APP-RAG` 目录里的资料能不能用于微调。

## 1. 当前实现目标

RAG 的作用不是替代四智能体、XGBoost 或双模型辩论，而是给大模型提供可检索的业务知识、历史案例和研判规范，降低幻觉，并让输出更贴近你的业务文档。

当前 RAG 主要服务于四类内容：

1. 历史人工标注案例：用于召回相似研判案例。
2. 黑产家族 / IOC / 威胁情报：用于辅助解释黑产关联、家族命中、C2、URL、邮箱、手机号等证据。
3. 正版 APP / 仿冒知识：用于辅助判断包名、签名、图标、应用名、开发者等是否存在仿冒风险。
4. 研判规范：用于约束模型甲、模型乙、四智能体解释层和终审裁决的输出格式。

## 2. 数据存放位置

默认向量数据库位置：

```text
C:\Users\啤酒肚\Desktop\工作\test1\data\rag\rag_store.db
```

RAG 代码位置：

```text
C:\Users\啤酒肚\Desktop\工作\test1\engine\rag\
```

主要文件：

```text
engine\rag\store.py        RAG 数据库、文档写入、向量检索
engine\rag\embedding.py    文本向量化，优先本地模型，失败后使用 hash embedding
engine\rag\__init__.py     对外暴露 rag_status、search 等接口
tools\build_rag_index.py   RAG 索引构建脚本
```

APP-RAG 原始资料目录：

```text
C:\Users\啤酒肚\Desktop\工作\test1\APP-RAG
```

## 3. APP-RAG 已支持的文件类型

当前构建脚本会递归扫描 `APP-RAG` 目录，支持：

```text
.docx
.pptx
.xlsx
.pdf
.txt
.md
.csv
```

当前已验证的 `APP-RAG` 文件规模：

```text
.docx  23 个
.pdf   13 个
.xlsx   6 个
.pptx   4 个
.jpg    2 个，不入库
.png    1 个，不入库
```

图片暂时不进入 RAG。后续如果做多模态，可以把图标、截图、流程图先 OCR 或视觉解析成文字，再进入 RAG。

## 4. 构建 RAG 索引

在项目目录执行：

```powershell
cd C:\Users\啤酒肚\Desktop\工作\test1
python tools\build_rag_index.py --reset
```

只构建 APP-RAG 文档，不混入历史报告、人工标注、正版库：

```powershell
python tools\build_rag_index.py --reset --skip-reports --skip-manual --skip-docs --skip-genuine
```

限制每类来源最多导入 200 条，适合快速测试：

```powershell
python tools\build_rag_index.py --reset --limit-per-source 200
```

指定 APP-RAG 目录：

```powershell
python tools\build_rag_index.py --reset --app-rag-dir ".\APP-RAG"
```

## 5. 当前 APP-RAG 构建验证结果

已完成一次完整 APP-RAG 构建验证，结果如下：

```json
{
  "app_rag": 376,
  "sources": {
    "threat_family_ioc": 238,
    "official_app_asset": 120,
    "judgement_spec": 9,
    "app_rag_document": 9
  }
}
```

含义：

```text
threat_family_ioc    黑产、诈骗、情报、IOC、反诈相关资料
official_app_asset   正版 APP、仿冒、资产、APP 全景态势相关资料
judgement_spec       判定依据、研判规范、标签、分类、培训材料
app_rag_document     无法明确归类但仍可检索的普通资料
```

## 6. 检索 API

查看 RAG 状态：

```text
GET /api/rag/status
```

手动检索：

```text
POST /api/rag/search
Content-Type: application/json

{
  "query": "虚假贷款 黑产家族 APP 判定 证据链",
  "top_k": 6
}
```

指定来源类型检索：

```json
{
  "query": "仿冒 APP 包名 签名 图标 相似度",
  "top_k": 5,
  "source_types": ["official_app_asset", "judgement_spec"]
}
```

## 7. RAG 在研判流程中的使用位置

当前研判流程中，RAG 会在生成 EvidenceBlock 后被调用。系统会基于样本字段、四智能体证据、业务标签、家族信息、仿冒信息等构造查询词，然后召回相似知识。

RAG 结果会注入给：

1. 四智能体的大模型解释层。
2. 模型甲初判。
3. 模型乙初判。
4. 质疑阶段。
5. 反驳阶段。
6. 终审裁决。

RAG 不直接修改：

```text
四智能体原始 EvidenceBlock
XGBoost 概率
最终融合权重
```

也就是说，RAG 是“参考上下文”，不是“最终裁判”。

## 8. 当前 embedding 方法

代码位置：

```text
engine\rag\embedding.py
```

当前逻辑：

1. 优先尝试加载本地 embedding 模型。
2. 如果本地没有 `torch`、`transformers` 或模型文件，则自动降级为 `local_hash_embedding`。
3. `local_hash_embedding` 不联网、不花钱、能稳定运行，但语义检索能力弱于真正的中文 embedding 模型。

当前验证环境显示：

```text
embedding = local_hash_embedding
原因：缺少 torch / transformers
```

如果你想提高检索质量，建议后续接入：

```text
BAAI/bge-small-zh-v1.5
BAAI/bge-large-zh-v1.5
bce-embedding-base_v1
text2vec-base-chinese
```

## 9. APP-RAG 能不能直接用于微调

结论：APP-RAG 更适合作为 RAG 知识库，不适合直接当作 SFT / DPO 训练集。

原因：

```text
APP-RAG 是规范、白皮书、培训材料、表格和说明文档。
它们通常没有“输入样本 -> 标准 EvidenceBlock -> 人工结论 -> 高质量证据链”这种监督训练结构。
```

可以用于微调的高价值数据应该长这样：

```json
{
  "input": {
    "sample": "样本字段",
    "evidence_blocks": "四智能体证据",
    "rag_context": "召回规范和相似案例"
  },
  "output": {
    "verdict": "恶意 / 可疑 / 良性",
    "risk_level": "高风险 / 中风险 / 低风险",
    "evidence_chain": ["证据链 1", "证据链 2"],
    "contradictions": ["矛盾点"],
    "confidence": 0.82
  }
}
```

因此，最适合做微调的数据来源是：

1. 你们已经人工标注过的冲突样本。
2. APP 中人工复核后的报告。
3. 已经确认正确的双模型辩论报告。
4. 专家修订过的 EvidenceBlock 中文解释。

APP-RAG 可以作为这些训练样本的“参考知识”，但不能直接替代人工标签。

## 10. 后续推荐

如果目标是让大模型更稳定，建议优先做三件事：

1. 保留当前 RAG，把 APP-RAG、人工标注案例、正版库、研判规范都入库。
2. 在 APP 里继续收集人工复核数据，形成真正的 SFT 样本。
3. 后续用这些复核样本训练“报告生成模型”或“证据解释模型”，而不是直接拿 APP-RAG 文档硬训。

如果目标是提高检索质量，建议：

1. 安装本地中文 embedding 模型。
2. 对 APP-RAG 文档做更细的字段化切分。
3. 将正版 APP 库、黑产家族库、人工案例库分别建立 source_type。
4. 在 prompt 中只注入 top 3-5 条最相关 RAG 结果，避免上下文过长。
