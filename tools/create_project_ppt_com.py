from __future__ import annotations

from pathlib import Path

import win32com.client as win32


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "MalApp_恶意APP智能研判平台_项目汇报.pptx"


def rgb(r: int, g: int, b: int) -> int:
    return r + g * 256 + b * 65536


COLORS = {
    "bg": rgb(248, 250, 252),
    "ink": rgb(15, 23, 42),
    "muted": rgb(100, 116, 139),
    "line": rgb(203, 213, 225),
    "teal": rgb(15, 118, 110),
    "blue": rgb(2, 132, 199),
    "red": rgb(220, 38, 38),
    "amber": rgb(217, 119, 6),
    "soft": rgb(241, 245, 249),
}


def set_text(shape, text: str, size: int = 20, color: str = "ink", bold: bool = False):
    tr = shape.TextFrame.TextRange
    tr.Text = text
    tr.Font.Name = "Microsoft YaHei"
    tr.Font.Size = size
    tr.Font.Color.RGB = COLORS[color]
    tr.Font.Bold = -1 if bold else 0
    shape.TextFrame.WordWrap = True
    shape.TextFrame.MarginLeft = 10
    shape.TextFrame.MarginRight = 10
    shape.TextFrame.MarginTop = 6
    shape.TextFrame.MarginBottom = 6


def textbox(slide, text: str, x: float, y: float, w: float, h: float, size=20, color="ink", bold=False):
    shape = slide.Shapes.AddTextbox(1, x, y, w, h)
    set_text(shape, text, size, color, bold)
    return shape


def rect(slide, x: float, y: float, w: float, h: float, fill="soft", line="line", radius=False):
    # 1 = rectangle, 5 = rounded rectangle
    shape = slide.Shapes.AddShape(5 if radius else 1, x, y, w, h)
    shape.Fill.ForeColor.RGB = COLORS[fill]
    shape.Line.ForeColor.RGB = COLORS[line]
    return shape


def slide_base(prs, title: str, subtitle: str = ""):
    slide = prs.Slides.Add(prs.Slides.Count + 1, 12)
    slide.FollowMasterBackground = False
    slide.Background.Fill.ForeColor.RGB = COLORS["bg"]
    textbox(slide, title, 42, 26, 760, 46, 25, "ink", True)
    if subtitle:
        textbox(slide, subtitle, 44, 72, 820, 30, 13, "muted")
    return slide


def bullet_card(slide, title: str, bullets: list[str], x: float, y: float, w: float, h: float, accent="teal"):
    rect(slide, x, y, w, h, "soft", "line", True)
    bar = rect(slide, x, y, 5, h, accent, accent)
    bar.Line.Visible = 0
    textbox(slide, title, x + 18, y + 13, w - 34, 30, 16, "ink", True)
    text = "\n".join(f"• {b}" for b in bullets)
    textbox(slide, text, x + 20, y + 50, w - 35, h - 60, 12, "ink")


def two_cards(slide, left_title, left_bullets, right_title, right_bullets):
    bullet_card(slide, left_title, left_bullets, 45, 130, 420, 330, "teal")
    bullet_card(slide, right_title, right_bullets, 495, 130, 420, 330, "blue")


def four_cards(slide, cards: list[tuple[str, list[str], str]]):
    positions = [(45, 124), (505, 124), (45, 315), (505, 315)]
    for (title, bullets, accent), (x, y) in zip(cards, positions):
        bullet_card(slide, title, bullets, x, y, 410, 160, accent)


def flow_slide(slide, items: list[str]):
    x, y, w, h, gap = 48, 158, 124, 72, 18
    for i, item in enumerate(items):
        box = rect(slide, x + i * (w + gap), y, w, h, "soft", "teal" if i in (2, 5) else "line", True)
        set_text(box, item, 12, "ink", True)
        if i < len(items) - 1:
            textbox(slide, "→", x + i * (w + gap) + w + 2, y + 17, gap + 6, 35, 22, "teal", True)


def placeholder(slide, title: str, x: float, y: float, w: float, h: float):
    rect(slide, x, y, w, h, "bg", "line", True)
    textbox(slide, title, x + 14, y + 12, w - 28, 26, 14, "ink", True)
    textbox(slide, "此处粘贴你的运行截图或最终报告截图", x + 14, y + h / 2 - 15, w - 28, 32, 12, "muted")


def build():
    ppt = win32.Dispatch("PowerPoint.Application")
    ppt.Visible = True
    ppt.DisplayAlerts = False
    prs = ppt.Presentations.Add()
    prs.PageSetup.SlideWidth = 960
    prs.PageSetup.SlideHeight = 540

    # 1
    s = slide_base(prs, "恶意 APP 智能研判平台", "基于四智能体、XGBoost、RAG 与双模型辩论的自动化研判系统")
    textbox(s, "MalApp", 55, 155, 300, 60, 42, "teal", True)
    textbox(s, "项目汇报 PPT\n结果展示页已预留，可直接粘贴 APP 截图", 58, 230, 600, 70, 18, "ink")
    rect(s, 670, 120, 210, 260, "teal", "teal", True)
    textbox(s, "数据加载\n特征归一\n四智能体\n机器学习\n双模型辩论\n结构化报告", 704, 154, 155, 190, 20, "bg", True)

    # 2
    s = slide_base(prs, "项目背景与痛点", "为什么需要一个自动化恶意 APP 研判平台")
    two_cards(
        s,
        "人工研判难点",
        ["样本字段多，单个 APP 可能包含 60+ 个静态、网络、情报和业务字段", "360/CM 等引擎结论可能冲突，理由也不一致", "人工需要串联证据链、判断权重、识别矛盾点，耗时且不稳定"],
        "系统目标",
        ["把原始 Excel 和冲突样本统一成 APP 可研判格式", "用四个领域智能体分别抽取证据并输出 EvidenceBlock", "结合机器学习概率、大模型辩论和缓存机制输出稳定报告"],
    )

    # 3
    s = slide_base(prs, "总体架构", "从数据接入到最终报告的端到端流程")
    flow_slide(s, ["Excel/样本库", "字段归一", "四智能体", "XGBoost", "RAG 检索", "双模型辩论", "终审报告"])
    four_cards(s, [
        ("数据层", ["Excel 导入、行数可控", "SQLite 保存批次、任务、结果"], "teal"),
        ("证据层", ["Raw Evidence", "Structured EvidenceBlock"], "blue"),
        ("推理层", ["模型甲/乙并行初判", "质疑、反驳、终审"], "amber"),
        ("展示层", ["桌面端 APP", "报告详情、缓存、导出"], "red"),
    ])

    # 4
    s = slide_base(prs, "数据接入与预处理", "APP 可以接入 Excel、本地数据和冲突样本队列")
    two_cards(
        s,
        "Excel 接入",
        ["选择工作表、表头行、数据开始行和本次传输数量", "支持 md5、包名、应用名、签名、URL、家族、业务标签等字段", "导入后进入统一特征表，供研判流水线使用"],
        "冲突样本与缓存",
        ["可从 Engine A/B 检测差异中拉取高优先级任务", "已研判样本写入报告缓存，重复样本直接复用结果", "支持暂停、继续和批次刷新"],
    )

    # 5
    s = slide_base(prs, "四智能体设计", "四个领域智能体并行工作，互不等待")
    four_cards(s, [
        ("静态分析智能体", ["验证签名一致性", "识别加固、壳、混淆", "检查 SDK 和权限风险"], "teal"),
        ("情报溯源智能体", ["抽取 C2、下载地址、域名/IP", "关联黑产家族和 IOC", "输出威胁命中证据"], "blue"),
        ("仿冒研判智能体", ["对比正版 APP 名称、包名、图标", "分析包名编辑距离", "判断仿冒概率和缺失字段"], "amber"),
        ("业务打标智能体", ["把技术特征翻译为反诈业务标签", "输出涉诈分类、危害类型", "结合上游风险分和家族标签"], "red"),
    ])

    # 6
    s = slide_base(prs, "EvidenceBlock 标准输出", "先让程序稳定产出结构化证据，再交给大模型解释")
    two_cards(
        s,
        "核心字段",
        ["agent：证据来自哪个智能体", "claim：该智能体的领域判断", "score：恶意概率，优先来自领域 XGBoost", "confidence：该判断靠不靠谱，结合校准、字段覆盖和证据一致性"],
        "证据项",
        ["evidence_type：签名、加固、IOC、家族、仿冒、业务标签等", "source_fields：支撑证据来自哪些原始字段", "strength：单条证据强度", "missing_fields：影响判断完整性的缺失字段"],
    )

    # 7
    s = slide_base(prs, "机器学习层：XGBoost", "用历史样本学习恶意概率和证据权重，不只依赖人工规则")
    two_cards(
        s,
        "训练数据",
        ["恶意样本、白样本、人工标注冲突样本、360/CM 一致低分样本", "按训练集、验证集、测试集拆分", "人工冲突样本权重高于弱标签，一致样本用于补充边界"],
        "模型产物",
        ["四个领域 XGBoost：静态、情报、仿冒、业务", "融合层模型：综合四智能体、A/B/C 引擎和证据强度", "自动搜索阈值并做置信度校准"],
    )

    # 8
    s = slide_base(prs, "双模型辩论流程", "模型甲和模型乙不是复读 XGBoost，而是基于证据链独立判断")
    flow_slide(s, ["证据摘要", "模型甲初判", "模型乙初判", "交叉质疑", "双方反驳", "终审裁决"])
    four_cards(s, [
        ("模型甲", ["偏保守复核", "强调交叉印证、反例和误报风险"], "teal"),
        ("模型乙", ["偏风险优先", "强调高危权限、IOC、仿冒和业务危害"], "blue"),
        ("质疑阶段", ["指出对方证据不足", "标注逻辑跳跃和字段缺失"], "amber"),
        ("终审阶段", ["融合双方结论", "输出恶意/可疑/良性与置信度"], "red"),
    ])

    # 9
    s = slide_base(prs, "RAG 与上下文工程", "按需检索，避免把所有资料一次塞进上下文")
    two_cards(
        s,
        "RAG 内容",
        ["历史人工标注案例：最贴近业务的相似案例", "黑产家族/IOC：MISP Galaxy、URLhaus、MalwareBazaar 等公开库", "正版 APP/仿冒知识：genuine_new.sql 和内部正版资产库", "研判规范：4.1、4.2、四智能体职责和 EvidenceBlock schema"],
        "上下文压缩",
        ["initial_evidence_json：初判保留较多证据", "turn_evidence_json：质疑/反驳只给高强度证据和摘要", "closing_evidence_json：终审只保留关键裁决证据", "完整 evidence_memory 保存在本地，按 evidence_ref 召回"],
    )

    # 10
    s = slide_base(prs, "Hermes 风格编排与工具层", "当前项目是 Hermes MCP 兼容风格编排，不是官方 Hermes Runtime")
    two_cards(
        s,
        "已实现的编排能力",
        ["一个主管流程调度四个领域智能体", "四智能体可并行执行解释层", "模型甲/乙可并行初判和质疑", "失败时进行 JSON 校验、修复和错误记录"],
        "可继续接入的 Hermes 能力",
        ["官方 Runtime：长期运行和任务生命周期管理", "Tool Sandbox：隔离工具调用风险", "A2A Protocol：跨进程/跨服务智能体通信", "技能记忆、跨 session 记忆和消息网关"],
    )

    # 11
    s = slide_base(prs, "桌面端 APP 功能", "面向实际使用的研判工作台")
    four_cards(s, [
        ("运行总览", ["查看加载数据、研判结果、报告缓存", "展示服务在线状态"], "teal"),
        ("数据加载", ["Excel 读取和传输", "自定义导入条数和起始行"], "blue"),
        ("新建研判", ["自动批量研判", "暂停、继续、刷新批次"], "amber"),
        ("结果详情", ["四智能体证据", "双模型辩论", "融合概率和终审报告"], "red"),
    ])

    # 12
    s = slide_base(prs, "性能优化与部署", "当前重点是减少模型调用次数、压缩上下文和复用结果")
    two_cards(
        s,
        "提速策略",
        ["重复样本直接走缓存", "四智能体解释层并行", "模型甲/乙初判和质疑并行", "反驳阶段只传 top 证据、关键论据和对方质疑点", "终审可配置为单模型或轻量裁决器"],
        "部署方式",
        ["本地 Qwen 可作为临时模型，但速度和 JSON 稳定性有限", "服务器使用 vLLM 部署 OpenAI-compatible API", "支持 Qwen 与 DeepSeek 系模型分别作为模型甲/乙", "4090 多卡可承载双模型服务，但需控制上下文长度和并发"],
    )

    # 13
    s = slide_base(prs, "当前实现状态", "已实现能力与后续增强方向")
    two_cards(
        s,
        "已实现",
        ["Excel 数据接入和格式转换", "四智能体 EvidenceBlock 输出", "XGBoost 训练、测试集保存、APP 推理", "RAG 检索 API 和上下文注入", "双模型辩论、JSON 校验、失败记录", "桌面端 EXE 打包和服务器模型接入"],
        "待增强",
        ["进一步扩大纯净训练数据，降低 XGBoost 偏置", "接入官方 Hermes Runtime 和原生记忆组件", "完善模型输出协议稳定性与自动修复器", "建立人工复核闭环，持续校准置信度"],
    )

    # 14
    s = slide_base(prs, "结果展示页 1", "此页留给你粘贴 APP 运行结果截图")
    placeholder(s, "运行总览 / 数据加载截图", 48, 120, 400, 330)
    placeholder(s, "自动研判流水线截图", 510, 120, 400, 330)

    # 15
    s = slide_base(prs, "结果展示页 2", "此页留给你粘贴单样本研判详情")
    placeholder(s, "四智能体证据截图", 48, 118, 400, 335)
    placeholder(s, "双模型辩论与终审报告截图", 510, 118, 400, 335)

    # 16
    s = slide_base(prs, "后续建设路线", "把当前 APP 逐步升级为可持续学习的研判平台")
    four_cards(s, [
        ("数据闭环", ["新增人工复核入口", "沉淀误报/漏报样本", "定期重训与评估"], "teal"),
        ("模型闭环", ["SFT 标准化证据输出", "验证集校准置信度", "RLHF/偏好优化辩论质量"], "blue"),
        ("知识闭环", ["RAG 扩充 IOC/家族/正版资产", "相似案例召回", "规范文档检索"], "amber"),
        ("工程闭环", ["官方 Hermes Runtime", "任务队列与 Redis 缓存", "批量并发与服务监控"], "red"),
    ])

    prs.SaveAs(str(OUT))
    prs.Close()
    ppt.Quit()
    print(OUT)


if __name__ == "__main__":
    build()
