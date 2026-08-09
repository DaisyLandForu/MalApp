from __future__ import annotations

from pathlib import Path

import win32com.client as win32


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "MalApp_恶意APP智能研判平台_项目汇报.pptx"


def rgb(r: int, g: int, b: int) -> int:
    return r + g * 256 + b * 65536


C = {
    "bg": rgb(248, 250, 252),
    "ink": rgb(15, 23, 42),
    "muted": rgb(100, 116, 139),
    "line": rgb(203, 213, 225),
    "soft": rgb(241, 245, 249),
    "teal": rgb(15, 118, 110),
    "blue": rgb(2, 132, 199),
    "amber": rgb(217, 119, 6),
    "red": rgb(220, 38, 38),
    "green": rgb(22, 163, 74),
}


def set_text(shape, text: str, size: int, color: str = "ink", bold: bool = False):
    shape.TextFrame.WordWrap = True
    shape.TextFrame.MarginLeft = 10
    shape.TextFrame.MarginRight = 10
    shape.TextFrame.MarginTop = 6
    shape.TextFrame.MarginBottom = 6
    tr = shape.TextFrame.TextRange
    tr.Text = text
    tr.Font.Name = "Microsoft YaHei"
    tr.Font.Size = size
    tr.Font.Color.RGB = C[color]
    tr.Font.Bold = -1 if bold else 0


def text(slide, content: str, x: float, y: float, w: float, h: float, size=13, color="ink", bold=False):
    shape = slide.Shapes.AddTextbox(1, x, y, w, h)
    set_text(shape, content, size, color, bold)
    return shape


def box(slide, x: float, y: float, w: float, h: float, fill="soft", line="line", radius=True):
    shape = slide.Shapes.AddShape(5 if radius else 1, x, y, w, h)
    shape.Fill.ForeColor.RGB = C[fill]
    shape.Line.ForeColor.RGB = C[line]
    return shape


def slide(prs, title: str, subtitle: str = ""):
    s = prs.Slides.Add(prs.Slides.Count + 1, 12)
    s.FollowMasterBackground = False
    s.Background.Fill.ForeColor.RGB = C["bg"]
    text(s, title, 36, 24, 850, 42, 24, "ink", True)
    if subtitle:
        text(s, subtitle, 38, 68, 860, 30, 12, "muted")
    return s


def bullets(items: list[str]) -> str:
    return "\n".join(f"• {item}" for item in items)


def card(slide, title: str, items: list[str], x: float, y: float, w: float, h: float, accent="teal", size=11):
    box(slide, x, y, w, h, "soft", "line", True)
    bar = box(slide, x, y, 5, h, accent, accent, False)
    bar.Line.Visible = 0
    text(slide, title, x + 16, y + 10, w - 28, 24, 15, "ink", True)
    text(slide, bullets(items), x + 18, y + 42, w - 30, h - 48, size, "ink")


def para_card(slide, title: str, body: str, x: float, y: float, w: float, h: float, accent="teal", size=12):
    box(slide, x, y, w, h, "soft", "line", True)
    bar = box(slide, x, y, 5, h, accent, accent, False)
    bar.Line.Visible = 0
    text(slide, title, x + 16, y + 10, w - 28, 24, 15, "ink", True)
    text(slide, body, x + 18, y + 42, w - 30, h - 48, size, "ink")


def two_col(slide, left_title, left_items, right_title, right_items, note=""):
    card(slide, left_title, left_items, 38, 124, 430, 318 if note else 360, "teal")
    card(slide, right_title, right_items, 492, 124, 430, 318 if note else 360, "blue")
    if note:
        para_card(slide, "说明", note, 38, 456, 884, 54, "amber", 11)


def three_col(slide, cards: list[tuple[str, list[str], str]]):
    xs = [38, 333, 628]
    for x, (title, items, accent) in zip(xs, cards):
        card(slide, title, items, x, 122, 270, 365, accent, 10)


def four_grid(slide, cards: list[tuple[str, list[str], str]]):
    positions = [(38, 116), (492, 116), (38, 320), (492, 320)]
    for (title, items, accent), (x, y) in zip(cards, positions):
        card(slide, title, items, x, y, 430, 170, accent, 10)


def flow(slide, items: list[str], x=42, y=156, w=116, h=70, gap=16):
    for i, item in enumerate(items):
        shape = box(slide, x + i * (w + gap), y, w, h, "soft", "teal" if i in (2, 5) else "line", True)
        set_text(shape, item, 11, "ink", True)
        if i < len(items) - 1:
            text(slide, "→", x + i * (w + gap) + w + 1, y + 19, gap + 10, 30, 18, "teal", True)


def placeholder(slide, title: str, x: float, y: float, w: float, h: float):
    box(slide, x, y, w, h, "bg", "line", True)
    text(slide, title, x + 14, y + 12, w - 28, 26, 14, "ink", True)
    text(slide, "结果展示由你后续粘贴：可放 APP 列表、单样本详情、四智能体证据、双模型辩论截图。", x + 14, y + h / 2 - 24, w - 28, 54, 12, "muted")


def build():
    ppt = win32.Dispatch("PowerPoint.Application")
    ppt.Visible = True
    ppt.DisplayAlerts = False
    prs = ppt.Presentations.Add()
    prs.PageSetup.SlideWidth = 960
    prs.PageSetup.SlideHeight = 540

    # 1
    s = slide(prs, "恶意 APP 智能研判平台", "基于四智能体、XGBoost、RAG、双模型辩论与桌面端 APP 的自动化研判系统")
    text(s, "MalApp", 54, 142, 300, 60, 44, "teal", True)
    text(s, "项目汇报详细版\n覆盖功能设计、技术栈、训练流程、上下文工程、模型部署、性能优化和后续路线。最后结果展示页已预留，你可以直接粘贴自己的运行截图。", 58, 218, 560, 115, 17, "ink")
    box(s, 660, 120, 230, 275, "teal", "teal", True)
    text(s, "数据接入\n特征工程\nEvidenceBlock\nXGBoost 概率\nRAG 检索\n双模型辩论\n结构化报告", 700, 145, 160, 215, 19, "bg", True)

    # 2
    s = slide(prs, "项目背景：为什么要做这个系统", "人工处理引擎冲突样本时，真正困难不在单个字段，而在证据链、权重和矛盾点的综合判断")
    two_col(
        s,
        "业务痛点",
        [
            "360、CM 或其他引擎可能对同一 APP 给出不同结论：一个判恶意，一个判良性。",
            "样本字段多，常见输入包含 MD5/SHA1、包名、应用名、签名、控制域名、下载地址、家族、仿冒标签、业务分类等。",
            "人工需要判断哪些证据更强：比如黑产家族命中、涉诈业务标签、签名异常、仿冒标记、权限缺失之间哪个更可信。",
            "同一批样本如果没有缓存和标准化流程，容易重复研判、重复消耗模型时间。",
        ],
        "建设目标",
        [
            "把不同 Excel、样本库和冲突数据统一成 APP 可研判格式。",
            "四个领域智能体先抽取结构化证据，避免大模型直接面对杂乱字段。",
            "XGBoost 负责给出可训练、可验证的恶意概率；大模型负责解释证据链、发现矛盾、形成辩论结论。",
            "桌面端 APP 支持数据加载、批量研判、暂停/继续、缓存复用、报告查看和导出。",
        ],
        "核心思想：先用程序和机器学习把证据标准化，再让大模型做解释和交叉质疑；大模型不直接替代全部规则，也不盲目复读 XGBoost。",
    )

    # 3
    s = slide(prs, "总体技术架构", "系统按数据层、证据层、模型层、辩论层、展示层分工，便于调试和扩展")
    flow(s, ["Excel/样本库", "字段归一", "四智能体", "XGBoost", "RAG", "双模型辩论", "报告输出"])
    four_grid(s, [
        ("数据层", ["Excel 导入：选择 sheet、表头行、开始行、传输数量。", "SQLite 保存样本、批次、任务、报告和缓存。", "支持测试集、冲突样本、恶意/白样本训练集。"], "teal"),
        ("证据层", ["Raw Evidence：权限、签名、URL、家族、正版匹配等原始结果。", "Structured EvidenceBlock：程序稳定生成。", "LLM Explanation：大模型只负责中文解释和矛盾分析。"], "blue"),
        ("模型层", ["四个领域 XGBoost 输出恶意概率。", "融合层综合四智能体、A/B 引擎、证据强度。", "验证集搜索阈值并校准置信度。"], "amber"),
        ("交互层", ["桌面端 Web UI + EXE 打包。", "运行总览、数据加载、新建研判、结果详情。", "支持暂停、继续、刷新批次和报告缓存。"], "red"),
    ])

    # 4
    s = slide(prs, "项目真实技术栈", "这里写的是当前项目实际使用的组件，不是泛泛的技术名词")
    three_col(s, [
        ("后端与存储", ["Python 标准库 HTTP 服务：run.py 中基于 BaseHTTPRequestHandler 暴露 API。", "SQLite：保存样本、任务、研判结果、报告缓存、RAG 索引元数据。", "Excel 处理：读取 xlsx 后转换为统一 APP 可导入字段。", "PyInstaller/EXE：把桌面端封装成可双击运行的应用。"], "teal"),
        ("机器学习与推理", ["XGBoost：训练四个领域模型和融合模型。", "vLLM：在服务器上部署 OpenAI-compatible 模型 API。", "本地 Qwen：可作为临时推理模型，但速度和 JSON 稳定性较弱。", "JSON Schema 校验：保证模型输出字段合规。"], "blue"),
        ("前端与工程", ["HTML/CSS/JavaScript：本地 Web UI，不依赖复杂前端框架。", "ThreadPoolExecutor：四智能体解释、模型甲/乙初判与质疑并行。", "RAG：向量索引和检索 API，把历史案例、规范、IOC、正版资产注入提示词。", "缓存：重复样本直接复用已有报告。"], "amber"),
    ])

    # 5
    s = slide(prs, "数据接入：Excel 如何进入 APP", "你可以自己决定一次导入多少条数据，系统会把不同格式整理成统一研判输入")
    two_col(
        s,
        "导入流程",
        [
            "在“数据加载”页面选择 Excel 文件，读取工作表列表。",
            "设置表头所在行、数据开始行、本次传输数量：例如从第 2 行开始导入 10 条。",
            "系统识别 md5、sample_id、app_name、package_name、sha1、签名、URL、家族、业务标签等字段。",
            "导入后形成一个批次，显示“总条数、待研判、已完成”。",
        ],
        "为什么要统一格式",
        [
            "恶意样本、白样本、360/CM 冲突样本和人工标注样本原始列名不完全一致。",
            "统一字段后，四智能体才能稳定读取同一批特征。",
            "测试集里的 gold_label、xgb_probability 等评估列不会直接泄露给大模型。",
            "APP 研判新样本时，XGBoost 会根据特征重新计算概率，而不是照抄 Excel 里的预测列。",
        ],
    )

    # 6
    s = slide(prs, "四智能体分工：不是四个聊天机器人", "当前四智能体的核心是领域工具 + 结构化证据生成，可选再接大模型解释层")
    four_grid(s, [
        ("静态分析智能体", ["输入：MD5/SHA、包名、证书指纹、签名状态、SDK、权限、加固壳信息。", "输出：静态可信度、签名异常、加固/混淆、SDK 风险、异常项列表。", "用途：判断 APP 静态结构是否存在恶意或规避分析迹象。"], "teal"),
        ("情报溯源智能体", ["输入：controlUrl、downloadUrl、域名、IP、邮箱、手机号、IOC、家族字段。", "输出：威胁情报命中、C2/下载基础设施、黑产家族关联图。", "用途：解释样本和外部恶意基础设施的关联。"], "blue"),
        ("仿冒研判智能体", ["输入：fakeApp、正版资产库、应用名、包名、图标、签名、编辑距离。", "输出：仿冒概率、仿冒分类、缺失字段、正版匹配证据。", "用途：判断是否冒充银行、钱包、贷款、社交等正版应用。"], "amber"),
        ("业务打标智能体", ["输入：病毒名、业务 score、涉诈家族、反诈分类、版本状态、上游风险分。", "输出：涉诈大类/小类、危害类型、业务影响等级。", "用途：把技术证据翻译成反诈业务可读标签。"], "red"),
    ])

    # 7
    s = slide(prs, "EvidenceBlock：证据标准化格式", "所有智能体都输出统一结构，后续训练、融合、RAG 和辩论都围绕它展开")
    para_card(
        s,
        "EvidenceBlock 的作用",
        "EvidenceBlock 是连接“原始字段”和“大模型解释”的中间层。它不是纯自然语言，也不是原始 Excel 行，而是一个稳定 JSON：里面包含智能体名称、判断结论、恶意概率、置信度、证据项、证据强度、来源字段、缺失字段、证据方向。这样做的好处是：模型不会被大量无关字段淹没，前端也能用统一格式展示。",
        38, 116, 884, 92, "teal", 12,
    )
    three_col(s, [
        ("核心字段", ["agent：哪个智能体输出。", "claim：该领域结论。", "score：恶意概率，优先使用领域 XGBoost。", "confidence：该概率是否可靠，不等于恶意概率。"], "blue"),
        ("证据字段", ["evidence_type：签名、IOC、仿冒、业务标签等。", "source_fields：来自哪些原始字段。", "strength：单条证据强度。", "direction：支持恶意、支持良性或背景信息。"], "amber"),
        ("质量字段", ["missing_fields：缺失哪些关键字段。", "contradictions：证据之间是否矛盾。", "evidence_ref：后续 RAG 或记忆召回用。", "explanation：中文逻辑说明。"], "red"),
    ])

    # 8
    s = slide(prs, "证据强度、恶意概率、置信度分别是什么", "这三个数经常被混淆，PPT 里必须讲清楚")
    three_col(s, [
        ("证据强度 strength", ["描述某一条证据本身有多强。", "例：黑产家族命中通常强于普通 SDK 风险。", "来源：字段含义、证据类型、训练权重、历史经验综合。", "不是最终恶意概率，只是证据项强弱。"], "teal"),
        ("恶意概率 score/probability", ["描述当前样本在该领域或融合层被判恶意的概率。", "四智能体 score 优先来自对应 XGBoost 领域模型。", "模型甲/乙 score 是大模型基于证据链自己的恶意倾向判断。", "最终概率由 XGBoost 与大模型结果融合。"], "blue"),
        ("置信度 confidence", ["描述“这个判断靠不靠谱”。", "需要结合验证集校准、字段覆盖率、证据一致性和缺失字段。", "概率接近 0 或 1 都可能高置信；概率接近 0.5 往往低置信。", "不能简单等于恶意概率。"], "amber"),
    ])

    # 9
    s = slide(prs, "XGBoost 是怎么训练和使用的", "它不是手工加分表，而是从训练数据中学习特征组合与恶意标签的关系")
    two_col(
        s,
        "训练输入",
        [
            "恶意样本：从 output_app_judgment 等恶意 APP 特征文件整理得到。",
            "白样本：从 output_app_white_lite 中筛选有特征的正版/良性样本。",
            "人工冲突样本：360/CM 判断冲突但人工已有标注，用于训练边界场景。",
            "一致低分样本：360 和 CM 分数为 0 的部分样本，用作弱良性补充。",
        ],
        "训练产物",
        [
            "四棵领域模型：static_analysis、threat_intel、impersonation、business_label。",
            "融合模型：综合四个领域概率、A/B 引擎差异、证据强度和字段覆盖。",
            "阈值：在验证集上自动搜索良性阈值和恶意阈值。",
            "校准：temperature scaling / isotonic calibration 用来让概率更接近真实准确率。",
        ],
        "树模型的直观理解：每棵树会学习“如果 fake_app 命中 + 黑产家族命中 + 上游风险高，则恶意概率高；如果签名正常 + 无 IOC + 正版匹配，则恶意概率低”。最终由多棵树投票/累加得到概率。",
    )

    # 10
    s = slide(prs, "为什么分四个领域模型，而不是一棵大树", "拆成四个领域模型是为了可解释、可调试、可扩展")
    two_col(
        s,
        "四棵树的好处",
        [
            "每个智能体只学习自己领域的特征，不会被其他领域噪声淹没。",
            "前端可以解释：静态、情报、仿冒、业务分别为什么高或低。",
            "某一领域训练数据不足时，只影响该领域，不会污染整个模型。",
            "后续如果新增图标 OCR、SDK 风险库、IOC 库，可以只增强对应智能体。",
        ],
        "一棵大树的问题",
        [
            "虽然也能训练，但解释会变差：很难说明是情报证据、仿冒证据还是业务证据导致恶意概率高。",
            "当数据不纯时，大模型/前端只能看到一个概率，难以定位 XGBoost 为什么错。",
            "用户提出“为什么特征看起来良性但 XGBoost 恶意高”时，领域模型更容易追踪原因。",
            "最终融合层仍然可以像一棵总模型一样综合四个领域结果。",
        ],
    )

    # 11
    s = slide(prs, "双模型辩论：模型甲和模型乙各做什么", "模型甲/乙不是四智能体，它们读取 EvidenceBlock 后做独立研判、质疑和反驳")
    two_col(
        s,
        "模型甲：保守复核",
        [
            "定位：强调证据交叉印证、反例、缺失字段和误报风险。",
            "关注：如果只有业务标签但缺少 IOC/权限/签名异常，是否可能误报。",
            "输出：综合结论、风险等级、核心论据、矛盾点、恶意倾向分。",
            "要求：不能直接复制 XGBoost 分数，必须说明具体证据链。",
        ],
        "模型乙：风险优先",
        [
            "定位：强调高危权限、黑产家族、C2、仿冒、业务危害链。",
            "关注：即使静态特征正常，是否已有足够情报和业务证据支持恶意。",
            "输出：对模型甲的质疑、关键证据补充和风险优先结论。",
            "要求：指出对方证据不足、逻辑跳跃或遗漏字段。",
        ],
    )

    # 12
    s = slide(prs, "辩论四阶段上下文组成", "上下文不是一次性塞全部字段，而是分阶段、分预算传递")
    four_grid(s, [
        ("初判 initial", ["输入：较完整 EvidenceBlock、样本摘要、RAG 摘要。", "模型甲/乙并行输出自己的结论。", "需要引用具体证据块，不能只说概率。"], "teal"),
        ("质疑 attack", ["输入：对方结论、关键论据、矛盾点、top 证据。", "目标：攻击对方证据不足、逻辑跳跃、字段缺失。", "甲乙可并行质疑。"], "blue"),
        ("反驳 rebuttal", ["输入：对方质疑点、自己的关键证据、必要字段。", "目标：回应质疑或承认不足并修正结论。", "为降低 token，只传 top 证据和摘要。"], "amber"),
        ("终审 closing", ["输入：压缩后的双方最终立场、关键证据、矛盾点。", "输出：恶意/可疑/良性、风险等级、最终分数。", "可配置单模型终审以提速。"], "red"),
    ])

    # 13
    s = slide(prs, "JSON 输出协议与稳定性处理", "大模型稳定输出不是靠一句“请输出 JSON”，而是靠五层约束")
    three_col(s, [
        ("提示词约束", ["明确 required keys：verdict、score、risk_level、arguments、evidence_refs、confidence 等。", "要求字段短、中文解释清楚、不得输出无关自由文本。", "要求引用 evidence_ref，减少幻觉。"], "teal"),
        ("解码与预算", ["降低输出 token，避免超上下文。", "初判保留更多证据，质疑/反驳压缩证据。", "必要时提高服务器模型超时时间。"], "blue"),
        ("校验与修复", ["后端用 schema 校验 JSON 字段和类型。", "失败后进入 repair 流程，让模型只修复格式。", "仍失败则记录错误，不使用规则回退冒充大模型。"], "amber"),
    ])

    # 14
    s = slide(prs, "RAG 设计：项目里应该存什么", "RAG 用来补充背景知识和历史经验，不是替代四智能体特征工程")
    two_col(
        s,
        "适合放入 RAG 的内容",
        [
            "历史人工标注案例：最有价值，可召回相似冲突样本的人工判断理由。",
            "黑产家族/IOC 知识：MISP Galaxy、URLhaus、MalwareBazaar 等公开资料。",
            "正版 APP/仿冒知识：genuine_new.sql 和内部正版资产库。",
            "研判规范：文档 4.1、4.2、四智能体职责、EvidenceBlock schema。",
        ],
        "什么时候使用",
        [
            "四智能体解释层：补充家族、IOC、正版资产或规范背景。",
            "模型甲/乙初判：读取与当前证据相关的少量相似案例。",
            "质疑/反驳：只按 evidence_ref 拉取相关证据，避免上下文爆炸。",
            "终审：只使用压缩后的关键 RAG 摘要。",
        ],
    )

    # 15
    s = slide(prs, "Hermes 与当前项目的关系", "当前项目实现的是 Hermes 风格编排，不是直接启动官方 Hermes Agent Runtime")
    two_col(
        s,
        "当前已实现",
        [
            "主管流程：统一调度四智能体、XGBoost、RAG、模型甲/乙和终审。",
            "工具式智能体：四智能体像可调用工具一样接收样本并输出 EvidenceBlock。",
            "并发派发：四智能体解释层、模型甲/乙初判和质疑可并行。",
            "跨样本缓存：已研判报告写入本地缓存，重复样本直接复用。",
        ],
        "官方 Hermes 可补充",
        [
            "Runtime：长期运行、健康检查、任务生命周期、定时任务。",
            "Tool Sandbox：隔离工具执行风险，限制文件和命令访问。",
            "A2A Protocol：让多个 Agent 跨进程、跨服务通信。",
            "技能记忆/跨 session 记忆/消息网关：用于持续学习和自动扫描。",
        ],
        "结论：可以后续把当前四智能体包装成 Hermes 工具，让官方 Hermes 主管调用；但现阶段 APP 已有自己的主管编排层。",
    )

    # 16
    s = slide(prs, "APP 功能模块", "用户侧看到的是完整研判工作台，而不是命令行脚本")
    four_grid(s, [
        ("运行总览", ["展示引擎原始数据、归一化特征、人工标注、研判结果、报告缓存数量。", "用于快速判断当前 APP 数据是否加载成功。"], "teal"),
        ("数据加载", ["选择 Excel 文件、sheet、表头行、开始行、传输条数。", "支持自己控制导入多少数据。"], "blue"),
        ("新建研判", ["选择批次，设置本次自动研判数量。", "支持自动开始、暂停、继续、刷新批次。", "失败样本会显示具体失败原因。"], "amber"),
        ("结果详情", ["展示四智能体证据、协同决策、XGBoost 与大模型融合。", "展示模型甲/乙初判、质疑、反驳、终审摘要。"], "red"),
    ])

    # 17
    s = slide(prs, "性能瓶颈与提速方法", "你看到 4-5 分钟/样本，主要时间花在大模型多轮辩论，而不是 XGBoost")
    two_col(
        s,
        "大致耗时分布",
        [
            "Excel/SQLite/字段归一：通常秒级。",
            "四智能体规则和 XGBoost：通常秒级到十几秒。",
            "四智能体大模型解释层：如果启用，会明显增加耗时。",
            "模型甲/乙初判、质疑、反驳、终审：最耗时，尤其是上下文长或服务器并发弱时。",
        ],
        "已做和可做的提速",
        [
            "重复样本走缓存：相同 md5 不重复调用大模型。",
            "四智能体解释层并行，模型甲/乙初判和质疑并行。",
            "质疑/反驳只传 top 2-3 证据和压缩摘要。",
            "终审可只用一个模型或轻量裁决器，节省一次模型调用。",
            "批量样本并行：一次同时跑 2 个样本，可提升吞吐但会增加服务器压力。",
        ],
    )

    # 18
    s = slide(prs, "服务器模型部署", "当前 APP 支持 OpenAI-compatible API，因此可以接 vLLM 部署的 Qwen/DeepSeek")
    two_col(
        s,
        "服务器侧",
        [
            "使用 vLLM 启动模型服务，暴露 /v1/chat/completions 兼容接口。",
            "模型甲可接 Qwen3-30B-A3B-Instruct-2507-FP8。",
            "模型乙可接 DeepSeek-R1-Distill-Qwen-32B-W4A16 或其他推理模型。",
            "4090 多卡部署时要关注显存、上下文长度、并发请求和超时时间。",
        ],
        "APP 侧",
        [
            "通过环境变量或界面配置模型甲/乙 API 地址、模型名、超时时间。",
            "如果模型输出不符合 JSON 协议，会触发校验失败或修复流程。",
            "如果上下文超过模型 max_model_len，会报 400 或 timed out，需要压缩证据。",
            "服务器模型比本地模型更适合批量研判，但仍要控制 token 和并发。",
        ],
    )

    # 19
    s = slide(prs, "训练、验证、测试集怎么用", "不是把所有数据混在一起训练，而是要用验证集调阈值、用测试集看真实效果")
    two_col(
        s,
        "数据划分",
        [
            "训练集：用于训练四个领域 XGBoost 和融合模型。",
            "验证集：用于搜索良性阈值、恶意阈值，以及做 temperature/isotonic 校准。",
            "测试集：训练完成后不参与调参，只放到 APP 里验证真实表现。",
            "人工冲突样本可以一部分训练/验证，剩余保存成测试集，专门看冲突场景表现。",
        ],
        "训练输出",
        [
            "模型文件：四个领域模型、融合模型、阈值配置、特征列配置。",
            "评估报告：AUC、F1、准确率、召回率、校准误差、loss 曲线。",
            "test_set_for_app.xlsx：可导入 APP 的测试集。",
            "feature_importance：解释哪些字段对模型影响最大。",
        ],
    )

    # 20
    s = slide(prs, "代码位置与调试入口", "后续如果你要自己排查，每一步都有对应文件")
    three_col(s, [
        ("核心研判", ["run.py：本地 HTTP 服务与 API 入口。", "engine/pipeline.py：四智能体和 EvidenceBlock 生成。", "engine/evidence_layers.py：Raw Evidence、Structured EvidenceBlock、LLM Explanation。", "engine/debate_flow.py：双模型辩论流程。"], "teal"),
        ("机器学习", ["ml_pipeline/xgb_pipeline.py：XGBoost 训练与评估。", "tools/train_selected_xgb_from_excels.py：用选定 Excel 训练。", "training_artifacts/：保存模型、阈值、测试集和报告。", "engine/decision_engine.py：XGBoost 与大模型融合决策。"], "blue"),
        ("前端与部署", ["web/index.html：APP 页面和交互。", "desktop_launcher.py：桌面端启动器。", "release/：打包后的 EXE。", "deploy/：服务器双模型部署说明。"], "amber"),
    ])

    # 21
    s = slide(prs, "已实现功能总结", "当前系统已经从“概念设计”推进到可运行的桌面端研判平台")
    two_col(
        s,
        "已实现",
        [
            "Excel 数据接入、字段归一化、批次管理和指定条数导入。",
            "四智能体 EvidenceBlock 标准输出，并支持中文逻辑解释。",
            "XGBoost 四领域模型、融合模型、阈值搜索、测试集导出。",
            "RAG 知识库、向量检索 API、相似案例/规范/IOC/正版资产注入。",
            "双模型辩论：初判、质疑、反驳、终审，带 JSON 校验和失败记录。",
            "桌面端 EXE、暂停继续、缓存复用、服务器模型接入、并行优化。",
        ],
        "仍需增强",
        [
            "扩大纯净训练数据，减少 XGBoost 对某些字段的过拟合。",
            "增强模型 JSON 输出稳定性，减少 schema 不合规和超时。",
            "完善人工复核闭环，把误报/漏报继续回流训练。",
            "接入官方 Hermes Runtime、Tool Sandbox、A2A 和长期记忆。",
            "把批量并行、Redis 缓存、布隆过滤器用于更大规模生产场景。",
        ],
    )

    # 22
    s = slide(prs, "结果展示页：运行与批量研判", "此页留给你粘贴最终 APP 截图")
    placeholder(s, "运行总览 / 数据加载", 42, 120, 410, 330)
    placeholder(s, "自动研判流水线 / 批量结果", 508, 120, 410, 330)

    # 23
    s = slide(prs, "结果展示页：单样本详情", "此页留给你粘贴四智能体、协同决策和双模型辩论截图")
    placeholder(s, "四智能体证据与协同决策", 42, 120, 410, 330)
    placeholder(s, "模型甲/乙辩论与终审报告", 508, 120, 410, 330)

    # 24
    s = slide(prs, "后续建设路线", "从可用平台继续升级到可学习、可追溯、可扩展的智能研判体系")
    four_grid(s, [
        ("数据路线", ["扩大恶意/白样本/冲突样本规模。", "人工复核结果回流训练。", "建立误报、漏报、边界样本库。"], "teal"),
        ("模型路线", ["继续训练四领域 XGBoost 和融合层。", "用 SFT 训练大模型稳定输出 EvidenceBlock/辩论 JSON。", "用验证集校准 confidence。"], "blue"),
        ("知识路线", ["扩充 MISP/IOC/URLhaus/正版资产 RAG。", "沉淀历史人工标注案例。", "把研判规范做成可检索知识。"], "amber"),
        ("工程路线", ["接入 Hermes Runtime 和工具沙箱。", "使用 Redis/布隆过滤器减少重复任务。", "支持多样本并发和服务监控。"], "red"),
    ])

    prs.SaveAs(str(OUT))
    prs.Close()
    ppt.Quit()
    print(OUT)


if __name__ == "__main__":
    build()
