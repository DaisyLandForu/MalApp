const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const state = { overview: null, reports: [], pending: [], taskSummary: null, currentReport: null, importItems: [] };
state.excelFile = null;
state.lastBatchId = "";
state.batchJobId = "";
state.modelSettings = null;
state.hermesStatus = null;
state.validation = null;
state.fiveLayer = null;
state.fiveLayerWorkflows = null;
state.fiveLayerWorkflowTimer = null;
state.fiveLayerSuiteId = localStorage.getItem("malappFiveLayerSuiteId") || "";
try {
  state.fiveLayerBatchSizes = JSON.parse(localStorage.getItem("malappFiveLayerBatchSizes") || "{}") || {};
} catch (_error) {
  state.fiveLayerBatchSizes = {};
}
state.fiveLayerRagItems = [];
state.fiveLayerRagIndex = 0;
state.fiveLayerGoldItems = [];
state.fiveLayerGoldIndex = 0;
state.fiveLayerGoldOverview = null;
state.appValidationResults = {};
state.validationJudgedOnly = true;
const names = {
  malicious: "恶意", suspicious: "可疑", benign: "良性",
  high: "高风险", medium: "中风险", low: "低风险",
  pending: "待处理", processing: "处理中", completed: "已完成", failed: "失败",
  static_analysis: "静态分析智能体", threat_intel: "情报溯源智能体",
  impersonation: "仿冒研判智能体", business_label: "业务打标智能体",
  model_a: "模型甲", model_b: "模型乙", arbiter: "终审裁决",
};
const viewMeta = {
  overviewView: ["运行总览", "数据处理、智能体状态与研判结果"],
  tasksView: ["研判任务", "待处理队列与历史报告"],
  dataView: ["数据加载", "导入特征数据并管理样本队列"],
  judgeView: ["新建研判", "运行四智能体与双模型辩论"],
  detailView: ["结果详情", "证据、辩论与三引擎协同结论"],
};

viewMeta.validationView = ["模型验证", "对比真实标签、模型预测和人工复核样本"];
viewMeta.fiveLayerView = ["五层评测", "模型、RAG、Agent、端到端与生产运行统一门禁"];
viewMeta.learningView = ["训练闭环", "人工复核、agent_trace、reward 和训练数据导出"];
Object.assign(names, {
  malicious: "恶意", suspicious: "可疑", benign: "良性",
  correct: "正确", incorrect: "错误", review: "可疑/复核",
});

async function api(path, options = {}) {
  const response = await fetch(path, { headers: { "Content-Type": "application/json" }, ...options });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}
function esc(v) { return String(v ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]); }
let toastTimer;
function toast(message, error = false) {
  const el = $("#toast"); el.textContent = message; el.className = `toast show${error ? " error" : ""}`;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.className = "toast"; }, 2600);
}
Object.assign(names, {
  malicious: "恶意", suspicious: "可疑", benign: "良性",
  high: "高风险", medium: "中风险", low: "低风险",
  pending: "待处理", processing: "处理中", completed: "已完成", failed: "失败",
  static_analysis: "静态分析智能体", threat_intel: "情报溯源智能体",
  impersonation: "仿冒研判智能体", business_label: "业务打标智能体",
  model_a: "模型甲", model_b: "模型乙", arbiter: "终审裁决",
});
Object.assign(names, {
  malicious: "恶意", suspicious: "可疑", benign: "良性",
  high: "高风险", medium: "中风险", low: "低风险",
  pending: "待处理", processing: "处理中", completed: "已完成", failed: "失败",
  correct: "正确", incorrect: "错误", review: "可疑/复核",
});
const fieldLabels = {
  xgboost_domain_probability: "机器学习先验恶意概率",
  xgb_agent_scores: "智能体恶意概率",
  static_analysis: "静态分析智能体",
  threat_intel: "情报溯源智能体",
  impersonation: "仿冒研判智能体",
  business_label: "业务打标智能体",
  model_a: "模型甲",
  model_b: "模型乙",
  arbiter: "终审裁决",
  signature_status: "签名状态",
  certificate_fingerprint: "证书指纹",
  certificate_fingerprint_md5: "证书指纹 MD5",
  packer: "加固或混淆",
  unshell_info: "脱壳/加固信息",
  sdk_list: "SDK 清单",
  permissions: "权限列表",
  control_url: "控制端地址",
  download_url: "下载地址",
  control_mailbox: "控制邮箱",
  control_phone: "控制手机号",
  domains: "域名",
  ips: "IP 地址",
  threat_intel_records: "威胁情报记录",
  fraud_family: "涉诈家族",
  fraud_category_big: "涉诈大类",
  fraud_category_small: "涉诈小类",
  harm_type: "危害类型",
  fake_app: "仿冒应用标记",
  official_app_name: "正版应用名称",
  official_pkg: "正版包名",
  official_md5: "正版 MD5",
  official_icon: "正版图标",
  brand_similarity: "品牌相似度",
  icon_path: "图标路径",
  icon_base64: "图标 Base64",
  icon_hash: "图标哈希",
  icon_text: "图标文字",
  official_app_assets: "正版应用资产",
  impersonation_probability: "仿冒恶意概率",
  risk_score: "上游风险分数",
  business_tags: "业务标签",
  version_status: "版本状态",
  evidence_refs: "引用证据块",
  omissions: "遗漏证据",
  contradictions: "矛盾点",
  evidence_chain: "证据链",
  feature_relations: "特征关系",
  supports_malicious: "支撑恶意判断",
  supports_benign: "支撑良性判断",
  insufficient: "证据不足",
  analysis: "分析结果",
  "analysis.技术场景翻译": "技术场景翻译",
  "analysis.技术场景翻译.标签": "技术场景标签",
  "analysis.技术场景翻译:标签": "技术场景标签",
  technical_scene_translation: "技术场景翻译",
  "technical_scene_translation.labels": "技术场景标签",
  labels: "标签",
  matched_rules: "命中规则",
  harm_chain: "危害链",
  "harm_chain.stages": "危害链阶段",
  business_harm_labels: "业务危害标签",
  source: "来源",
  source_risk_score: "上游风险分数",
  source__risk_score: "上游风险分数",
  "source_上游风险分数": "上游风险分数",
  "source__上游风险分数": "上游风险分数",
  upstream_risk_score: "上游风险分数",
  app_name: "应用名称",
  package_name: "包名",
  md5: "MD5",
  sha1: "SHA1",
  sha256: "SHA256",
  genuine_package_match: "正版包名匹配",
  genuine_signature_match: "正版签名匹配",
  genuine_name_match: "正版名称匹配",
  name_obfuscation: "名称伪装",
  impersonation_flag: "仿冒标记",
  visual_similarity: "视觉相似度",
  sample_icon_available: "样本图标可用",
  official_asset_match: "正版资产匹配",
  "official_asset_match.asset_count": "正版资产数量",
  asset_count: "资产数量",
  assessment: "评估结果",
  review_verdict: "智能体判断结论",
  review_reason: "判断依据",
  trust_assessment: "字段可信度评估",
  causal_reasoning: "逻辑推导",
  feature_links: "特征关系",
  missing_impact: "缺失字段影响",
};
const evidenceTypeLabels = {
  signature_anomaly: "签名异常",
  signature_missing: "签名缺失",
  signature_normal: "签名正常",
  packer_or_obfuscation: "加固或混淆",
  permission_risk: "高危权限",
  sdk_risk: "SDK 风险",
  static_baseline: "静态基线",
  control_infrastructure: "控制端基础设施",
  network_indicator: "网络威胁指标",
  threat_intel_hit: "情报命中",
  malware_family: "黑产家族",
  threat_intel_clear: "情报未命中",
  declared_impersonation: "仿冒标记",
  official_asset_reference: "正版资产对照",
  brand_similarity: "品牌相似度",
  name_obfuscation: "名称或包名伪装",
  package_edit_distance: "包名编辑距离",
  impersonation_clear: "仿冒证据不足",
  fraud_category: "涉诈分类",
  harm_category: "危害类型",
  fraud_family: "涉诈家族",
  risk_score: "上游风险分数",
  version_status: "版本状态",
  business_tags: "业务标签",
  business_label_missing: "业务证据不足",
  missing_feature: "缺失关键字段",
  xgboost_domain_probability: "机器学习先验恶意概率",
  evidence_conflict: "证据冲突",
};
function fieldLabel(key) { return fieldLabels[key] || String(key || "").replace(/_/g, " "); }
function fieldTokenLabel(token) {
  const raw = String(token ?? "").trim().replace(/^['"“”`]+|['"“”`]+$/g, "");
  if (!raw) return "";
  if (fieldLabels[raw]) return fieldLabels[raw];
  const normalized = raw
    .replace(/^source__?/, "")
    .replace(/^analysis[:.]/, "")
    .replace(/^assessment[:.]/, "")
    .replace(/:/g, ".");
  if (fieldLabels[normalized]) return fieldLabels[normalized];
  const segments = normalized.split(/[.]/).filter(Boolean);
  const translated = segments
    .map((part) => fieldLabels[part] || evidenceTypeLabels[part] || part.replace(/_/g, " "))
    .join("·");
  return translated || raw.replace(/_/g, " ");
}
function quoteFieldToken(token) {
  const label = fieldTokenLabel(token);
  return label ? `“${label}”` : "";
}
function cleanQuotedValue(value) {
  return String(value ?? "")
    .trim()
    .replace(/^['"“”`\[]+|['"“”`\]]+$/g, "")
    .replace(/\s+/g, " ");
}
function normalizeGeneratedFeatureText(value) {
  let text = String(value ?? "");
  text = text.replace(/原始字段\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)\s*=\s*'([^']*)'/g, (_, key, val) => `原始字段${quoteFieldToken(key)}为“${cleanQuotedValue(val)}”`);
  text = text.replace(/原始字段\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)\s*=\s*"([^"]*)"/g, (_, key, val) => `原始字段${quoteFieldToken(key)}为“${cleanQuotedValue(val)}”`);
  text = text.replace(/原始字段\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)\s*=\s*([^，。；\n\r]+)/g, (_, key, val) => `原始字段${quoteFieldToken(key)}为“${cleanQuotedValue(val)}”`);
  text = text.replace(/原始字段\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)(?=[，。；\n\r]|$)/g, (_, key) => `原始字段${quoteFieldToken(key)}`);
  text = text.replace(/业务标签\s+([A-Za-z0-9_\u4e00-\u9fff.:-]+)为/g, (_, key) => `业务标签${quoteFieldToken(key)}为`);
  text = text.replace(/标签\s*=\s*\[([^\]]+)\]/g, (_, val) => `标签为“${cleanQuotedValue(val)}”`);
  text = text.replace(/结论\s+([^，。；\n\r]+)/g, (_, val) => `结论：${cleanQuotedValue(val)}`);
  text = text.replace(
    /(analysis[.:][A-Za-z0-9_\u4e00-\u9fff.:]+|technical_scene_translation(?:[.:][A-Za-z0-9_\u4e00-\u9fff]+)*|official_asset_match(?:[.:][A-Za-z0-9_\u4e00-\u9fff]+)*|visual_similarity(?:[.:][A-Za-z0-9_\u4e00-\u9fff]+)*|harm_chain(?:[.:][A-Za-z0-9_\u4e00-\u9fff]+)*|source__?[A-Za-z0-9_\u4e00-\u9fff]+|business_harm_labels|matched_rules)/g,
    (match) => fieldTokenLabel(match)
  );
  text = text.replace(/(上游风险分数|机器学习先验恶意概率|智能体恶意概率|仿冒恶意概率|风险分数)\s*=\s*([0-9.]+)/g, "“$1”为 $2");
  text = text.replace(/([：，。；、])\s+/g, "$1");
  text = text.replace(/\s+([：，。；、])/g, "$1");
  text = text.replace(/([\u4e00-\u9fff])\s+([\u4e00-\u9fff])/g, "$1$2");
  text = text.replace(/([，。；：、]){2,}/g, "$1");
  return text;
}
function confidenceText(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${Math.round((numeric <= 1 ? numeric : numeric / 100) * 100)}%` : "--";
}
function num(v) { return Number(v || 0).toLocaleString("zh-CN"); }
function bytes(v) {
  let n = Number(v || 0); const units = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i > 1 ? 2 : 1)} ${units[i]}`;
}
function score(v) {
  if (v === null || v === undefined || v === "") return "--";
  const n = Number(v);
  return Number.isFinite(n) ? (n <= 1 ? n.toFixed(3) : n.toFixed(1)) : "--";
}
function riskLevelText(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "未知";
  if (n >= 0.85) return "高风险";
  if (n >= 0.6) return "中风险";
  if (n >= 0.3) return "低到中风险";
  return "低风险";
}
function verdictByScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "--";
  if (n >= 0.85) return "恶意";
  if (n >= 0.6) return "可疑";
  return "良性";
}
function verdictCodeByScore(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "";
  if (n >= 0.85) return "malicious";
  if (n >= 0.6) return "suspicious";
  return "benign";
}
function verdictCodeFromText(value) {
  const text = String(value ?? "").toLowerCase();
  if (!text) return "";
  if (text.includes("恶") || text.includes("malicious")) return "malicious";
  if (text.includes("可疑") || text.includes("疑") || text.includes("suspicious")) return "suspicious";
  if (text.includes("良") || text.includes("benign")) return "benign";
  return "";
}
function scoreReviewConflictText(block, item) {
  const scoreCode = verdictCodeByScore(block?.score);
  const reviewCode = verdictCodeFromText(item?.review_verdict);
  if (!scoreCode || !reviewCode || scoreCode === reviewCode) return "";
  const scoreLabel = verdictByScore(block?.score);
  const reviewLabel = displayText(item?.review_verdict);
  return `该智能体的恶意概率指向“${scoreLabel}”，但智能体只看原始特征后的判断为“${reviewLabel}”。这属于机器学习概率与原始特征复核不一致，需要在模型甲乙辩论中结合字段缺失、证据强度和其他智能体结论重新取舍。`;
}
function cleanDebatePunctuation(value) {
  let text = String(value ?? "");
  text = text.replace(/模型([甲乙])\s*(提出质疑|质疑依据|反驳观点|补充依据)\s*[：:]\s*/g, "");
  text = text.replace(/本轮质疑基于([^：:\n]+)[：:]\s*质疑点/g, "本轮质疑基于$1，质疑点");
  text = text.replace(/质疑点\s*[：:]\s*/g, "");
  text = text.replace(/回答\s*[：:]\s*/g, "");
  text = text.replace(/[“"]恶意判断依据\s*[：:]\s*([^”"]+)[”"]/g, "恶意判断依据为$1");
  text = text.replace(/[“"]模型评分\s*[：:]?\s*([0-9.]+)[”"]/g, "模型评分 $1");
  text = text.replace(/请针对[“"]([^”"]+)[”"]说明/g, "请针对$1说明");
  text = text.replace(/([，。！？；：、])\s+([，。！？；：、])/g, "$1");
  text = text.replace(/\s+([，。！？；：、])/g, "$1");
  text = text.replace(/([，。！？；：、])\s+/g, "$1");
  text = text.replace(/；为什么/g, "；需要说明为什么");
  text = text.replace(/，为什么/g, "，需要说明为什么");
  text = text.replace(/([。！？])\1+/g, "$1");
  text = text.replace(/([，；：、])\1+/g, "$1");
  text = text.replace(/\s{2,}/g, " ");
  return text.trim();
}
function cleanGeneratedText(value) {
  let text = String(value ?? "");
  text = text.replace(/<think>[\s\S]*?<\/think>/gi, " ");
  text = text.replace(/<\/?think>/gi, " ");
  text = text.replace(/<\/?(?:b|strong|em|i|p|br|span|div|section|ol|ul|li)[^>]*>/gi, " ");
  // Protocol keys are backend metadata.  Do not show them as raw English text
  // when a model leaks JSON fragments into the analyst-facing report.
  text = text.replace(/\b(?:question|answer|arguments|evidence_refs|evidence_chain|feature_relations|contradictions|omissions|verdict|risk_level|confidence|score|accepted_corrections|discarded_claims)\b\s*[:：]?\s*/gi, "");
  text = text.replace(/\b(?:agent_judgement|agent_judgment|rule_judgement|rule_judgment|rule_judge|llm_ru|llm_review|llm_independent_review)\b\s*[:：]?\s*/gi, "");
  text = text.replace(/\b(question|answer|arguments|evidence_refs|evidence_chain|feature_relations|contradictions|omissions|verdict|risk_level|confidence|score)\s*[:：]\s*/gi, "");
  text = text.replace(/(^|[。；;，,\n\r\s])(?:question|answer|arguments|evidence_refs|evidence_chain|feature_relations|contradictions|omissions|verdict|risk_level|confidence|score)\s+/gi, "$1");
  text = text.replace(/协议字段已自动补齐/gi, "");
  text = text.replace(/自动补齐字段\s*[:：]\s*[^。；\n\r]+/gi, "");
  text = text.replace(/\b(score|verdict|risk_level|arguments|omissions|evidence_refs|confidence|contradictions|evidence_chain|feature_relations|accepted_corrections|discarded_claims)\b\s*,?\s*/gi, "");
  const pairs = [
    [/\bmodel_a\b/g, "模型甲"], [/\bmodel_b\b/g, "模型乙"], [/\barbiter\b/g, "终审裁决"],
    [/\bmalicious\b/gi, "恶意"], [/\bsuspicious\b/gi, "可疑"], [/\bbenign\b/gi, "良性"],
    [/\bhigh\b/gi, "高风险"], [/\bmedium\b/gi, "中风险"], [/\blow\b/gi, "低风险"],
    [/\bsupports_malicious\b/g, "支撑恶意判断"], [/\bsupports_benign\b/g, "支撑良性判断"], [/\binsufficient\b/g, "证据不足"],
    [/\bfake_app\b/gi, "仿冒应用标记"], [/\bcontrol_url\b/gi, "控制端地址"], [/\bdownload_url\b/gi, "下载地址"],
    [/\bcontrol_mailbox\b/gi, "控制邮箱"], [/\bcontrol_phone\b/gi, "控制手机号"], [/\bdomains\b/gi, "域名"], [/\bips\b/gi, "IP 地址"],
    [/\bthreat_intel_records\b/gi, "威胁情报记录"], [/\bfraud_family\b/gi, "涉诈家族"], [/\bfraud_category_big\b/gi, "涉诈大类"],
    [/\bfraud_category_small\b/gi, "涉诈小类"], [/\bharm_type\b/gi, "危害类型"], [/\brisk_score\b/gi, "上游风险分数"],
    [/\bpacker_or_obfuscation\b/gi, "加固或混淆"], [/\bsdk_risk\b/gi, "SDK 风险"], [/\bnetwork_indicator\b/gi, "网络威胁指标"],
    [/\bmalware_family\b/gi, "黑产家族"], [/\bdeclared_impersonation\b/gi, "仿冒标记"], [/\bimpersonation_probability\b/gi, "仿冒恶意概率"],
    [/\bxgboost_domain_probability\b/gi, "机器学习先验恶意概率"], [/\bxgb_agent_scores\b/gi, "智能体恶意概率"], [/\bxgb_score\b/gi, "机器学习分数"],
    [/\bofficial_app_name\b/gi, "正版应用名称"], [/\bofficial_pkg\b/gi, "正版包名"], [/\bofficial_md5\b/gi, "正版 MD5"],
    [/\bofficial_icon\b/gi, "正版图标"], [/\bbrand_similarity\b/gi, "品牌相似度"], [/\bicon_path\b/gi, "图标路径"],
    [/\bicon_base64\b/gi, "图标 Base64"], [/\bicon_hash\b/gi, "图标哈希"], [/\bicon_text\b/gi, "图标文字"],
    [/\bofficial_app_assets\b/gi, "正版应用资产"], [/\bstatic_analysis\b/g, "静态分析智能体"], [/\bthreat_intel\b/g, "情报溯源智能体"],
    [/\bimpersonation\b/g, "仿冒研判智能体"], [/\bbusiness_label\b/g, "业务打标智能体"], [/->/g, "，"], [/\?{2,}/g, ""],
    [/\bscore_review_disagreement\b/gi, "评分复核分歧"], [/\bllm_independent_review\b/gi, "智能体独立判断"],
    [/\bllm_review\b/gi, "智能体复核"], [/\bsource__?/gi, "来源字段"], [/\bcorrelates\s+with\b/gi, "与"],
    [/\bagent_judgement\b/gi, "智能体复核结论"], [/\bagent_judgment\b/gi, "智能体复核结论"],
    [/\brule_judgement\b/gi, "工具证据结论"], [/\brule_judgment\b/gi, "工具证据结论"],
    [/\brule_judge\b/gi, "工具证据结论"], [/\bllm_rule_disagreement\b/gi, "智能体复核与工具证据存在分歧"],
    [/\bllm_ru\b/gi, "智能体复核"], [/\bEvidenceBlock\b/g, "证据块"],
    [/ML概率/g, "机器学习概率"], [/LLM可疑冲突/g, "大模型可疑冲突"],
    [/\bquestion\b/gi, "质疑点"], [/\banswer\b/gi, "回应依据"], [/\bpresent\b/gi, "字段存在"],
    [/\brisk\b/gi, "风险"], [/\bkey evidence\b/gi, "关键证据"], [/\braw feature\b/gi, "原始特征"],
  ];
  pairs.forEach(([pattern, replacement]) => { text = text.replace(pattern, replacement); });
  Object.entries(fieldLabels)
    .sort((a, b) => b[0].length - a[0].length)
    .forEach(([key, label]) => { text = text.replaceAll(key, label); });
  text = normalizeGeneratedFeatureText(text);
  text = cleanDebatePunctuation(text);
  return text
    .replace(/[;；]\s*[;；]+/g, "；")
    .replace(/[，,]\s*[，,]+/g, "，")
    .replace(/[。\.]\s*[。\.]+/g, "。")
    .replace(/[。．.]\s*[。．.]+/g, "。")
    .replace(/\s*-\s*>\s*/g, "，")
    .replace(/(?:^|[，；。])\s*[,;:：]+\s*/g, "$1")
    .replace(/([，。；：、])\s*[,;:：]+\s*/g, "$1")
    .replace(/[,;]\s*$/g, "")
    .replace(/([。！？；，、])\s+([。！？；，、])/g, "$1")
    .replace(/([：，。；、])\s+/g, "$1")
    .replace(/\s+([，。；：、])/g, "$1")
    .replace(/([\u4e00-\u9fff])\s+([\u4e00-\u9fff])/g, "$1$2")
    .replace(/([，。；：、])\1+/g, "$1")
    .replace(/\s{2,}/g, " ")
    .trim();
}
function sentenceText(value) {
  return displayText(value).replace(/[。．.！？!?；;，,、\s]+$/g, "");
}
function endSentence(value) {
  const text = sentenceText(value);
  return text ? `${text}。` : "";
}
function joinSentenceParts(parts) {
  return parts.map(sentenceText).filter(Boolean).join("。");
}
function briefErrorText(value) {
  const raw = String(value ?? "").trim();
  if (!raw) return "研判失败，未返回具体原因。";
  const text = raw.replace(/\s+/g, " ");
  const lower = text.toLowerCase();
  const model = (text.match(/malapp-model-[ab]/i) || [])[0] || "模型接口";
  const endpoint = (text.match(/https?:\/\/[^\s;]+\/v1/i) || [])[0] || "";
  const endpointText = endpoint ? `接口：${endpoint}` : "";
  if (lower.includes("remote end closed") || lower.includes("connection closed")) {
    return `${model} 已连接但服务端主动断开，通常是模型服务未启动、正在重启、显存不足或请求超时。${endpointText}`;
  }
  if (lower.includes("timed out") || lower.includes("timeout")) {
    return `${model} 连接超时，请检查端口转发、服务进程和模型加载状态。${endpointText}`;
  }
  if (lower.includes("connection refused") || lower.includes("couldn't connect") || lower.includes("failed to connect")) {
    return `${model} 无法连接，请确认模型服务已启动且端口可访问。${endpointText}`;
  }
  if (lower.includes("bad request") || lower.includes("http error 400")) {
    return `${model} 拒绝请求，通常是模型名称、请求格式或上下文长度不兼容。${endpointText}`;
  }
  if (lower.includes("did not satisfy") || lower.includes("schema")) {
    return `${model} 返回内容未满足结构化格式要求，已停止本条研判。`;
  }
  return displayText(text).slice(0, 180);
}
function displaySimilarity(a, b) {
  const left = sentenceText(a).replace(/\s+/g, "");
  const right = sentenceText(b).replace(/\s+/g, "");
  if (!left || !right) return 0;
  if (left === right) return 1;
  const setLeft = new Set([...left]);
  const setRight = new Set([...right]);
  let common = 0;
  setLeft.forEach((ch) => { if (setRight.has(ch)) common += 1; });
  return common / Math.max(setLeft.size, setRight.size, 1);
}
function uniqueDisplayItems(items, limit = 5) {
  const result = [];
  (Array.isArray(items) ? items : [])
    .map(displayText)
    .forEach((item) => {
      const text = sentenceText(item);
      if (!text) return;
      if (result.some(old => displaySimilarity(old, text) >= 0.88)) return;
      result.push(text);
    });
  return result.slice(0, limit);
}
function displayText(value) {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map(displayText).filter(Boolean).join("、");
  if (typeof value === "object") {
    return Object.entries(value)
      .filter(([, v]) => v !== undefined && v !== null && v !== "")
      .map(([k, v]) => `${fieldLabel(k)}：${displayText(v)}`)
      .join("；");
  }
  return cleanGeneratedText(value);
}
function evidenceDirectionText(value) {
  return {
    supports_malicious: "支撑恶意判断",
    supports_benign: "支撑良性判断",
    insufficient: "证据不足",
    context: "背景信息",
  }[value] || displayText(value || "背景信息");
}
function evidenceTypeText(value) {
  return evidenceTypeLabels[value] || displayText(value || "证据");
}
function logicalEvidenceLine(item) {
  const type = evidenceTypeText(item.evidence_type);
  const desc = sentenceText(item.description || "");
  const direction = evidenceDirectionText(item.direction || "context");
  const strength = score(item.strength);
  const fields = (item.source_fields || []).length ? `来源字段：${displayText((item.source_fields || []).join("、"))}` : "";
  const strengthLabel = item.evidence_type === "xgboost_domain_probability" ? "模型概率" : "证据强度";
  return `<li><strong>${esc(type)}</strong>：${esc(desc)}<br><small>${esc(direction)}；${strengthLabel} ${strength}${fields ? `；${esc(fields)}` : ""}</small></li>`;
}

function isMachineLearningEvidence(item) {
  const fields = Array.isArray(item?.source_fields) ? item.source_fields.map(String) : [];
  const type = String(item?.evidence_type || "");
  return type === "xgboost_domain_probability" || type === "xgb_agent_scores" || fields.includes("xgb_agent_scores");
}
function agentExplanationMap(report) {
  const rows = report?.evidence_layers?.llm_explanation?.agent_explanations || [];
  return Object.fromEntries(rows.map(item => [item.agent, item]));
}
function renderAgentExplanation(item, block = {}) {
  if (!item) return "";
  const chainItems = (item.evidence_chain || []).map(displayText).filter(Boolean);
  const featureLinkItems = (item.feature_links || []).map(displayText).filter(Boolean);
  const contradictionItems = (item.contradictions || []).map(displayText).filter(Boolean);
  const reviewVerdict = item.review_verdict ? `独立复核结论为${displayText(item.review_verdict)}` : "";
  const reviewReason = item.review_reason ? `${reviewVerdict ? `${reviewVerdict}，` : ""}${displayText(item.review_reason)}` : "";
  const trustMap = {
    raw_features: "只基于该智能体收到的原始特征字段",
    insufficient: "该领域原始字段不足，结论需要保留不确定性",
  };
  const trust = item.trust_assessment ? (trustMap[item.trust_assessment] || displayText(item.trust_assessment)) : "";
  const scoreConflict = scoreReviewConflictText(block, item);
  const hasConflict = item.rule_alignment && item.rule_alignment !== "一致";
  const conflictItems = [
    ...contradictionItems,
    item.missing_impact ? `缺失字段影响：${displayText(item.missing_impact)}` : "",
    scoreConflict,
    item.rule_difference,
    item.conflict_resolution,
  ].map(displayText).filter(Boolean);
  const conclusion = [
    reviewReason,
    item.summary ? `综合摘要：${displayText(item.summary)}` : "",
    trust ? `复核方式：${trust}` : "",
  ].map(sentenceText).filter(Boolean);
  const reasoning = [
    item.causal_reasoning ? `逻辑推导：${displayText(item.causal_reasoning)}` : "",
    ...chainItems.slice(0, 3).map((value) => `关键证据：${sentenceText(value)}`),
    ...featureLinkItems.slice(0, 2).map((value) => `特征关系：${sentenceText(value)}`),
  ].map(sentenceText).filter(Boolean);
  const gaps = [
    ...(hasConflict || conflictItems.length ? conflictItems.slice(0, 3).map(sentenceText) : []),
  ].map(sentenceText).filter(Boolean);
  const section = (title, rows) => {
    const cleanRows = rows.map(sentenceText).filter(Boolean);
    if (!cleanRows.length) return "";
    const items = cleanRows.map((row) => `<li>${esc(endSentence(row))}</li>`).join("");
    return `<section class="agent-explain-section">
      <b>${esc(title)}</b>
      <ul class="agent-explain-items">${items}</ul>
    </section>`;
  };
  const body = [
    section("结论", conclusion),
    section("主要依据", reasoning),
    section("不确定点", gaps),
  ].filter(Boolean).join("");
  const summary = body || `<p>智能体未返回可展示的独立判断内容。</p>`;
  return `<div class="llm-explanation model-explanation">
    <strong>智能体判断</strong>
    ${summary}
  </div>`;
}

function fallbackAgentExplanation(block, llmLayer = {}) {
  const items = (block.evidence_items || []).filter(item => !isMachineLearningEvidence(item)).slice(0, 4);
  const claim = displayText(block.claim || "");
  const chain = items.map((item) => {
    const type = evidenceTypeText(item.evidence_type);
    const desc = sentenceText(item.description || "");
    const direction = evidenceDirectionText(item.direction || "context");
    const strength = `证据强度 ${score(item.strength)}`;
    return `<li>${esc(joinSentenceParts([`${type}：${desc}`, `${direction}，${strength}`]))}。</li>`;
  }).join("");
  const missing = (block.missing_fields || []).length
    ? `<p><b>缺失字段影响：</b>${esc(sentenceText(displayText((block.missing_fields || []).join("、"))))} 缺失，会降低该领域判断的完整性。</p>`
    : "";
  const modelStatus = llmLayer.status === "model_failed"
    ? `智能体判断未生成：${displayText(llmLayer.message || "模型返回不满足结构化要求")}`
    : llmLayer.status === "model_unavailable"
      ? "智能体判断未生成：当前未配置或未连通可用模型。"
      : "智能体判断未生成：本报告没有保存该智能体的模型复核结果。";
  return `<div class="llm-explanation fallback-explanation">
    <strong>智能体判断</strong>
    <p class="muted">${esc(modelStatus)}</p>
    <hr>
    <strong>规则判断</strong>
    ${claim ? `<p>${esc(claim)}</p>` : ""}
    ${chain ? `<p><b>证据链推导</b></p><ol>${chain}</ol>` : ""}
    ${missing}
  </div>`;
}
function modelSummaryText(x, k) {
  const label = names[x.verdict] || verdictByScore(x.score);
  const risk = names[x.risk_level] || riskLevelText(x.score);
  const role = k === "model_a" ? "模型甲按保守复核视角检查误报、缺失字段和证据交叉印证" : "模型乙按风险优先视角检查威胁链、仿冒、情报命中和漏报风险";
  const args = Array.isArray(x.arguments) ? x.arguments.map(displayText).filter(Boolean).slice(0, 4) : [];
  return `${role}。本轮结论为${label}，风险等级为${risk}，恶意倾向分为 ${score(x.score)}。${args.length ? `核心依据：${args.join("；")}。` : ""}`;
}
function modelReasoningParagraph(x, k) {
  const label = names[x.verdict] || verdictByScore(x.score);
  const risk = names[x.risk_level] || riskLevelText(x.score);
  const args = Array.isArray(x.arguments) ? x.arguments.map(displayText).filter(Boolean) : [];
  const chain = Array.isArray(x.evidence_chain) ? x.evidence_chain.map(displayText).filter(Boolean) : [];
  const relations = Array.isArray(x.feature_relations) ? x.feature_relations.map(displayText).filter(Boolean) : [];
  const contradictions = Array.isArray(x.contradictions) ? x.contradictions.map(displayText).filter(Boolean) : [];
  const refs = Array.isArray(x.evidence_refs) ? x.evidence_refs.map(modelDisplayName).filter(Boolean) : [];
  const pieces = [
    `${names[k]}最终倾向为${label}，风险等级为${risk}，恶意倾向分为${score(x.score)}，模型置信度为${confidenceText(x.confidence)}`,
  ];
  if (args.length) pieces.push(`主要依据是${args.slice(0, 3).map(sentenceText).join("；")}`);
  if (chain.length) pieces.push(`证据链推导为${chain.slice(0, 2).map(sentenceText).join("；")}`);
  if (relations.length) pieces.push(`关键特征关系为${relations.slice(0, 2).map(sentenceText).join("；")}`);
  if (contradictions.length) pieces.push(`仍需注意${contradictions.slice(0, 2).map(sentenceText).join("；")}`);
  if (refs.length) pieces.push(`引用证据块包括${refs.slice(0, 4).join("、")}`);
  return endSentence(displayText(pieces.join("。")));
}
function invalidInitialText(text) {
  const value = displayText(text || "");
  if (!value || value.length < 8) return true;
  if (/[?？]/.test(value)) return true;
  return /(模型甲|模型乙|对方|质疑|反驳|我方|请解释|请说明|请核验|请判断|是否|仅依据当前输入|EvidenceBlock 独立形成初判|独立形成初判|该阶段仅依据输入证据块|输入证据块形成独立陈述|输入证据块 -> 特征组合复核|rule_|rule judge|rule_judge|llm_|llm ru|ML概率|LLM可疑冲突|评分复核|复核分支|模型原始结论|已按校准阈值)/i.test(value);
}
function cleanInitialItems(items) {
  return uniqueDisplayItems(items, 6)
    .filter(item => item && !invalidInitialText(item));
}
function initialFallbackSentence(x, k) {
  const label = names[x.verdict] || verdictByScore(x.score);
  const risk = names[x.risk_level] || riskLevelText(x.score);
  const refs = Array.isArray(x.evidence_refs) ? x.evidence_refs.map(modelDisplayName).filter(Boolean).slice(0, 4) : [];
  const refText = refs.length ? refs.join("、") : "四智能体证据块";
  if (label === "恶意") {
    return `恶意判断依据：${refText}中存在互相支撑的风险信号，综合证据强度后倾向${label}，风险等级为${risk}，恶意倾向分为 ${score(x.score)}。`;
  }
  if (label === "良性") {
    return `良性判断依据：${refText}未形成足够完整的恶意证据链，关键高危字段或交叉印证不足，风险等级为${risk}，恶意倾向分为 ${score(x.score)}。`;
  }
  return `可疑判断依据：${refText}同时存在风险信号和证据缺口，当前只能支撑${label}结论，风险等级为${risk}，恶意倾向分为 ${score(x.score)}。`;
}
function modelInitialCard(x, k) {
  const label = names[x.verdict] || verdictByScore(x.score);
  const risk = names[x.risk_level] || riskLevelText(x.score);
  const args = cleanInitialItems(x.arguments).slice(0, 5);
  const chain = cleanInitialItems(x.evidence_chain).slice(0, 5);
  const relations = cleanInitialItems(x.feature_relations).slice(0, 4);
  const contradictions = cleanInitialItems(x.contradictions).slice(0, 4);
  const refs = Array.isArray(x.evidence_refs) ? x.evidence_refs.map(modelDisplayName).filter(Boolean).slice(0, 4) : [];
  const list = (items, empty) => items.length ? items.map(item => `<li>${esc(item)}</li>`).join("") : `<li class="muted">${empty}</li>`;
  const displayArgs = args.length ? args : [initialFallbackSentence(x, k)];
  const displayChain = chain.length ? chain : [`${refs.length ? refs.join("、") : "四智能体证据"} -> 提取静态、情报、仿冒和业务侧特征 -> 判断风险方向 -> 输出${label}结论。`];
  const displayRelations = relations.length ? relations : [`${refs.length ? refs.join("、") : "四智能体证据"}之间形成交叉支撑或相互约束，用于解释为什么当前结论为${label}。`];
  return `<article class="debate-card model-initial">
    <div class="panel-head"><strong>${names[k]}</strong><span>${esc(label)} · ${esc(risk)} · 恶意倾向 ${score(x.score)}</span></div>
    <div class="model-sections">
      <section><b>初判依据</b><ul>${list(displayArgs, "模型未返回可解析的初判依据。")}</ul></section>
      <section><b>引用证据块</b><p>${refs.length ? esc(refs.join("、")) : "<span class=\"muted\">模型未声明引用证据块。</span>"}</p></section>
      <section><b>证据链推导</b><ol>${list(displayChain, "模型未返回可解析的证据链。")}</ol></section>
      <section><b>特征关系</b><ul>${list(displayRelations, "模型未返回可解析的特征关系。")}</ul></section>
      <section><b>矛盾点与缺口</b><ul>${list(contradictions, "模型未指出明确矛盾点。")}</ul></section>
    </div>
  </article>`;
}
function renderModelSettings(settings) {
  state.modelSettings = settings;
  $("#localQwenToggle").checked = Boolean(settings.local_qwen_enabled);
  $("#serverModelsEnabled").checked = Boolean(settings.server_models_enabled);
  $("#modelAApiUrl").value = settings.model_a_api_url || "";
  $("#modelAModel").value = settings.model_a_model || "";
  $("#modelAApiKey").value = settings.model_a_api_key || "";
  $("#modelBApiUrl").value = settings.model_b_api_url || "";
  $("#modelBModel").value = settings.model_b_model || "";
  $("#modelBApiKey").value = settings.model_b_api_key || "";
  const stateEl = $("#modelState");
  stateEl.className = `model-state ${settings.ready ? "" : "warning"}`;
  stateEl.innerHTML = settings.mode === "server_models"
    ? "<b>服务器双模型已启用</b>"
    : settings.mode === "local_qwen"
      ? "<b>本地 Qwen 已启用</b>"
      : settings.mode === "model_required"
        ? "<b>需要启用模型</b>"
        : "<b>模型不可用，研判会停止</b>";
  stateEl.title = settings.message || "";
}
function setServerModelSettingsVisible(visible) {
  $("#serverModelSettings").hidden = !visible;
}
async function saveServerModelSettings() {
  const button = $("#saveServerModelSettingsBtn");
  const result = $("#serverModelSettingsResult");
  button.disabled = true;
  result.textContent = "正在保存并检测模型甲、模型乙接口...";
  try {
    const settings = await api("/api/model/settings", {
      method: "POST",
      body: JSON.stringify({
        server_models_enabled: $("#serverModelsEnabled").checked,
        model_a_api_url: $("#modelAApiUrl").value.trim(),
        model_a_model: $("#modelAModel").value.trim(),
        model_a_api_key: $("#modelAApiKey").value,
        model_b_api_url: $("#modelBApiUrl").value.trim(),
        model_b_model: $("#modelBModel").value.trim(),
        model_b_api_key: $("#modelBApiKey").value,
      }),
    });
    renderModelSettings(settings);
    const a = settings.server_models?.model_a?.message || "未检测";
    const b = settings.server_models?.model_b?.message || "未检测";
    result.textContent = `模型甲：${a}；模型乙：${b}。`;
    toast(settings.ready ? "服务器双模型已连接" : "配置已保存，但模型接口暂不可用", !settings.ready);
  } catch (e) {
    result.textContent = `保存失败：${e.message}`;
    toast(`服务器模型配置失败：${e.message}`, true);
  } finally {
    button.disabled = false;
  }
}
async function loadModelSettings() {
  renderModelSettings(await api("/api/model/settings"));
}
async function loadHermesStatus() {
  const status = await api("/api/hermes/status");
  state.hermesStatus = status;
  const el = $("#hermesState");
  const externalRuntime = status.mode === "external_runtime" || status.external_runtime_enabled;
  el.className = `model-state ${status.official_runtime_available || externalRuntime ? "" : "warning"}`;
  el.innerHTML = externalRuntime
    ? "<b>外部 Hermes Runtime</b>"
    : status.official_runtime_available
    ? "<b>Hermes 官方运行时</b>"
    : "<b>Hermes MCP 兼容模式</b>";
  el.title = status.message || "";
}
async function toggleLocalQwen() {
  const toggle = $("#localQwenToggle");
  toggle.disabled = true;
  try {
    const settings = await api("/api/model/settings", {
      method: "POST",
      body: JSON.stringify({ local_qwen_enabled: toggle.checked }),
    });
    renderModelSettings(settings);
    toast(settings.message, settings.local_qwen_enabled && !settings.ready);
  } catch (e) {
    toggle.checked = !toggle.checked;
    toast(`模型设置失败：${e.message}`, true);
  } finally {
    toggle.disabled = false;
  }
}
function switchView(id) {
  $$(".view").forEach(v => v.classList.toggle("active", v.id === id));
  $$(".nav-item").forEach(v => v.classList.toggle("active", v.dataset.view === id));
  $("#pageTitle").textContent = viewMeta[id][0]; $("#pageSubtitle").textContent = viewMeta[id][1];
  if (id === "validationView" && !state.validation) loadValidation();
  if (id === "fiveLayerView") {
    if (!state.fiveLayer) loadFiveLayer();
    else scheduleFiveLayerWorkflowPoll();
  } else if (state.fiveLayerWorkflowTimer) {
    clearTimeout(state.fiveLayerWorkflowTimer);
    state.fiveLayerWorkflowTimer = null;
  }
  if (id === "learningView") {
    loadHumanReviewReports();
    renderLearningCurrentReport();
  }
}

function sumDatasetCounts(value) {
  if (!value || typeof value !== "object") return 0;
  return Object.values(value).reduce((total, item) => {
    if (typeof item === "number") return total + item;
    return total + sumDatasetCounts(item);
  }, 0);
}

function fiveLayerStatusText(value) {
  return { ready: "就绪", partial: "部分就绪", blocked: "阻塞" }[value] || "未生成";
}

function fiveLayerStatusClass(value) {
  return value === "ready" ? "completed" : value === "blocked" ? "failed" : "pending";
}

function fiveLayerResultPct(value) {
  return value === null || value === undefined ? "--" : `${(Number(value) * 100).toFixed(2)}%`;
}

function fiveLayerResultMs(value) {
  return value === null || value === undefined ? "--" : `${(Number(value) / 1000).toFixed(2)} 秒`;
}

function fiveLayerResultNumber(value, digits = 2) {
  return value === null || value === undefined ? "--" : Number(value).toFixed(digits);
}

function fiveLayerJobStatusText(value) {
  return {
    queued: "排队中",
    running: "运行中",
    cancelling: "正在取消",
    completed: "已完成",
    failed: "失败",
    cancelled: "已取消",
  }[value] || "尚未运行";
}

function fiveLayerJobStatusClass(value) {
  return value === "completed" ? "completed" : value === "failed" ? "failed" : "pending";
}

function fiveLayerDatasetLabel(value) {
  return {
    model_release_holdout: "严格未见发布集",
    expert_gold_holdout: "专家金标集",
    model_diagnostic_eval: "历史诊断集",
    model_schema_challenges: "结构挑战集",
    rag_retrieval_eval: "RAG检索集",
    rag_corpus_inventory: "RAG语料清单",
    evidence_faithfulness_eval: "证据忠实度集",
    agent_trace_eval: "Agent轨迹集",
    agent_fault_eval: "故障注入集",
    agent_ablation_eval: "Agent消融集",
    end_to_end_release_holdout: "端到端发布集",
    end_to_end_diagnostic_all: "端到端诊断集",
    end_to_end_challenge_eval: "端到端挑战集",
    production_replay_eval: "生产回放集",
    production_reliability_eval: "生产可靠性集",
    drift_reference: "漂移参考集",
  }[value] || value;
}

function fiveLayerMetricLabel(value) {
  return {
    coverage: "覆盖率",
    trace_coverage: "轨迹覆盖率",
    malicious_recall: "恶意召回率",
    benign_false_positive_rate: "良性误报率",
    json_schema_success_rate: "JSON结构成功率",
    calibration_ece: "校准误差 ECE",
    approved_queries: "已批准检索标注",
    recall_at_5: "Recall@5",
    evidence_faithfulness_rate: "证据忠实度",
    hallucination_rate: "幻觉率",
    graph_nodes: "图谱节点数",
    agent_schema_success_rate: "Agent结构成功率",
    agent_failure_rate: "Agent失败率",
    agent_timeout_rate: "Agent超时率",
    restart_recovery_rate: "断点恢复率",
    required_ablation_variants: "必需消融变体",
    decided_accuracy: "已决样本准确率",
    structure_success_rate: "结构成功率",
    latency_p95_ms: "P95延迟",
    success_rate: "成功率",
    failure_rate: "失败率",
    model_unavailable_rate: "模型不可用率",
    agent_degraded_rate: "Agent降级率",
    required_fault_scenarios: "必需故障场景",
    drift_psi_block: "漂移PSI阻断阈值",
    human_reviews: "人工复核数",
    required_reliability_scenarios: "必需可靠性场景",
  }[value] || value;
}

function fiveLayerGateLines(gates) {
  return Object.entries(gates || {}).map(([key, value]) => {
    let metric = key;
    let operator = "=";
    if (key.endsWith("_min")) {
      metric = key.slice(0, -4);
      operator = "≥";
    } else if (key.endsWith("_max")) {
      metric = key.slice(0, -4);
      operator = "≤";
    }
    const countMetric = ["approved_queries", "graph_nodes", "required_ablation_variants", "required_fault_scenarios", "human_reviews", "required_reliability_scenarios"].includes(metric);
    const display = metric === "latency_p95_ms"
      ? `${num(value)} 毫秒`
      : countMetric || Number(value) > 1
        ? num(value)
        : fiveLayerResultPct(value);
    return `${fiveLayerMetricLabel(metric)} ${operator} ${display}`;
  });
}

function fiveLayerResultTiles(key, result) {
  const m = result?.metrics || {};
  const total = result?.sample_total || 0;
  if (key === "layer1_model") {
    const goldTotal = Number(m.frozen_gold_release_count || 0);
    const strictTotal = Number(m.strict_reference_total || total || 0);
    const strictChannels = m.strict_reference_channels || {};
    const channels = m.gold_compare_channels || {};
    const strictChannelRows = [
      ["全量最终融合", strictChannels.pipeline_final],
      ["全量模型甲", strictChannels.model_a],
      ["全量模型乙", strictChannels.model_b],
      ["全量XGBoost", strictChannels.xgboost],
    ].flatMap(([label, value]) => value ? [
      [`${label}输出`, `${num(value.available_outputs || 0)} / ${num(strictTotal)}`],
      [`${label}准确率 / 恶意召回`, `${fiveLayerResultPct(value.decided_accuracy)} / ${fiveLayerResultPct(value.malicious_recall)}`],
    ] : []);
    const channelRows = [
      ["金标最终融合", channels.pipeline_final],
      ["金标模型甲单方", channels.model_a],
      ["金标模型乙单方", channels.model_b],
      ["金标XGBoost", channels.xgboost],
    ].flatMap(([label, value]) => value ? [
      [`${label}输出`, `${num(value.available_outputs || 0)} / ${num(goldTotal)}`],
      [`${label}准确率 / 恶意召回`, `${fiveLayerResultPct(value.decided_accuracy)} / ${fiveLayerResultPct(value.malicious_recall)}`],
    ] : []);
    const rows = [
      ["冻结专家金标", num(m.frozen_gold_release_count || 0)],
      ["原始金标 / 双审晋级", `${num(m.base_frozen_gold_count || 0)} / ${num(m.approved_expansion_gold_count || 0)}`],
      ["严格来源扩展", num(m.strict_extension_count || 0)],
      ["扩展待双专家复核", num(m.strict_extension_review_pending || 0)],
      ["历史匹配输出 甲 / 乙", `${num(m.historical_model_a_outputs || 0)} / ${num(m.historical_model_b_outputs || 0)}`],
      ["严格集全量评测任务", `${fiveLayerJobStatusText(m.model_release_status || "not_run")}；完成 ${num(m.model_release_completed || 0)} / ${num(strictTotal)}，失败 ${num(m.model_release_failed || 0)}`],
      ["专家金标集任务", `${fiveLayerJobStatusText(m.gold_compare_status || "not_run")}；累计 ${num(m.gold_compare_completed || 0)} / ${num(goldTotal)}`],
      ["来源参考一致率 甲 / 乙", `${fiveLayerResultPct(m.provisional_model_a_agreement)} / ${fiveLayerResultPct(m.provisional_model_b_agreement)}`],
      ...strictChannelRows,
      ...channelRows,
    ];
    if (m.model_release_failure_reason) rows.push(["正式盲测失败原因", String(m.model_release_failure_reason).slice(0, 200)]);
    return rows;
  }
  if (key === "layer2_rag") {
    const rows = [
      ["检索测试样本", num(total)],
      ["历史RAG报告", num(m.rag_enabled_reports || 0)],
      ["非空检索率", fiveLayerResultPct(m.nonempty_retrieval_rate)],
      ["平均召回文档", fiveLayerResultNumber(m.average_retrieved_documents)],
      ["专家批准 / 总数", `${num(m.approved_queries || 0)} / ${num(total)}`],
      ["专家 Recall@5", fiveLayerResultPct(m.recall_at_5)],
      ["专家 MRR / nDCG@10", `${fiveLayerResultNumber(m.mrr)} / ${fiveLayerResultNumber(m.ndcg_at_10)}`],
      ["专家证据忠实度", fiveLayerResultPct(m.evidence_faithfulness_rate)],
      ["专家幻觉率", fiveLayerResultPct(m.hallucination_rate)],
      ["银标预标样本", num(m.silver_prelabel_rows || 0)],
      ["银标 Recall@5", fiveLayerResultPct(m.silver_recall_at_5)],
      ["银标 MRR / nDCG@10", `${fiveLayerResultNumber(m.silver_mrr)} / ${fiveLayerResultNumber(m.silver_ndcg_at_10)}`],
      ["RAG三变体", `${num(m.rag_variants_completed || 0)} / 3 完成；失败 ${num(m.rag_variants_failed || 0)}`],
    ];
    if (m.rag_experiment_failure_reason) rows.push(["实验失败原因", String(m.rag_experiment_failure_reason).slice(0, 160)]);
    return rows;
  }
  if (key === "layer3_agent") {
    const rows = [
      ["轨迹测试样本", num(total)],
      ["已有保存输出", num(m.reports_with_saved_output || 0)],
      ["轨迹覆盖率", fiveLayerResultPct(m.trace_coverage)],
      ["结构成功率", fiveLayerResultPct(m.agent_schema_success_rate)],
      ["Agent失败率", fiveLayerResultPct(m.agent_failure_rate)],
      ["超时率", fiveLayerResultPct(m.agent_timeout_rate)],
      ["五变体消融", `${num(m.ablation_variants_completed || 0)} / 5 完成；失败 ${num(m.ablation_variants_failed || 0)}`],
      ["断点恢复", `${num(m.restart_recovered || 0)} / ${num(m.restart_attempts || 0)}`],
      ["恢复率", fiveLayerResultPct(m.restart_recovery_rate)],
      ["幂等重放跳过", num(m.idempotent_replay_skipped || 0)],
    ];
    if (m.ablation_failure_reason) rows.push(["消融失败原因", String(m.ablation_failure_reason).slice(0, 160)]);
    if (m.recovery_failure_reason) rows.push(["恢复失败原因", String(m.recovery_failure_reason).slice(0, 160)]);
    return rows;
  }
  if (key === "layer4_e2e") {
    return [
      ["已完成 / 总数", `${num(m.evaluated_total || 0)} / ${num(total)}`],
      ["待研判", num(m.pending_total || 0)],
      ["覆盖率", fiveLayerResultPct(m.coverage)],
      ["准确率", fiveLayerResultPct(m.decided_accuracy)],
      ["恶意召回率", fiveLayerResultPct(m.malicious_recall)],
      ["良性误报率", fiveLayerResultPct(m.benign_false_positive_rate)],
      ["Macro-F1", fiveLayerResultPct(m.macro_f1)],
      ["P50 / P95", `${fiveLayerResultMs(m.latency_p50_ms)} / ${fiveLayerResultMs(m.latency_p95_ms)}`],
    ];
  }
  const jobs = m.batch_job_status || {};
  return [
    ["生产回放", num(total)],
    ["累计报告", num(m.saved_reports || 0)],
    ["验证覆盖率", fiveLayerResultPct(m.validation_coverage)],
    ["模型不可用率", fiveLayerResultPct(m.model_unavailable_rate)],
    ["Agent降级率", fiveLayerResultPct(m.agent_degraded_rate)],
    ["人工推翻率", fiveLayerResultPct(m.human_override_rate)],
    ["P50 / P95", `${fiveLayerResultMs(m.latency_p50_ms)} / ${fiveLayerResultMs(m.latency_p95_ms)}`],
    ["批任务状态", Object.entries(jobs).map(([name, value]) => `${name}:${value}`).join("，") || "--"],
  ];
}

function fiveLayerExperimentHtml(key, experiments) {
  const experiment = key === "layer1_model"
    ? experiments?.model_release
    : key === "layer2_rag"
      ? experiments?.rag_compare
      : key === "layer3_agent"
        ? experiments?.agent_ablation
        : null;
  if (!experiment) return "";
  const variants = experiment.variants || [];
  if (key === "layer1_model") {
    const gold = experiments?.gold_compare || {};
    const strictTotal = Number(experiment.reference_total || 0);
    const strictStatus = experiment.status || "not_run";
    const strictFailed = variants.reduce((sum, item) => sum + Number(item.failed_samples || 0), 0);
    const fallbackLatency = variants[0]?.metrics?.latency_p95_ms;
    const strictRows = Object.entries({
      pipeline_final: "最终融合",
      model_a: "模型甲",
      model_b: "模型乙",
      xgboost: "XGBoost",
    }).map(([channel, label]) => {
      const m = (experiment.reference_channels || {})[channel] || {};
      return `<tr>
        <td>严格训练未见集（全量参考口径 ${num(strictTotal)} 条）</td>
        <td>${label}</td>
        <td><span class="badge ${fiveLayerJobStatusClass(strictStatus)}">${esc(fiveLayerJobStatusText(strictStatus))}</span></td>
        <td>${num(m.available_outputs || 0)} / ${num(strictTotal)}</td>
        <td>${num(strictFailed)}</td>
        <td>${fiveLayerResultPct(m.decided_accuracy)}</td>
        <td>${fiveLayerResultPct(m.malicious_recall)}</td>
        <td>${fiveLayerResultPct(m.benign_false_positive_rate)}</td>
        <td>${fiveLayerResultPct(m.review_rate)}</td>
        <td>${fiveLayerResultMs(m.latency_p95_ms ?? fallbackLatency)}</td>
      </tr>`;
    }).join("");
    const goldStatus = gold.status || "not_run";
    const goldRows = Object.entries({
      pipeline_final: "最终融合",
      model_a: "模型甲",
      model_b: "模型乙",
      xgboost: "XGBoost",
    }).map(([channel, label]) => {
      const item = (gold.channels || {})[channel] || {};
      return `<tr>
        <td>专家金标集</td>
        <td>${label}</td>
        <td><span class="badge ${fiveLayerJobStatusClass(goldStatus)}">${esc(fiveLayerJobStatusText(goldStatus))}</span></td>
        <td>${num(item.available_outputs || 0)}</td>
        <td>${num(gold.failed_variants || 0)}</td>
        <td>${fiveLayerResultPct(item.decided_accuracy)}</td>
        <td>${fiveLayerResultPct(item.malicious_recall)}</td>
        <td>${fiveLayerResultPct(item.benign_false_positive_rate)}</td>
        <td>${fiveLayerResultPct(item.review_rate)}</td>
        <td>--</td>
      </tr>`;
    }).join("");
    return `<section class="five-layer-experiment">
      <h4>数据集运行明细</h4>
      <p class="five-layer-experiment-note">严格训练未见集全部 ${num(strictTotal)} 条均参与最终融合、模型甲、模型乙和XGBoost的准确率、恶意召回、良性误报与待复核率计算；95条专家金标子集同时保留，便于对照标签可信度。</p>
      <div class="table-wrap"><table style="min-width:1120px"><thead><tr><th>数据集</th><th>决策路径 / 变体</th><th>状态</th><th>输出 / 完成</th><th>失败</th><th>准确率</th><th>恶意召回</th><th>良性误报</th><th>待复核率</th><th>P95</th></tr></thead><tbody>${strictRows}${goldRows}</tbody></table></div>
    </section>`;
  }
  if (!variants.length) {
    return `<section class="five-layer-experiment"><h4>变体实验明细</h4><p>尚未运行；点击本层“开始执行”后，结果会按变体独立落盘并显示。</p></section>`;
  }
  const rows = variants.map(item => {
    const m = item.metrics || {};
    return `<tr>
      <td>${esc(item.name || item.variant || "--")}</td>
      <td><span class="badge ${fiveLayerJobStatusClass(item.status)}">${esc(fiveLayerJobStatusText(item.status))}</span></td>
      <td>${num(item.completed_samples || 0)}</td>
      <td>${num(item.failed_samples || 0)}</td>
      <td>${fiveLayerResultPct(m.decided_accuracy)}</td>
      <td>${fiveLayerResultPct(m.malicious_recall)}</td>
      <td>${fiveLayerResultMs(m.latency_p95_ms)}</td>
    </tr>`;
  }).join("");
  const recovery = key === "layer3_agent" ? experiments?.recovery || {} : null;
  const recoveryText = recovery
    ? `<p class="five-layer-experiment-note">故障恢复：${num(recovery.restart_recovered || 0)} / ${num(recovery.restart_attempts || 0)}；幂等重放跳过 ${num(recovery.idempotent_replay_skipped || 0)} 条；状态 ${esc(fiveLayerJobStatusText(recovery.status))}。</p>`
    : "";
  return `<section class="five-layer-experiment">
    <h4>变体实验明细</h4>
    <div class="table-wrap"><table><thead><tr><th>变体</th><th>状态</th><th>完成</th><th>失败</th><th>准确率</th><th>恶意召回</th><th>P95</th></tr></thead><tbody>${rows}</tbody></table></div>
    ${recoveryText}
  </section>`;
}

function fiveLayerActionHtml(key, action, catalog, latestJob, activeJob) {
  const definition = catalog?.[action] || {};
  const isActive = activeJob && activeJob.job_id === latestJob?.job_id;
  const cumulative = definition.progress || {};
  const sampleTotal = Math.max(0, Number(definition.sample_total || cumulative.dataset_total || 0));
  const completedBase = Math.max(0, Number(cumulative.completed_base_samples || 0));
  const remainingBase = Math.max(0, Number(cumulative.remaining_base_samples ?? (sampleTotal - completedBase)));
  const variantCount = Math.max(1, Number(definition.variant_count || 1));
  const defaultBatch = Math.max(1, Number(definition.default_batch_size || 10));
  const configuredBatch = Number(state.fiveLayerBatchSizes[action] || defaultBatch);
  const savedBatch = Number.isFinite(configuredBatch) ? Math.max(1, Math.floor(configuredBatch)) : defaultBatch;
  const batchSize = remainingBase ? Math.min(remainingBase, savedBatch) : 0;
  state.fiveLayerBatchSizes[action] = batchSize;
  const startsDisabled = activeJob || !remainingBase ? "disabled" : "";
  const progressTotal = Number(latestJob?.command_total || 0);
  const progressDone = Number(latestJob?.command_completed || 0);
  const progressPct = progressTotal ? Math.min(100, progressDone / progressTotal * 100) : 0;
  const cumulativePct = sampleTotal ? Math.min(100, completedBase / sampleTotal * 100) : 0;
  const latestResults = Array.isArray(latestJob?.results) ? latestJob.results : [];
  const liveBatch = latestJob?.batch_progress || {};
  const batchCompleted = Number(liveBatch.completed_executions ?? latestResults.reduce((sum, item) => sum + Number(item.completed || 0), 0));
  const batchFailed = Number(liveBatch.failed_executions ?? latestResults.reduce((sum, item) => sum + Number(item.failed || 0), 0));
  const batchPlanned = Number(liveBatch.planned_executions || latestJob?.planned_executions || 0);
  const batchPct = Math.min(100, Math.max(0, Number(liveBatch.percent || 0) * 100));
  const presetValues = [...new Set((definition.batch_presets || [1, 10, 20, 50, 100])
    .map(value => Math.floor(Number(value)))
    .filter(value => value > 0 && value < remainingBase))];
  const presetHtml = presetValues.map(value =>
    `<button type="button" data-five-batch-preset="${esc(action)}" data-five-batch-value="${value}" ${activeJob ? "disabled" : ""}>${num(value)}</button>`
  ).join("");
  const secondary = key === "layer1_model" && action === "gold_compare"
    ? `<button data-five-manual="gold-review">进入金标扩充</button>`
    : key === "layer2_rag"
    ? `<button data-five-manual="rag-review">进入RAG专家标注</button>`
    : key === "layer5_production"
      ? `<button data-five-manual="human-review">进入人工复核闭环</button>`
      : "";
  const jobHtml = latestJob ? `<div class="five-layer-job">
    <div class="five-layer-job-head">
      <span class="badge ${fiveLayerJobStatusClass(latestJob.status)}">${esc(fiveLayerJobStatusText(latestJob.status))}</span>
      <span>${num(progressDone)} / ${num(progressTotal)} 个子实验</span>
    </div>
    <div class="progress-track"><span style="width:${Math.max(progressPct, batchPct).toFixed(1)}%"></span></div>
    <small>本次选择 ${num(latestJob.batch_size || batchSize)} 条；样本流程 ${num(batchCompleted + batchFailed)} / ${num(batchPlanned)}，成功 ${num(batchCompleted)}，失败 ${num(batchFailed)}。${esc(latestJob.current_command || latestJob.error || `任务 ${latestJob.job_id}`)}</small>
  </div>` : `<small>尚未运行本层自动实验。</small>`;
  return `<div class="five-layer-next">
    <div>
      <strong>${esc(definition.name || "运行本层下一步")}</strong>
      <p>${esc(definition.description || "")}</p>
      <small>可用数据集共 ${num(sampleTotal)} 条，但不会强制一次跑完；每个基础样本运行 ${num(variantCount)} 个变体。系统会先排除检查点中已完成样本，再按您设置的数量选取下一批。</small>
    </div>
    <div class="five-layer-batch-controls">
      <label>本次运行样本数（可自定义）
        <input type="number" min="1" max="${Math.max(1, remainingBase)}" step="1" value="${batchSize}" data-five-batch-size="${esc(action)}" ${(activeJob || !remainingBase) ? "disabled" : ""}>
        <small>允许范围：${remainingBase ? `1～${num(remainingBase)}` : "已无剩余样本"}</small>
      </label>
      <div class="five-layer-batch-summary">
        <span>累计完成 <strong>${num(completedBase)} / ${num(sampleTotal)}</strong></span>
        <span>剩余 <strong>${num(remainingBase)}</strong></span>
        <span>本次预计执行 <strong>${num(batchSize * variantCount)}</strong> 个样本流程</span>
      </div>
      <div class="five-layer-batch-presets">
        <span>快捷设置</span>${presetHtml || "<small>当前没有可运行样本</small>"}
        ${remainingBase ? `<button type="button" data-five-batch-preset="${esc(action)}" data-five-batch-value="${remainingBase}" ${activeJob ? "disabled" : ""}>全部剩余（${num(remainingBase)}）</button>` : ""}
      </div>
      <div class="progress-track"><span style="width:${cumulativePct.toFixed(1)}%"></span></div>
      <small>累计覆盖率 ${cumulativePct.toFixed(2)}%；部分批次仅表示“评测进行中”，完整集覆盖100%后才参与正式发布门禁。</small>
    </div>
    <div class="five-layer-next-actions">
      <button class="primary" data-five-workflow="${esc(action)}" ${startsDisabled}>${isActive ? "正在运行" : remainingBase ? "运行下一批" : "已全部完成"}</button>
      ${isActive ? `<button data-five-cancel="${esc(activeJob.job_id)}">取消任务</button>` : ""}
      ${secondary}
    </div>
    ${jobHtml}
  </div>`;
}

function renderFiveLayerCards(data) {
  const target = $("#fiveLayerCards");
  const summary = $("#fiveLayerTestSummary");
  if (!target || !summary) return;
  const results = data.test_results || {};
  const validation = results.suite_validation || {};
  summary.textContent = results.suite_id
    ? `套件 ${results.suite_id}：自动校验 ${num(validation.checks_passed || 0)} / ${num(validation.checks_total || 0)} 项通过，失败 ${num(validation.checks_failed || 0)} 项。测试结果中的“--”表示尚无有效人工分母或实验尚未运行。`
    : "尚未生成五层测试结果。";
  const order = [
    ["layer1_model", "model_release", "#256cb6"],
    ["layer2_rag", "rag_compare", "#7b3f98"],
    ["layer3_agent", "agent_ablation", "#16899a"],
    ["layer4_e2e", "complete_release", "#11875d"],
    ["layer5_production", "production_reliability", "#b36b00"],
  ];
  const workflows = state.fiveLayerWorkflows || {};
  target.innerHTML = order.map(([key, action, color], index) => {
    const definition = data.layers?.[key] || {};
    const result = results.layers?.[key] || {};
    const ready = data.readiness?.layers?.[key] || {};
    const layerCounts = data.latest_suite?.dataset_counts?.[key] || {};
    const latestJob = workflows.latest_by_action?.[action] || null;
    const datasetLines = Object.entries(layerCounts).map(([name, count]) =>
      `<li><span>${esc(fiveLayerDatasetLabel(name))}</span><strong>${num(count)} 条</strong></li>`
    ).join("");
    const gateLines = fiveLayerGateLines(data.release_gates?.[key]).map(line => `<li>${esc(line)}</li>`).join("");
    const tiles = fiveLayerResultTiles(key, result).map(([label, value]) =>
      `<div class="five-layer-result-tile"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`
    ).join("");
    return `<article class="five-layer-card" style="--layer-color:${color}" id="${key}">
      <header class="five-layer-card-head">
        <div class="five-layer-card-title">
          <span class="five-layer-index">${index + 1}</span>
          <div>
            <h3>${esc(definition.name || result.name || key)}</h3>
            <p>${esc(definition.decision || result.scope || "")}</p>
          </div>
        </div>
        <span class="badge ${fiveLayerStatusClass(ready.status)}">${esc(fiveLayerStatusText(ready.status))}</span>
      </header>
      <div class="five-layer-card-body">
        <section class="five-layer-section">
          <h4>测试数据与口径</h4>
          <p>${esc(result.scope || "等待生成本层测试集")}</p>
          <ul class="five-layer-data-list">${datasetLines || "<li>尚无数据</li>"}</ul>
          <small>${esc(result.note || "")}</small>
        </section>
        <section class="five-layer-section">
          <h4>发布门禁</h4>
          <ul class="five-layer-gates">${gateLines || "<li>尚无门禁定义</li>"}</ul>
        </section>
        <section class="five-layer-section five-layer-results">
          <h4>实际测试结果</h4>
          <div class="five-layer-result-grid">${tiles}</div>
        </section>
      </div>
      ${fiveLayerExperimentHtml(key, data.experiments || {})}
      <div class="five-layer-readiness">
        <strong>当前结论</strong>
        <span>${esc(ready.reason || "等待生成与运行评测")}</span>
      </div>
      ${key === "layer1_model" ? `<div class="five-layer-dataset-actions">
        ${fiveLayerActionHtml(
          key,
          "gold_compare",
          workflows.catalog,
          workflows.latest_by_action?.gold_compare || null,
          workflows.active_job,
        )}
        ${fiveLayerActionHtml(key, action, workflows.catalog, latestJob, workflows.active_job)}
      </div>` : fiveLayerActionHtml(key, action, workflows.catalog, latestJob, workflows.active_job)}
    </article>`;
  }).join("");

  const active = workflows.active_job;
  const activeBatch = active?.batch_progress || {};
  $("#fiveLayerWorkflowSummary").innerHTML = active
    ? `当前正在运行：<strong>${esc(active.name || active.action)}</strong>；本次选择 ${num(active.batch_size || 0)} 条，样本流程 ${num(activeBatch.finished_executions || 0)} / ${num(activeBatch.planned_executions || active.planned_executions || 0)}；子实验 ${num(active.command_completed || 0)} / ${num(active.command_total || 0)}；当前步骤：${esc(active.current_command || "正在启动")}。页面会每3秒自动刷新。`
    : `五层任务执行器空闲。每个评测区域都可以独立设置“本次运行样本数”，无需一次跑完整个数据集；多次运行会跳过已完成样本并继续累计检查点结果。`;
  bindFiveLayerActions();
}

function renderFiveLayerSuiteHistory(data) {
  const select = $("#fiveLayerSuiteSelect");
  if (!select) return;
  const history = Array.isArray(data.suite_history) ? data.suite_history : [];
  const selected = data.selected_suite_id || data.latest_suite?.suite_id || "";
  if (selected) {
    state.fiveLayerSuiteId = selected;
    localStorage.setItem("malappFiveLayerSuiteId", selected);
  }
  select.innerHTML = history.length ? history.map(item => {
    const created = item.created_at ? new Date(item.created_at).toLocaleString("zh-CN") : "时间未知";
    const resultText = item.has_results
      ? `累计输出 ${num(item.completed_executions || 0)}`
      : "尚无运行结果";
    return `<option value="${esc(item.suite_id)}" ${item.suite_id === selected ? "selected" : ""}>${esc(created)} · ${esc(item.suite_id)} · ${resultText}${item.is_latest ? " · 最新" : ""}</option>`;
  }).join("") : '<option value="">尚无已保存套件</option>';
  select.disabled = !history.length;
}

function renderFiveLayer(data) {
  state.fiveLayer = data;
  const suite = data.latest_suite || {};
  const readiness = data.readiness || {};
  const selection = suite.selection || {};
  const counts = suite.dataset_counts || {};
  const current = data.current_end_to_end?.metrics || {};
  const quality = suite.quality_gate || {};
  renderFiveLayerSuiteHistory(data);
  const metrics = [
    ["总体状态", fiveLayerStatusText(readiness.overall_status), "五层全部通过后才可发布", readiness.overall_status === "ready" ? "#11875d" : "#b36b00"],
    ["严格未见发布集", selection.release_holdout_count ?? "--", `正式金标 ${num(selection.frozen_gold_release_count || 0)}；来源扩展 ${num(selection.strict_source_reference_extension_count || 0)}（已晋级 ${num(selection.approved_expansion_gold_count || 0)}）`, "#256cb6"],
    ["历史回归集", selection.diagnostic_all_count ?? "--", `训练重叠 ${num(selection.training_overlap_count || 0)} 条`, "#7b3f98"],
    ["新鲜专家候选", selection.fresh_candidate_count ?? "--", "双人复核和仲裁后转为新测试集", "#16899a"],
    ["当前端到端覆盖", pct(current.coverage), `已研判 ${num(current.evaluated_total || 0)} / ${num(current.validation_total || 0)}`, "#11875d"],
  ];
  $("#fiveLayerMetrics").innerHTML = metrics.map(m => `<article class="metric" style="--metric-color:${m[3]}"><span>${esc(m[0])}</span><strong>${typeof m[1] === "number" ? num(m[1]) : esc(m[1])}</strong><small>${esc(m[2])}</small></article>`).join("");
  $("#fiveLayerPath").textContent = suite.suite_dir
    ? `当前套件：${suite.suite_id}；目录：${suite.suite_dir}；状态：${suite.status}。历史结果已持久化，可通过上方“评测套件 / 历史结果”切换查看。`
    : "尚未生成五层评测套件。点击“生成五层数据集”后，将只读现有数据并创建新的版本目录。";

  $("#fiveLayerQuality").textContent = suite.suite_dir
    ? `数据质量门禁：${quality.release_safe_without_exclusions ? "可直接使用" : "必须使用隔离后的发布集"}；高/严重问题 ${num(quality.high_or_critical_findings || 0)} 项。严格发布集不会包含历史训练重叠样本。`
    : "尚未生成数据质量清单。";
  renderFiveLayerCards(data);
}

async function loadFiveLayer() {
  try {
    const query = state.fiveLayerSuiteId
      ? `?suite_id=${encodeURIComponent(state.fiveLayerSuiteId)}`
      : "";
    const [overview, workflows] = await Promise.all([
      api(`/api/evaluation/five-layer${query}`),
      api(`/api/evaluation/five-layer/workflows${query}`),
    ]);
    state.fiveLayerWorkflows = workflows;
    renderFiveLayer(overview);
    scheduleFiveLayerWorkflowPoll();
  } catch (error) {
    $("#fiveLayerPath").textContent = `读取五层评测失败：${error.message}`;
    toast(`读取五层评测失败：${error.message}`, true);
  }
}

function scheduleFiveLayerWorkflowPoll() {
  if (state.fiveLayerWorkflowTimer) clearTimeout(state.fiveLayerWorkflowTimer);
  state.fiveLayerWorkflowTimer = null;
  if (!state.fiveLayerWorkflows?.active_job || !$("#fiveLayerView")?.classList.contains("active")) return;
  state.fiveLayerWorkflowTimer = setTimeout(loadFiveLayer, 3000);
}

function bindFiveLayerActions() {
  const saveBatchSize = (action, rawValue) => {
    const definition = state.fiveLayerWorkflows?.catalog?.[action] || {};
    const progress = definition.progress || {};
    const maximum = Math.max(0, Number(definition.max_batch_size ?? progress.remaining_base_samples ?? definition.sample_total ?? 0));
    if (!maximum) return 0;
    const parsed = Number(rawValue);
    const value = Math.max(1, Math.min(maximum, Number.isFinite(parsed) ? Math.floor(parsed) : 1));
    state.fiveLayerBatchSizes[action] = value;
    localStorage.setItem("malappFiveLayerBatchSizes", JSON.stringify(state.fiveLayerBatchSizes));
    return value;
  };
  $$('[data-five-batch-size]').forEach(input => {
    input.onchange = () => {
      const action = input.dataset.fiveBatchSize;
      const value = saveBatchSize(action, input.value);
      input.value = value;
      renderFiveLayerCards(state.fiveLayer || {});
    };
  });
  $$('[data-five-batch-preset]').forEach(button => {
    button.onclick = () => {
      saveBatchSize(button.dataset.fiveBatchPreset, button.dataset.fiveBatchValue);
      renderFiveLayerCards(state.fiveLayer || {});
    };
  });
  $$("[data-five-workflow]").forEach(button => {
    button.onclick = () => startFiveLayerWorkflow(button.dataset.fiveWorkflow);
  });
  $$("[data-five-cancel]").forEach(button => {
    button.onclick = () => cancelFiveLayerWorkflow(button.dataset.fiveCancel);
  });
  $$("[data-five-manual='rag-review']").forEach(button => {
    button.onclick = openFiveLayerRagReview;
  });
  $$("[data-five-manual='gold-review']").forEach(button => {
    button.onclick = openFiveLayerGoldReview;
  });
  $$("[data-five-manual='human-review']").forEach(button => {
    button.onclick = () => switchView("learningView");
  });
}

async function startFiveLayerWorkflow(action) {
  const definition = state.fiveLayerWorkflows?.catalog?.[action] || {};
  const progress = definition.progress || {};
  const sampleTotal = Math.max(0, Number(definition.sample_total || 0));
  const remaining = Math.max(0, Number(progress.remaining_base_samples ?? sampleTotal));
  if (!remaining) {
    toast("本层没有未完成样本，无需再次运行", true);
    return;
  }
  const requested = Math.max(1, Number(state.fiveLayerBatchSizes[action] || definition.default_batch_size || 10));
  const batchSize = Math.min(remaining, Math.floor(requested));
  const variantCount = Math.max(1, Number(definition.variant_count || 1));
  const accepted = window.confirm(
    `${definition.name || "运行五层评测"}\n\n${definition.description || ""}\n\n本次由您设置运行 ${num(batchSize)} 条基础样本，预计执行 ${num(batchSize * variantCount)} 个样本流程。已完成样本会自动跳过，结果继续累计到同一套件。任务将在后台运行并保存检查点。是否开始？`
  );
  if (!accepted) return;
  try {
    await api("/api/evaluation/five-layer/workflows/start", {
      method: "POST",
      body: JSON.stringify({
        action,
        batch_size: batchSize,
        suite_id: state.fiveLayerSuiteId,
      }),
    });
    toast("五层评测任务已在后台启动");
    await loadFiveLayer();
  } catch (error) {
    toast(`启动失败：${error.message}`, true);
  }
}

async function cancelFiveLayerWorkflow(jobId) {
  if (!window.confirm("取消会终止当前子实验，但已经落盘的检查点和结果会保留。确定取消？")) return;
  try {
    await api("/api/evaluation/five-layer/workflows/cancel", {
      method: "POST",
      body: JSON.stringify({ job_id: jobId }),
    });
    toast("五层评测任务已取消");
    await loadFiveLayer();
  } catch (error) {
    toast(`取消失败：${error.message}`, true);
  }
}

function goldExpansionStatusText(value) {
  return {
    pending_first_review: "待一审",
    pending_second_review: "待二审",
    needs_adjudication: "待仲裁",
    approved: "双审一致",
    adjudicated: "已仲裁",
    rejected: "已排除",
  }[value] || value || "--";
}

async function openFiveLayerGoldReview() {
  const panel = $("#fiveLayerGoldReview");
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
  $("#fiveLayerGoldReviewer").value = localStorage.getItem("malappFiveLayerGoldReviewer") || "";
  $("#fiveLayerGoldTarget").value = localStorage.getItem("malappFiveLayerGoldTarget") || "500";
  await loadFiveLayerGoldExpansion();
}

async function loadFiveLayerGoldExpansion() {
  const progress = $("#fiveLayerGoldProgress");
  progress.textContent = "正在加载金标扩充状态……";
  const reviewer = $("#fiveLayerGoldReviewer").value.trim();
  const role = $("#fiveLayerGoldRole").value;
  const target = Math.max(96, Number($("#fiveLayerGoldTarget").value || 500));
  try {
    const params = new URLSearchParams({
      target: String(target),
      reviewer,
      role,
      limit: "50",
    });
    const response = await api(`/api/evaluation/five-layer/gold-expansion?${params}`);
    state.fiveLayerGoldOverview = response;
    state.fiveLayerGoldItems = response.items || [];
    state.fiveLayerGoldIndex = 0;
    $("#fiveLayerGoldTarget").max = String(Math.max(96, Number(response.release_total || 1495)));
    renderFiveLayerGoldItem();
  } catch (error) {
    progress.textContent = `加载失败：${error.message}`;
    toast(`金标扩充加载失败：${error.message}`, true);
  }
}

function renderFiveLayerGoldItem() {
  const overview = state.fiveLayerGoldOverview || {};
  const counts = overview.status_counts || {};
  const items = state.fiveLayerGoldItems || [];
  const item = items[state.fiveLayerGoldIndex];
  const role = $("#fiveLayerGoldRole").value;
  $("#fiveLayerGoldProgress").textContent = overview.prepared
    ? `目标 ${num(overview.target_total)} 条；当前可冻结 ${num(overview.current_gold_count)} 条，尚缺 ${num(overview.remaining_to_target)} 条。候选严格执行双人独立盲审；分歧样本必须第三人仲裁。`
    : "尚未建立扩充批次。点击“生成/补齐分层候选”，系统会按恶意60%、良性40%的目标结构稳定抽样。";
  const metrics = [
    ["当前冻结金标", num(overview.current_gold_count || overview.base_gold_count || 0)],
    ["目标数量", num(overview.target_total || 500)],
    ["目标恶意 / 良性", `${num(overview.desired_labels?.malicious || 0)} / ${num(overview.desired_labels?.benign || 0)}`],
    ["当前恶意 / 良性", `${num(overview.current_labels?.malicious || 0)} / ${num(overview.current_labels?.benign || 0)}`],
    ["待一审 / 待二审", `${num(counts.pending_first_review || 0)} / ${num(counts.pending_second_review || 0)}`],
    ["待仲裁 / 已排除", `${num(counts.needs_adjudication || 0)} / ${num(counts.rejected || 0)}`],
  ];
  $("#fiveLayerGoldMetrics").innerHTML = metrics.map(([label, value]) =>
    `<div class="five-layer-result-tile"><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`
  ).join("");
  $("#freezeFiveLayerGoldBtn").disabled = !overview.ready_to_freeze;
  $("#saveFiveLayerGoldBtn").disabled = !item;
  $("#skipFiveLayerGoldBtn").disabled = !item;
  const disagreement = $("#fiveLayerGoldDisagreement");
  disagreement.hidden = true;
  disagreement.textContent = "";
  if (!item) {
    $("#fiveLayerGoldSample").innerHTML = `<h4>${role === "adjudicate" ? "当前没有待仲裁样本" : "当前复核人没有可领取样本"}</h4><p>${role === "adjudicate" ? "只有两位专家结论不一致时才进入这里。" : "若已完成一审，请更换为另一位专家账号进行盲审；同一复核人不能复核同一条两次。"}</p>`;
    return;
  }
  const input = item.input || {};
  const fields = [
    ["样本ID", item.id], ["当前阶段", goldExpansionStatusText(item.status)],
    ["应用名称", input.app_name], ["包名", input.package_name],
    ["MD5", input.md5 || item.id], ["签名状态", input.signature_status],
    ["证书主体", input.certificate_owner], ["病毒名称", input.virus_name],
    ["仿冒标记", input.fake_app], ["正版应用", input.official_app_name],
    ["360分数", input.engine_360_score], ["CM分数", input.engine_cm_score],
    ["控制端", input.control_url], ["下载地址", input.download_url],
    ["权限", input.permissions], ["风险描述", input.virus_description || input.description],
  ].filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== "");
  $("#fiveLayerGoldSample").innerHTML = `<h4>独立研判样本 ${num(state.fiveLayerGoldIndex + 1)} / ${num(items.length)}</h4><dl>${fields.map(([label, value]) => {
    const text = typeof value === "object" ? JSON.stringify(value) : String(value);
    return `<div><dt>${esc(label)}</dt><dd>${esc(text.slice(0, 800))}</dd></div>`;
  }).join("")}</dl>`;
  if (role === "adjudicate" && Array.isArray(item.independent_reviews)) {
    disagreement.hidden = false;
    disagreement.innerHTML = `两位专家独立结论：${item.independent_reviews.map(review => `<strong>${esc(review.reviewer)}</strong>＝${esc(names[review.label] || (review.label === "exclude" ? "排除" : review.label))}（${esc(review.notes || "无说明")}）`).join("；")}。仲裁人必须是第三人。`;
  }
  $("#fiveLayerGoldNotes").value = "";
}

async function prepareFiveLayerGoldExpansion() {
  const targetInput = $("#fiveLayerGoldTarget");
  const maximum = Math.max(96, Number(targetInput.max || 1495));
  const target = Math.max(96, Math.min(maximum, Number(targetInput.value || 500)));
  targetInput.value = String(target);
  localStorage.setItem("malappFiveLayerGoldTarget", String(target));
  if (!window.confirm(`将建立或补齐 ${num(target)} 条冻结金标目标。来源参考标签只用于分层抽样，不会展示给专家或直接成为金标。是否继续？`)) return;
  const button = $("#prepareFiveLayerGoldBtn");
  button.disabled = true;
  try {
    await api("/api/evaluation/five-layer/gold-expansion/prepare", {
      method: "POST",
      body: JSON.stringify({ target_total: target }),
    });
    toast("金标扩充候选已生成或补齐");
    await loadFiveLayerGoldExpansion();
  } catch (error) {
    toast(`准备失败：${error.message}`, true);
  } finally {
    button.disabled = false;
  }
}

async function saveFiveLayerGoldReview() {
  const item = state.fiveLayerGoldItems?.[state.fiveLayerGoldIndex];
  if (!item) return;
  const reviewer = $("#fiveLayerGoldReviewer").value.trim();
  const notes = $("#fiveLayerGoldNotes").value.trim();
  if (!reviewer) {
    toast("请输入复核人姓名或工号", true);
    $("#fiveLayerGoldReviewer").focus();
    return;
  }
  if (!notes) {
    toast("请填写支持结论的证据或排除原因", true);
    $("#fiveLayerGoldNotes").focus();
    return;
  }
  localStorage.setItem("malappFiveLayerGoldReviewer", reviewer);
  const button = $("#saveFiveLayerGoldBtn");
  button.disabled = true;
  try {
    await api("/api/evaluation/five-layer/gold-expansion/review", {
      method: "POST",
      body: JSON.stringify({
        sample_id: item.id,
        reviewer,
        label: $("#fiveLayerGoldLabel").value,
        notes,
        role: $("#fiveLayerGoldRole").value,
      }),
    });
    toast($("#fiveLayerGoldRole").value === "adjudicate" ? "仲裁结果已保存" : "独立复核已保存");
    await loadFiveLayerGoldExpansion();
  } catch (error) {
    button.disabled = false;
    toast(`保存失败：${error.message}`, true);
  }
}

function skipFiveLayerGoldReview() {
  const items = state.fiveLayerGoldItems || [];
  if (!items.length) return;
  state.fiveLayerGoldIndex = (state.fiveLayerGoldIndex + 1) % items.length;
  renderFiveLayerGoldItem();
}

async function freezeFiveLayerGoldExpansion() {
  const overview = state.fiveLayerGoldOverview || {};
  const target = Number(overview.target_total || $("#fiveLayerGoldTarget").value || 500);
  if (!overview.ready_to_freeze) {
    toast(`尚缺 ${num(overview.remaining_to_target || 0)} 条有效双审/仲裁金标`, true);
    return;
  }
  if (!window.confirm(`将冻结 v2-${num(target)} 金标版本并生成新的五层套件。旧套件和历史结果不会覆盖。是否继续？`)) return;
  const button = $("#freezeFiveLayerGoldBtn");
  button.disabled = true;
  button.textContent = "正在冻结并生成套件";
  try {
    await api("/api/evaluation/five-layer/gold-expansion/freeze", {
      method: "POST",
      body: JSON.stringify({ target_total: target, name: `v2-gold${target}` }),
    });
    toast(`新的 ${num(target)} 条冻结金标套件已生成`);
    await Promise.all([loadFiveLayer(), loadFiveLayerGoldExpansion()]);
  } catch (error) {
    toast(`冻结失败：${error.message}`, true);
  } finally {
    button.textContent = "冻结新版本并生成五层套件";
    button.disabled = !state.fiveLayerGoldOverview?.ready_to_freeze;
  }
}

async function openFiveLayerRagReview() {
  const panel = $("#fiveLayerRagReview");
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "start" });
  $("#fiveLayerRagReviewer").value = localStorage.getItem("malappFiveLayerRagReviewer") || "";
  await loadFiveLayerRagAnnotations();
}

async function loadFiveLayerRagAnnotations() {
  const progress = $("#fiveLayerRagReviewProgress");
  progress.textContent = "正在加载待复核检索样本……";
  try {
    const response = await api("/api/evaluation/five-layer/rag-annotations?status=pending&limit=50");
    state.fiveLayerRagItems = response.items || [];
    state.fiveLayerRagIndex = 0;
    state.fiveLayerRagCounts = response.counts || {};
    renderFiveLayerRagItem();
  } catch (error) {
    progress.textContent = `加载失败：${error.message}`;
    toast(`RAG标注加载失败：${error.message}`, true);
  }
}

function renderFiveLayerRagItem() {
  const progress = $("#fiveLayerRagReviewProgress");
  const items = state.fiveLayerRagItems || [];
  const item = items[state.fiveLayerRagIndex];
  const counts = state.fiveLayerRagCounts || {};
  if (!item) {
    progress.textContent = `当前批次没有待复核样本。已批准 ${num(counts.approved || 0)} 条，已仲裁 ${num(counts.adjudicated || 0)} 条。`;
    $("#fiveLayerRagQuery").innerHTML = "<strong>待复核队列已清空</strong>";
    $("#fiveLayerRagDocuments").innerHTML = "";
    $("#saveFiveLayerRagBtn").disabled = true;
    $("#skipFiveLayerRagBtn").disabled = true;
    return;
  }
  $("#saveFiveLayerRagBtn").disabled = false;
  $("#skipFiveLayerRagBtn").disabled = false;
  progress.textContent = `本次加载 ${num(items.length)} 条，当前第 ${num(state.fiveLayerRagIndex + 1)} 条；全套待复核 ${num(counts.needs_expert_review || 0)} 条，已批准 ${num(counts.approved || 0)} 条。`;
  $("#fiveLayerRagQuery").innerHTML = `<span>检索问题</span><strong>${esc(item.query || item.id || "--")}</strong><small>样本ID：${esc(item.id || "--")}</small>`;
  const relevant = new Set(item.relevant_doc_ids || []);
  const hardNegative = new Set(item.hard_negative_doc_ids || []);
  const weakRelevant = new Set(item.weak_relevant_doc_ids || []);
  const weakHardNegative = new Set(item.weak_hard_negative_doc_ids || []);
  $("#fiveLayerRagDocuments").innerHTML = (item.retrieved_items || []).map((doc, index) => {
    const docId = String(doc.doc_id || "");
    const selected = relevant.has(docId) ? "relevant" : hardNegative.has(docId) ? "hard_negative" : "ignore";
    const weak = weakRelevant.has(docId)
      ? `<span class="badge pending">机器预标：相关</span>`
      : weakHardNegative.has(docId)
        ? `<span class="badge pending">机器预标：困难负例</span>`
        : "";
    return `<article class="five-layer-rag-document">
      <div>
        <div class="five-layer-rag-document-head">
          <strong>${index + 1}. ${esc(doc.title || docId || "未命名文档")}</strong>
          ${weak}
        </div>
        <small>${esc(doc.source_type || "未知来源")} · 相似度 ${fiveLayerResultNumber(doc.similarity, 4)} · ${esc(docId)}</small>
        <p>${esc(doc.content || "无摘要内容")}</p>
      </div>
      <label>专家结论
        <select data-rag-doc-id="${esc(docId)}">
          <option value="ignore" ${selected === "ignore" ? "selected" : ""}>不计入</option>
          <option value="relevant" ${selected === "relevant" ? "selected" : ""}>相关证据</option>
          <option value="hard_negative" ${selected === "hard_negative" ? "selected" : ""}>困难负例</option>
        </select>
      </label>
    </article>`;
  }).join("") || `<div class="empty">本条尚无召回文档。若确认语料库没有相关证据，请勾选“无相关文档”。</div>`;
  $("#fiveLayerRagStatus").value = ["approved", "adjudicated", "needs_expert_review"].includes(item.annotation_status)
    ? item.annotation_status
    : "approved";
  $("#fiveLayerRagNoRelevant").checked = Boolean(item.no_relevant_document);
  $("#fiveLayerRagEvidenceSupported").value = typeof item.evidence_supported === "boolean" ? String(item.evidence_supported) : "";
  $("#fiveLayerRagHallucination").value = typeof item.hallucination === "boolean" ? String(item.hallucination) : "";
  $("#fiveLayerRagWrongEvidence").checked = Boolean(item.wrong_evidence);
  $("#fiveLayerRagMissingEvidence").checked = Boolean(item.missing_evidence);
  $("#fiveLayerRagNotes").value = item.review_notes || "";
}

async function saveFiveLayerRagAnnotation() {
  const item = state.fiveLayerRagItems?.[state.fiveLayerRagIndex];
  if (!item) return;
  const reviewer = $("#fiveLayerRagReviewer").value.trim();
  if (!reviewer) {
    toast("请输入复核人，保证标注可审计", true);
    $("#fiveLayerRagReviewer").focus();
    return;
  }
  const relevant = [];
  const hardNegative = [];
  $$("[data-rag-doc-id]").forEach(select => {
    if (select.value === "relevant") relevant.push(select.dataset.ragDocId);
    if (select.value === "hard_negative") hardNegative.push(select.dataset.ragDocId);
  });
  const button = $("#saveFiveLayerRagBtn");
  button.disabled = true;
  localStorage.setItem("malappFiveLayerRagReviewer", reviewer);
  const optionalBool = selector => {
    const value = $(selector)?.value || "";
    return value === "" ? null : value === "true";
  };
  try {
    await api("/api/evaluation/five-layer/rag-annotations", {
      method: "POST",
      body: JSON.stringify({
        sample_id: item.id,
        relevant_doc_ids: relevant,
        hard_negative_doc_ids: hardNegative,
        annotation_status: $("#fiveLayerRagStatus").value,
        reviewer,
        review_notes: $("#fiveLayerRagNotes").value.trim(),
        no_relevant_document: $("#fiveLayerRagNoRelevant").checked,
        evidence_supported: optionalBool("#fiveLayerRagEvidenceSupported"),
        hallucination: optionalBool("#fiveLayerRagHallucination"),
        wrong_evidence: $("#fiveLayerRagWrongEvidence").checked,
        missing_evidence: $("#fiveLayerRagMissingEvidence").checked,
      }),
    });
    toast("RAG专家标注已保存");
    state.fiveLayerRagItems.splice(state.fiveLayerRagIndex, 1);
    if (state.fiveLayerRagIndex >= state.fiveLayerRagItems.length) state.fiveLayerRagIndex = 0;
    renderFiveLayerRagItem();
  } catch (error) {
    button.disabled = false;
    toast(`保存失败：${error.message}`, true);
  }
}

function skipFiveLayerRagAnnotation() {
  const items = state.fiveLayerRagItems || [];
  if (!items.length) return;
  state.fiveLayerRagIndex = (state.fiveLayerRagIndex + 1) % items.length;
  renderFiveLayerRagItem();
}

async function generateFiveLayer() {
  const button = $("#generateFiveLayerBtn");
  const oldText = button.textContent;
  try {
    button.disabled = true;
    button.textContent = "正在审计并生成";
    $("#fiveLayerPath").textContent = "正在扫描验证集、训练数据、研判数据库、RAG库和Agent轨迹，请稍候……";
    const generated = await api("/api/evaluation/five-layer/generate", {
      method: "POST",
      body: JSON.stringify({
        name: "v1",
        model_size: 500,
        rag_size: 200,
        agent_size: 500,
        challenge_size: 300,
        fresh_candidate_size: 1000,
      }),
    });
    state.fiveLayerSuiteId = generated.suite_id || "";
    if (state.fiveLayerSuiteId) {
      localStorage.setItem("malappFiveLayerSuiteId", state.fiveLayerSuiteId);
    }
    state.fiveLayer = null;
    await loadFiveLayer();
    toast("五层评测数据集已生成");
  } catch (error) {
    $("#fiveLayerPath").textContent = `生成失败：${error.message}`;
    toast(`五层评测生成失败：${error.message}`, true);
  } finally {
    button.disabled = false;
    button.textContent = oldText;
  }
}

function renderOverview(data) {
  state.overview = data; const c = data.counts;
  const metrics = [
    ["已加载检测数据", c.engine_records, `覆盖 ${num(c.unique_engine_samples)} 个唯一样本`, "#2563a7"],
    ["已加载特征记录", c.feature_records, `${num(c.manual_labels)} 条人工标签`, "#16899a"],
    ["待处理任务", (data.task_status.find(x => x.name === "pending") || {}).count || 0, `队列共 ${num(c.queued_samples)} 个样本`, "#b36b00"],
    ["已保存研判结果", c.saved_reports, `${num(c.cached_reports)} 份缓存报告`, "#14845f"],
    ["数据存储占用", bytes(data.storage.data_directory_bytes), `数据库 ${bytes(data.storage.database_bytes)}`, "#7c3f98"],
  ];
  $("#metricGrid").innerHTML = metrics.map(m => `<article class="metric" style="--metric-color:${m[3]}"><span>${m[0]}</span><strong>${typeof m[1] === "number" ? num(m[1]) : m[1]}</strong><small>${m[2]}</small></article>`).join("");
  $("#overviewUpdated").textContent = `更新于 ${new Date(data.generated_at).toLocaleTimeString("zh-CN")}`;
  $("#uptimeText").textContent = `运行时长 ${Math.floor(data.uptime_seconds / 60)} 分钟`;
  renderDistribution("#taskStatusChart", data.task_status, ["#b36b00", "#2563a7", "#14845f", "#b42318"]);
  renderDistribution("#sourceList", data.feature_sources, ["#16899a", "#2563a7", "#14845f", "#7c3f98"]);
  $("#agentStatusList").innerHTML = data.agents.map(a => `<div class="agent-row"><strong>${esc(names[a.name] || a.name)}</strong><span class="state-dot">● ${esc(a.status || "ready")}</span><small>${esc(a.summary || "运行环境已就绪")}</small></div>`).join("");
  $("#recentReports").innerHTML = data.recent_reports.length ? data.recent_reports.map(r => `<div class="recent-row" data-report-id="${esc(r.report_id)}"><strong>${esc(r.app_name)}</strong><span class="badge ${r.risk_level}">${names[r.risk_level] || r.risk_level}</span><small>${esc(r.sample_id)} · ${names[r.verdict] || r.verdict} · ${score(r.final_score)} · ${new Date(r.created_at).toLocaleString("zh-CN")}</small></div>`).join("") : "<p>暂无研判结果</p>";
  $$("[data-report-id]").forEach(el => el.onclick = () => openReport(el.dataset.reportId));
  renderInventory(data); drawTrend(data.trend);
}
function renderDistribution(selector, items, colors) {
  const max = Math.max(1, ...items.map(x => Number(x.count)));
  $(selector).innerHTML = items.length ? items.map((x, i) => `<div class="dist-row"><span>${esc(names[x.name] || x.name)}</span><strong>${num(x.count)}</strong><div class="bar"><i style="width:${Number(x.count) / max * 100}%;--bar-color:${colors[i % colors.length]}"></i></div></div>`).join("") : "<p>暂无数据</p>";
}
function drawTrend(items) {
  const canvas = $("#trendChart"), ctx = canvas.getContext("2d"), w = canvas.width, h = canvas.height;
  ctx.clearRect(0, 0, w, h); ctx.font = "12px Microsoft YaHei"; ctx.fillStyle = "#667085";
  if (!items.length) { ctx.fillText("暂无趋势数据", 30, 50); return; }
  const pad = { l: 48, r: 24, t: 20, b: 42 }, max = Math.max(1, ...items.map(x => x.count));
  ctx.strokeStyle = "#e2e7eb"; ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) { const y = pad.t + (h - pad.t - pad.b) * i / 4; ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(w - pad.r, y); ctx.stroke(); }
  const slot = (w - pad.l - pad.r) / items.length, barW = Math.max(8, slot * .48);
  items.forEach((x, i) => {
    const bh = (h - pad.t - pad.b) * x.count / max, cx = pad.l + slot * i + slot / 2;
    ctx.fillStyle = "#2563a7"; ctx.fillRect(cx - barW / 2, h - pad.b - bh, barW, bh);
    ctx.fillStyle = "#667085"; ctx.textAlign = "center"; ctx.fillText(x.day.slice(5), cx, h - 17);
    ctx.fillStyle = "#17202a"; ctx.fillText(String(x.count), cx, h - pad.b - bh - 7);
  });
}
function renderInventory(data) {
  const c = data.counts, rows = [
    ["引擎检测原始数据", c.engine_records, "Engine A / Engine B 检测记录"],
    ["归一化特征数据", c.feature_records, "静态、网络、情报和业务特征"],
    ["人工标注数据", c.manual_labels, "用于评估和后续置信度学习"],
    ["研判结果", c.saved_reports, "完整 JSON 报告，可导出归档"],
    ["报告缓存", c.cached_reports, "降低重复样本推理耗时"],
  ];
  $("#inventoryList").innerHTML = rows.map(r => `<div class="inventory-row"><strong>${r[0]}</strong><b>${num(r[1])}</b><small>${r[2]}</small></div>`).join("");
}

function normalizedTasks() {
  const done = state.reports.map(r => ({ id: r.report_id, sample: r.sample?.sample_id || "-", app: r.sample?.app_name || r.sample?.package_name || "-", status: "completed", risk: r.decision?.risk_level || "low", value: Number(r.decision?.final_score || 0), time: r.created_at, report: r }));
  const pending = state.pending.map(r => ({ id: `pending-${r.md5}`, sample: r.md5, app: r.priority_reason || r.source, status: r.status || "pending", risk: r.priority_score >= 70 ? "high" : r.priority_score >= 40 ? "medium" : "low", value: Number(r.priority_score || 0), time: r.updated_at }));
  return [...done, ...pending];
}
function renderTasks() {
  let rows = normalizedTasks(); const status = $("#statusFilter").value, risk = $("#riskFilter").value, q = $("#taskSearch").value.trim().toLowerCase();
  if (status) rows = rows.filter(x => x.status === status); if (risk) rows = rows.filter(x => x.risk === risk);
  if (q) rows = rows.filter(x => `${x.sample} ${x.app}`.toLowerCase().includes(q));
  const sort = $("#taskSort").value;
  rows.sort((a, b) => sort === "risk" ? ({ high: 3, medium: 2, low: 1 }[b.risk] - ({ high: 3, medium: 2, low: 1 }[a.risk])) : sort === "score" ? b.value - a.value : String(b.time).localeCompare(String(a.time)));
  const all = normalizedTasks();
  const taskSummary = state.taskSummary || {};
  $("#taskSummary").innerHTML = ["pending", "processing", "completed", "failed"].map(s => {
    const count = Number.isFinite(Number(taskSummary[s])) ? Number(taskSummary[s]) : all.filter(x => x.status === s).length;
    return `<div class="summary-item"><span>${names[s]}</span><strong>${num(count)}</strong></div>`;
  }).join("");
  $("#taskTableBody").innerHTML = rows.length ? rows.slice(0, 300).map(x => `<tr><td><strong>${esc(x.sample)}</strong><br><small>${esc(x.id)}</small></td><td>${esc(x.app)}</td><td><span class="badge ${x.status}">${names[x.status]}</span></td><td><span class="badge ${x.risk}">${names[x.risk]}</span></td><td>${score(x.value)}</td><td>${x.time ? new Date(x.time).toLocaleString("zh-CN") : "--"}</td><td><button data-task="${esc(x.id)}">${x.report ? "查看报告" : "载入样本"}</button></td></tr>`).join("") : `<tr><td colspan="7">没有符合条件的任务</td></tr>`;
  $$("[data-task]").forEach(b => b.onclick = () => { const x = all.find(v => v.id === b.dataset.task); x.report ? renderReport(x.report) : loadQueuedSample(x.sample); });
}
async function loadTasks() {
  const [reports, pending, taskSummary] = await Promise.all([api("/api/reports?limit=200"), api("/api/tasks/next?limit=200"), api("/api/tasks/summary")]);
  state.reports = reports.items || []; state.pending = pending.items || []; state.taskSummary = taskSummary || {}; renderTasks();
}
async function openReport(id) {
  const report = state.reports.find(r => r.report_id === id) || (await api("/api/reports?limit=200")).items.find(r => r.report_id === id);
  if (report) renderReport(report);
}

function pct(value) {
  return value == null ? "--" : `${(Number(value) * 100).toFixed(2)}%`;
}
function validationResultText(value) {
  return { correct: "正确", incorrect: "错误", review: "可疑/复核" }[value] || value || "--";
}
function validationResultClass(value) {
  return value === "correct" ? "completed" : value === "incorrect" ? "failed" : "pending";
}
function appCompareResult(gold, verdict) {
  if (!verdict) return "";
  if (verdict === "suspicious") return "review";
  return gold === verdict ? "correct" : "incorrect";
}
function appValidationResult(row) {
  const local = state.appValidationResults[row.md5];
  if (local) return local;
  const saved = row.app_report || {};
  if (!saved.verdict) return null;
  return {
    verdict: saved.verdict,
    final_score: saved.final_score,
    report_id: saved.report_id,
    created_at: saved.created_at,
    saved: true,
  };
}
function appValidationSummary(rows) {
  const done = rows
    .map(row => ({ row, result: appValidationResult(row) }))
    .filter(item => item.result && !item.result.running && !item.result.error && item.result.verdict);
  let correct = 0, incorrect = 0, review = 0, tp = 0, fn = 0, fp = 0, tn = 0;
  for (const item of done) {
    const gold = item.row.gold_label;
    const verdict = item.result.verdict;
    const compare = appCompareResult(gold, verdict);
    if (compare === "correct") correct += 1;
    if (compare === "incorrect") incorrect += 1;
    if (compare === "review") review += 1;
    if (gold === "malicious" && verdict === "malicious") tp += 1;
    if (gold === "malicious" && verdict === "benign") fn += 1;
    if (gold === "benign" && verdict === "malicious") fp += 1;
    if (gold === "benign" && verdict === "benign") tn += 1;
  }
  const decided = correct + incorrect;
  return {
    done: done.length,
    correct, incorrect, review, tp, fn, fp, tn, decided,
    accuracy: decided ? correct / decided : null,
    recall: (tp + fn) ? tp / (tp + fn) : null,
    precision: (tp + fp) ? tp / (tp + fp) : null,
  };
}
function renderValidation(data) {
  state.validation = data;
  const s = data.summary || {};
  // `items` contains only the current page. Keep its statistics separate
  // from the persisted, full-validation-set judgement count.
  const appS = appValidationSummary(data.items || []);
  const appJudgedTotal = Number(data.judged_total || 0);
  const judgedS = data.judged_summary || {};
  const coveredMalicious = Number(judgedS.labels?.malicious || 0);
  const coveredBenign = Number(judgedS.labels?.benign || 0);
  const totalMalicious = Number(s.labels?.malicious || 0);
  const totalBenign = Number(s.labels?.benign || 0);
  const metrics = [
    ["验证集总数", s.total || 0, `真实标签：恶意 ${num(s.labels?.malicious || 0)} / 良性 ${num(s.labels?.benign || 0)}`, "#2563a7"],
    ["APP已研判", appJudgedTotal, `验证集全量已保存研判 ${num(appJudgedTotal)} 条；当前页 ${num(appS.done)} 条`, "#7c3f98"],
    ["已研判 APP 正确率", pct(judgedS.accuracy), `全量正确 ${num(judgedS.correct || 0)} / 错误 ${num(judgedS.incorrect || 0)} / 复核 ${num(judgedS.review || 0)}`, "#0f766e"],
    ["已研判标签覆盖", `${num(coveredMalicious)} / ${num(coveredBenign)}`, `恶意 ${num(coveredMalicious)}/${num(totalMalicious)}；良性 ${num(coveredBenign)}/${num(totalBenign)}`, coveredBenign ? "#2563a7" : "#b42318"],
    ["当前页 APP 正确率", pct(appS.accuracy), `正确 ${num(appS.correct)} / 错误 ${num(appS.incorrect)}`, "#14845f"],
    ["当前页 APP 恶意召回率", pct(appS.recall), `TP ${num(appS.tp)} / FN ${num(appS.fn)}`, "#b36b00"],
    ["当前页 APP 恶意精确率", pct(appS.precision), `FP ${num(appS.fp)} / TN ${num(appS.tn)} / 复核 ${num(appS.review)}`, "#16899a"],
  ];
  $("#validationMetrics").innerHTML = metrics.map(m => `<article class="metric" style="--metric-color:${m[3]}"><span>${m[0]}</span><strong>${typeof m[1] === "number" ? num(m[1]) : m[1]}</strong><small>${m[2]}</small></article>`).join("");
  $("#validationPath").textContent = data.exists
    ? `来源：${data.path}；当前只显示已完成 APP 研判的样本，筛选后 ${num(data.total)} 条，当前显示 ${num((data.items || []).length)} 条。测试集中已研判 ${num(data.judged_total || 0)} 条；XGB 仅作为参考列。`
    : `未找到验证集：${data.path}`;
  const rows = data.items || [];
  $("#validationTableBody").innerHTML = rows.length ? rows.map(row => `
    <tr>
      <td><strong>${esc(row.md5)}</strong><br><small>${esc(row.app_name || row.package_name || "-")}</small></td>
      <td><span class="badge ${row.gold_label === "malicious" ? "high" : "low"}">${names[row.gold_label] || row.gold_label}</span></td>
      <td><span class="badge ${row.pred_label === "malicious" ? "high" : row.pred_label === "benign" ? "low" : "medium"}">${names[row.pred_label] || row.pred_label}</span></td>
      <td>${renderAppValidationVerdict(row)}</td>
      <td>${renderAppValidationCompare(row)}</td>
      <td>${row.xgb_probability == null ? "--" : score(row.xgb_probability)}</td>
      <td>360: ${esc(row.engine_360_score || "--")}<br><small>cm: ${esc(row.engine_cm_score || "--")}</small></td>
      <td>${esc(row.label_source || "-")}<br><small>${esc(row.virus_name || "")}</small></td>
      <td><button data-app-validate-md5="${esc(row.md5)}">APP研判对比</button><button data-validation-md5="${esc(row.md5)}">载入样本</button></td>
    </tr>`).join("") : `<tr><td colspan="9">当前没有已完成 APP 研判且符合筛选条件的样本。请先在“新建研判”或“APP研判对比”中完成研判。</td></tr>`;
  $$("[data-validation-md5]").forEach(b => b.onclick = () => loadValidationSample(b.dataset.validationMd5));
  $$("[data-app-validate-md5]").forEach(b => b.onclick = () => validateOneSampleWithApp(b.dataset.appValidateMd5, b));
}
function renderAppValidationVerdict(row) {
  const result = appValidationResult(row);
  if (!result) return `<span class="muted">未研判</span>`;
  if (result.running) return `<span class="badge processing">研判中</span>`;
  if (result.error) return `<span class="badge failed">失败</span><br><small>${esc(result.error)}</small>`;
  const verdict = result.verdict || "";
  const klass = verdict === "malicious" ? "high" : verdict === "benign" ? "low" : "medium";
  const source = result.saved ? "已研判" : "本次运行";
  return `<span class="badge ${klass}">${names[verdict] || verdict || "--"}</span><br><small>${source} · 分数 ${score(result.final_score || 0)}</small>`;
}
function renderAppValidationCompare(row) {
  const result = appValidationResult(row);
  if (!result || result.running || result.error) return `<span class="muted">--</span>`;
  const compare = appCompareResult(row.gold_label, result.verdict);
  return `<span class="badge ${validationResultClass(compare)}">${validationResultText(compare)}</span>`;
}
async function loadValidation() {
  const params = new URLSearchParams({
    limit: String(Math.max(20, Math.min(1000, Number($("#validationLimit")?.value || 200)))),
    label: $("#validationLabelFilter")?.value || "",
    result: $("#validationResultFilter")?.value || "",
    q: $("#validationSearch")?.value?.trim() || "",
    judged: state.validationJudgedOnly ? "1" : "0",
  });
  const data = await api(`/api/validation/items?${params}`);
  renderValidation(data);
}

async function loadValidationSample(md5) {
  const sample = await api(`/api/validation/sample?md5=${encodeURIComponent(md5)}`);
  $("#sampleInput").value = JSON.stringify(sample, null, 2);
  switchView("judgeView");
  toast("已载入验证样本");
}
async function validateOneSampleWithApp(md5, button, rowOverride = null) {
  const row = rowOverride || (state.validation?.items || []).find(x => x.md5 === md5);
  if (!row) return;
  state.appValidationResults[md5] = { running: true };
  if (state.validation) renderValidation(state.validation);
  const oldText = button?.textContent || "";
  try {
    if (button) { button.disabled = true; button.textContent = "研判中"; }
    const sample = await api(`/api/validation/sample?md5=${encodeURIComponent(md5)}`);
    const report = await api("/api/judgements", { method: "POST", body: JSON.stringify(sample) });
    const decision = report.decision || {};
    state.appValidationResults[md5] = {
      verdict: decision.verdict,
      final_score: decision.final_score,
      report_id: report.report_id,
    };
    renderValidation(state.validation);
    const compare = appCompareResult(row.gold_label, decision.verdict);
    toast(`APP研判完成：${names[decision.verdict] || decision.verdict}，对比${validationResultText(compare)}`, compare === "incorrect");
  } catch (e) {
    state.appValidationResults[md5] = { error: e.message || String(e) };
    renderValidation(state.validation);
    toast(`APP研判失败：${e.message}`, true);
  } finally {
    if (button) { button.disabled = false; button.textContent = oldText || "APP研判对比"; }
  }
}
async function runValidationPage() {
  const limit = Math.max(20, Math.min(1000, Number($("#validationLimit")?.value || 200)));
  const params = new URLSearchParams({
    limit: String(limit),
    label: $("#validationLabelFilter")?.value || "",
    result: $("#validationResultFilter")?.value || "",
    q: $("#validationSearch")?.value?.trim() || "",
    pending: "1",
    order: "stratified",
  });
  const pendingPage = await api(`/api/validation/items?${params}`);
  const rows = pendingPage.items || [];
  const button = $("#runValidationPageBtn");
  const oldText = button.textContent;
  if (!rows.length) {
    toast("当前筛选范围内没有待研判样本");
    return;
  }
  button.disabled = true;
  try {
    for (let i = 0; i < rows.length; i++) {
      button.textContent = `批量研判 ${i + 1}/${rows.length}`;
      await validateOneSampleWithApp(rows[i].md5, null, rows[i]);
    }
    toast(`当前页批量APP研判完成：${num(rows.length)} 条`);
    await loadValidation();
  } finally {
    button.disabled = false;
    button.textContent = oldText;
  }
}

function modelDisplayName(value) {
  return fieldLabels[value] || names[value] || displayText(value || "");
}
function renderCrossExam(turn) {
  const typeText = turn.type === "challenge" ? "质疑" : "反驳";
  const from = modelDisplayName(turn.from_label || turn.from);
  const to = modelDisplayName(turn.to_label || turn.to);
  const title = from && to ? `${from}${typeText}${to}` : typeText;
  const questionLabel = turn.type === "challenge" ? "质疑内容" : "反驳观点";
  const answerLabel = turn.type === "challenge" ? "质疑依据" : "补充依据";
  const refs = (turn.evidence_refs || []).length
    ? `<p><small>引用证据块：${esc((turn.evidence_refs || []).map(modelDisplayName).join("、"))}</small></p>`
    : "";
  const questionText = displayText(turn.question || "");
  const answerText = displayText(turn.answer || "");
  const invalidRebuttal = turn.type === "rebuttal" && (
    displaySimilarity(questionText, answerText) >= 0.72 || /[?？]\s*$/.test(answerText)
  );
  const answerHtml = invalidRebuttal
    ? `<p class="muted"><b>${esc(from || "模型")} ${answerLabel}：</b>本轮未形成可采纳的反驳理由，已隐藏重复问句；请重新研判以生成基于证据块的反驳。</p>`
    : `<p><b>${esc(from || "模型")} ${answerLabel}：</b>${esc(answerText)}</p>`;
  return `<article class="debate-card cross-exam">
    <strong>第 ${turn.round} 轮 ${typeText}｜${esc(title)}</strong>
    <p><b>${esc(from || "模型")} ${questionLabel}：</b>${esc(questionText)}</p>
    ${answerHtml}
    ${refs}
  </article>`;
}

async function parseFile(file) {
  const text = await file.text(), ext = file.name.split(".").pop().toLowerCase();
  if (ext === "jsonl" || ext === "txt") return text.split(/\r?\n/).filter(Boolean).map((line, i) => { try { return JSON.parse(line); } catch { return { md5: `TEXT-${i + 1}`, raw_text: line }; } });
  const parsed = JSON.parse(text); return Array.isArray(parsed) ? parsed : parsed.items && Array.isArray(parsed.items) ? parsed.items : [parsed];
}
function parseTextInput(text) {
  const value = text.trim();
  if (!value) throw new Error("请先粘贴 JSON 或 JSONL 内容");
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed : parsed.items && Array.isArray(parsed.items) ? parsed.items : [parsed];
  } catch {
    return value.split(/\r?\n/).filter(Boolean).map((line, index) => {
      try { return JSON.parse(line); } catch { throw new Error(`第 ${index + 1} 行不是有效 JSON`); }
    });
  }
}
function setImportItems(items, label) {
  state.importItems = items;
  $("#recordPreview").value = `${num(items.length)} 条`;
  $("#importDataBtn").disabled = !items.length;
  $("#importProgress").textContent = `${label}解析完成，共 ${num(items.length)} 条记录。`;
}
async function importData() {
  const button = $("#importDataBtn"); button.disabled = true; $("#importProgress").textContent = `正在导入 ${num(state.importItems.length)} 条记录...`;
  try {
    const limit = Math.max(1, Math.min(100000, Number($("#genericImportLimit").value || 100)));
    const result = await api("/api/data/import", { method: "POST", body: JSON.stringify({ items: state.importItems.slice(0, limit), source: $("#importSource").value || "manual_upload" }) });
    $("#importProgress").textContent = `导入完成：成功 ${num(result.imported)} 条，失败 ${num(result.failed)} 条，批次内重复 ${num(result.duplicates_in_batch)} 条。`;
    toast(`成功导入 ${num(result.imported)} 条数据`);
    await afterBatchCreated(result.batch_id);
    await refreshAll();
  } catch (e) { $("#importProgress").textContent = `导入失败：${e.message}`; toast(`导入失败：${e.message}`, true); } finally { button.disabled = false; }
}

async function loadConflicts() {
  const data = await api("/api/engine/samples?limit=30&conflict_only=1");
  $("#engineSampleList").innerHTML = data.items.map(x => `<button class="sample-item" data-md5="${esc(x.md5)}"><strong>${esc(x.app_name || x.package_name || x.md5)}</strong><small>${esc(x.md5)} · ${esc(x.engine_scores || "")}</small></button>`).join("");
  $$("[data-md5]").forEach(b => b.onclick = () => loadEngineSample(b.dataset.md5));
}
async function loadEngineSample(md5) { $("#sampleInput").value = JSON.stringify(await api(`/api/engine/sample?md5=${encodeURIComponent(md5)}`), null, 2); switchView("judgeView"); }
async function loadQueuedSample(md5) { $("#sampleInput").value = JSON.stringify(await api(`/api/features/sample?md5=${encodeURIComponent(md5)}`), null, 2); switchView("judgeView"); }
async function loadDemo() { $("#sampleInput").value = JSON.stringify(await api("/api/sample"), null, 2); }
async function judgeCurrent() {
  let payload; try { payload = JSON.parse($("#sampleInput").value); } catch (e) { $("#runHint").textContent = `JSON 格式错误：${e.message}`; return; }
  const b = $("#judgeBtn"); b.disabled = true; b.textContent = "研判中"; $("#runHint").textContent = "正在运行四智能体分析、双模型辩论和三引擎协同决策...";
  try { const report = await api("/api/judgements", { method: "POST", body: JSON.stringify(payload) }); state.reports.unshift(report); renderReport(report); await refreshAll(); }
  catch (e) { $("#runHint").textContent = `研判失败：${e.message}`; } finally { b.disabled = false; b.textContent = "开始研判"; }
}

function renderReport(r) {
  state.currentReport = r; $("#emptyDetail").hidden = true; $("#detailContent").hidden = false;
  $("#reportId").textContent = r.report_id; $("#detailTitle").textContent = r.sample?.app_name || r.sample?.package_name || r.sample?.sample_id || "样本详情";
  $("#detailSubtitle").textContent = `${r.sample?.package_name || "--"} · ${new Date(r.created_at).toLocaleString("zh-CN")}`;
  const d = r.decision || {};
  $("#decisionMetrics").innerHTML = [["最终结论", names[d.verdict] || d.verdict, "#14845f"], ["最终分数", score(d.final_score), "#2563a7"], ["风险等级", names[d.risk_level] || d.risk_level, "#b36b00"]].map(x => `<article class="metric" style="--metric-color:${x[2]}"><span>${x[0]}</span><strong>${x[1]}</strong></article>`).join("");
  const s = r.sample || {}; $("#sampleFacts").innerHTML = [["样本 ID", s.sample_id], ["MD5", s.md5], ["SHA256", s.sha256], ["包名", s.package_name], ["应用名称", s.app_name], ["签名状态", s.signature_status], ["权限数量", (s.permissions || []).length]].map(x => `<dt>${x[0]}</dt><dd>${esc(x[1] ?? "--")}</dd>`).join("");
  const explanations = agentExplanationMap(r);
  const llmLayer = r.evidence_layers?.llm_explanation || {};
  $("#evidenceList").innerHTML = (r.evidence_blocks || []).map(x => {
    const evidenceLines = (x.evidence || []).slice(0, 8).map(e => `<li>${esc(displayText(e))}</li>`).join("");
    const structured = (x.evidence_items || []).filter(item => !isMachineLearningEvidence(item)).slice(0, 8).map(logicalEvidenceLine).join("");
    const missing = (x.missing_fields || []).length ? `<p class="muted">缺失字段：${esc((x.missing_fields || []).join("、"))}</p>` : "";
    const llmExplanation = renderAgentExplanation(explanations[x.agent], x) || fallbackAgentExplanation(x, llmLayer);
    return `<article class="evidence-card">
      <div class="panel-head"><strong>${names[x.agent] || x.agent}</strong><span>置信度 ${confidenceText(x.confidence)} · 恶意概率 ${score(x.score)}</span></div>
      <p class="agent-claim">${esc(displayText(x.claim))}</p>
      ${llmExplanation}
      <div class="logic-block">
        <strong>规则判断</strong>
        <ul>${structured || evidenceLines || "<li>暂无证据输出</li>"}</ul>
      </div>
      ${missing}
    </article>`;
  }).join("");
  const debate = r.debate || {};
  const providerModes = Object.values(debate.providers || {}).map(x => x.backend);
  const stageBackends = (debate.stages || []).flatMap(stage => (stage.turns || []).map(turn => turn.backend || ""));
  const usedFallback = stageBackends.some(x => x.includes("fallback"));
  const usedQwen = providerModes.includes("local_qwen") && !usedFallback;
  const usedServerModel = providerModes.includes("openai_compatible") && !usedFallback;
  const completedModelReasoning = (usedQwen || usedServerModel) && (debate.stages || []).length > 0;
  const usedEvidenceVerification = debate.execution_mode === "llm_evidence_verification";
  const hermesRuntime = r.preprocess?.agent_runtime?.hermes || {};
  const hermesModeText = hermesRuntime.mode === "external_runtime"
    ? "外部 Hermes Runtime（长期记忆、消息网关、子代理生命周期协议已接入）"
    : hermesRuntime.mode === "official_cli"
    ? "官方 Hermes"
    : "内嵌 Hermes MCP 兼容模式";
  const orchestratorText = r.execution?.orchestrator === "hermes"
    ? `四智能体由 Hermes 主管通过 MCP 工具并行委派；运行模式：${hermesModeText}。`
    : "四智能体由项目原生调度器运行。";
  const runtimeText = usedFallback
    ? "本次已启用本地 Qwen，但模型调用失败。模型甲和模型乙显示的是规则回退结果，并非大模型真实推理；请启动可用的 Qwen 工作进程或配置服务器模型 API。"
    : usedEvidenceVerification
    ? "当前为证据复核模式；建议重新研判以执行完整的初判、质疑、反驳和终审流程。"
    : completedModelReasoning
    ? "本报告已调用大模型完成初判、质疑、反驳和终审。"
    : usedFallback
      ? "本报告启用了本地 Qwen，但模型调用失败，已降级为规则研判。"
      : "大模型未完成有效推理，本报告不作为有效辩论结果；请配置可用模型后重新研判。";
  const initialCards = ["model_a", "model_b"].map(k => modelInitialCard(debate[k] || {}, k)).join("");
  const arbiter = debate.arbiter || {};
  const arbiterSummary = arbiter.final_summary || arbiter.rationale || "终审裁决尚未形成摘要。";
  const arbiterCard = `<article class="debate-card"><div class="panel-head"><strong>${names.arbiter}</strong><span>${names[arbiter.verdict] || arbiter.verdict || "--"} · 恶意倾向 ${score(arbiter.score)}</span></div><p>${esc(displayText(arbiterSummary))}</p></article>`;
  $("#debateList").innerHTML = `<article class="debate-card runtime"><strong>四智能体编排模式</strong><p>${orchestratorText}</p></article><article class="debate-card runtime ${usedFallback ? "warning" : ""}"><strong>本次辩论运行模式</strong><p>${runtimeText}</p></article>` + initialCards + arbiterCard + (debate.cross_examination || []).map(renderCrossExam).join("");
  $("#decisionSummary").innerHTML = `<ul class="decision-list">${(d.key_evidence || []).slice(0, 7).map(x => `<li>${esc(displayText(x.label))}，证据强度 ${score(x.strength)}</li>`).join("")}</ul>`;
  const reasoningCards = ["model_a", "model_b"].map(k => {
    const x = debate[k] || {};
    return `<article class="debate-card reasoning">
      <div class="panel-head"><strong>${names[k]}总结</strong><span>模型置信度 ${confidenceText(x.confidence)}</span></div>
      <p>${esc(modelReasoningParagraph(x, k))}</p>
    </article>`;
  }).join("");
  const fusion = d.fusion || {};
  const fusionCard = `<article class="debate-card reasoning">
    <div class="panel-head"><strong>机器学习与大模型融合</strong><span>${esc(fusion.mode || "evidence_only")}</span></div>
    <ul>
      <li>XGBoost 恶意概率：${score(fusion.xgb_probability)}</li>
      <li>大模型综合概率：${score(fusion.llm_probability)}</li>
      <li>大模型判断置信度：${confidenceText(fusion.llm_confidence)}</li>
      <li>实际融合权重：XGBoost ${score(fusion.xgb_weight)}，大模型 ${score(fusion.llm_weight)}</li>
    </ul>
    <p>${esc(displayText(fusion.formula || "最终结论由结构化特征模型与大模型证据复核共同决定。"))}</p>
  </article>`;
  $("#debateList").insertAdjacentHTML("beforeend", reasoningCards + fusionCard);
  renderLearningCurrentReport();
  drawRadar(r); switchView("detailView");
}
function drawRadar(r) {
  const canvas = $("#engineRadar"), ctx = canvas.getContext("2d"), scores = r.decision?.engine_scores || {};
  const series = [{ name: "Engine A", color: "#2563a7", base: scores.engine_a }, { name: "Engine B", color: "#b36b00", base: scores.engine_b }, { name: "Engine C", color: "#14845f", base: scores.engine_c }];
  const labels = ["静态可信", "情报一致", "仿冒匹配", "业务危害"], blocks = Object.fromEntries((r.evidence_blocks || []).map(x => [x.agent, Number(x.score || 0)]));
  const domain = [blocks.static_analysis || .4, blocks.threat_intel || .4, blocks.impersonation || .4, blocks.business_label || .4];
  const w = canvas.width, h = canvas.height, c = { x: w / 2, y: h / 2 + 8 }, radius = Math.min(w, h) * .36, point = (rad, i) => ({ x: c.x + Math.cos(-Math.PI / 2 + i * Math.PI / 2) * rad, y: c.y + Math.sin(-Math.PI / 2 + i * Math.PI / 2) * rad });
  ctx.clearRect(0, 0, w, h); ctx.font = "13px Microsoft YaHei"; ctx.textAlign = "center";
  for (let level = 1; level <= 5; level++) { ctx.beginPath(); labels.forEach((_, i) => { const p = point(radius * level / 5, i); i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y); }); ctx.closePath(); ctx.strokeStyle = "#dfe4ea"; ctx.stroke(); }
  labels.forEach((l, i) => { const p = point(radius + 25, i); ctx.fillStyle = "#667085"; ctx.fillText(l, p.x, p.y); });
  series.forEach((x, si) => { ctx.beginPath(); domain.forEach((v, i) => { const value = Math.max(0, Math.min(1, Number(x.base || .5) * .55 + v * .45 + si * .01)); const p = point(radius * value, i); i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y); }); ctx.closePath(); ctx.fillStyle = `${x.color}22`; ctx.fill(); ctx.strokeStyle = x.color; ctx.lineWidth = 2; ctx.stroke(); });
  $("#radarLegend").innerHTML = series.map(x => `<span><i style="background:${x.color}"></i>${x.name}</span>`).join("");
}
function download(content, type, name) { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([content], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 500); }

function reportLabel(r) {
  const sample = r.sample || {};
  const decision = r.decision || {};
  const app = sample.app_name || sample.package_name || sample.sample_id || "未知应用";
  const verdict = names[decision.verdict] || decision.verdict || "无结论";
  const risk = names[decision.risk_level] || decision.risk_level || "无风险等级";
  const time = r.created_at ? new Date(r.created_at).toLocaleString("zh-CN") : "";
  return `${app} | ${verdict} | ${risk} | ${score(decision.final_score)} | ${time}`;
}

async function loadHumanReviewReports() {
  const select = $("#humanReportSelect");
  if (!select) return;
  const selected = state.currentReport?.report_id || select.value;
  select.innerHTML = `<option value="">正在加载报告...</option>`;
  try {
    const data = await api("/api/reports?limit=200");
    const items = data.items || [];
    state.reports = items;
    if (!items.length) {
      select.innerHTML = `<option value="">暂无已研判报告</option>`;
      renderLearningCurrentReport();
      return;
    }
    select.innerHTML = items.map(r => `<option value="${esc(r.report_id)}">${esc(reportLabel(r))}</option>`).join("");
    if (selected && items.some(r => r.report_id === selected)) select.value = selected;
    else if (!state.currentReport) state.currentReport = items[0];
    if (select.value) {
      const picked = items.find(r => r.report_id === select.value);
      if (picked) state.currentReport = picked;
    }
    renderLearningCurrentReport();
  } catch (e) {
    select.innerHTML = `<option value="">报告加载失败</option>`;
    $("#humanReviewResult").textContent = `报告加载失败：${e.message}`;
  }
}

function pickHumanReviewReport() {
  const reportId = $("#humanReportSelect")?.value || "";
  if (!reportId) return null;
  const report = state.reports.find(r => r.report_id === reportId);
  if (report) {
    state.currentReport = report;
    renderLearningCurrentReport();
  }
  return state.currentReport?.report_id === reportId ? state.currentReport : null;
}

function renderLearningCurrentReport() {
  const el = $("#learningCurrentReport");
  if (!el) return;
  const r = state.currentReport;
  if (!r) {
    el.textContent = "请选择一份已研判报告，或先完成一次研判。";
    return;
  }
  if ($("#humanReportSelect") && r.report_id && $("#humanReportSelect").value !== r.report_id) $("#humanReportSelect").value = r.report_id;
  const d = r.decision || {};
  el.innerHTML = `当前报告：<strong>${esc(r.report_id)}</strong><br>样本：${esc(r.sample?.app_name || r.sample?.sample_id || "--")}<br>当前结论：${esc(names[d.verdict] || d.verdict || "--")}，风险：${esc(names[d.risk_level] || d.risk_level || "--")}，分数：${score(d.final_score)}<br>agent_trace：${esc(r.execution?.agent_trace_id || "已保存或待查询")}`;
  const currentVerdict = d.verdict;
  if (currentVerdict && $("#humanLabel")) $("#humanLabel").value = currentVerdict;
}

async function saveHumanReview() {
  const selectedReport = pickHumanReviewReport();
  if (!selectedReport?.report_id) {
    toast("请先选择一份研判报告", true);
    return;
  }
  const optionalBool = id => {
    const value = $(id)?.value || "";
    return value === "" ? null : value === "true";
  };
  const payload = {
    report_id: selectedReport.report_id,
    human_label: $("#humanLabel").value,
    reviewer: $("#humanReviewer").value.trim(),
    notes: $("#humanNotes").value.trim(),
    review_status: $("#humanReviewStatus")?.value || "reviewed",
    error_types: Array.from($("#humanErrorTypes")?.selectedOptions || []).map(option => option.value),
    evidence_supported: optionalBool("#humanEvidenceSupported"),
    json_valid: optionalBool("#humanJsonValid"),
    concise: optionalBool("#humanConcise"),
    punctuation_valid: optionalBool("#humanPunctuationValid"),
    hallucination: optionalBool("#humanHallucination"),
    corrected_output: $("#humanCorrectedOutput")?.value?.trim() || "",
  };
  $("#humanReviewResult").textContent = "正在保存人工复核...";
  try {
    const result = await api("/api/human-reviews", { method: "POST", body: JSON.stringify(payload) });
    $("#humanReviewResult").textContent = `已保存人工复核：${names[result.human_label] || result.human_label}。reward=${score(result.reward?.reward)}，is_correct=${result.is_correct === null ? "未判定" : result.is_correct ? "一致" : "不一致"}，错误分类=${(result.error_types || []).join("、") || "无"}。`;
    toast("人工复核已保存");
  } catch (e) {
    $("#humanReviewResult").textContent = `保存失败：${e.message}`;
    toast(e.message, true);
  }
}

async function openCurrentTrace() {
  const selectedReport = pickHumanReviewReport();
  if (!selectedReport?.report_id) {
    toast("请先选择一份研判报告", true);
    return;
  }
  $("#humanReviewResult").textContent = "正在读取 agent_trace...";
  try {
    const trace = await api(`/api/agent-trace?report_id=${encodeURIComponent(selectedReport.report_id)}`);
    download(JSON.stringify(trace, null, 2), "application/json;charset=utf-8", `${trace.trace_id || selectedReport.report_id}_agent_trace.json`);
    $("#humanReviewResult").textContent = `已导出 agent_trace：${trace.trace_id}`;
  } catch (e) {
    $("#humanReviewResult").textContent = `读取失败：${e.message}`;
    toast(e.message, true);
  }
}

async function exportTrainingDatasets() {
  const limit = Math.max(1, Math.min(100000, Number($("#datasetExportLimit").value || 5000)));
  $("#datasetExportResult").textContent = "正在导出训练数据...";
  try {
    const result = await api("/api/datasets/export", { method: "POST", body: JSON.stringify({ limit }) });
    $("#datasetExportResult").innerHTML = `导出完成：报告 SFT ${num(result.report_generation_sft_count)} 条，DPO ${num(result.debate_dpo_count)} 条，策略训练 ${num(result.policy_training_count)} 条。<br>${Object.entries(result.files || {}).map(([k, v]) => `${esc(k)}：${esc(v)}`).join("<br>")}`;
    toast("训练数据已导出");
  } catch (e) {
    $("#datasetExportResult").textContent = `导出失败：${e.message}`;
    toast(e.message, true);
  }
}

async function loadBatches(selectBatchId = "") {
  const data = await api("/api/batches?limit=50");
  const items = data.items || [];
  const placeholder = `<option value="">请选择本次要研判的数据批次</option>`;
  $("#batchSelect").innerHTML = items.length ? placeholder + items.map(item => {
    const label = `${item.source} | ${item.total_count} 条 | 待研判 ${item.pending || 0} | 已完成 ${item.completed || 0}`;
    return `<option value="${esc(item.batch_id)}">${esc(label)}</option>`;
  }).join("") : `<option value="">暂无可用批次</option>`;
  if (selectBatchId && items.some(item => item.batch_id === selectBatchId)) {
    $("#batchSelect").value = selectBatchId;
  } else {
    $("#batchSelect").value = "";
    state.batchJobId = "";
    $("#retryFailedBatchJudgeBtn").disabled = true;
    $("#pauseBatchJudgeBtn").disabled = true;
    $("#resumeBatchJudgeBtn").disabled = true;
    $("#batchProgress").textContent = "先加载数据或刷新冲突样本，再选择批次开始研判。";
    $("#batchProgressBar").style.width = "0%";
  }
  $("#startBatchJudgeBtn").disabled = !$("#batchSelect").value;
}
async function afterBatchCreated(batchId) {
  if (!batchId) return;
  state.lastBatchId = batchId;
  await loadBatches(batchId);
  if ($("#autoJudgeAfterImport").checked) await startBatchJudgement();
}
async function startBatchJudgement() {
  const batchId = $("#batchSelect").value;
  const limit = Math.max(1, Math.min(1000, Number($("#batchJudgeLimit").value || 10)));
  if (!batchId) { toast("请先选择数据批次", true); return; }
  const button = $("#startBatchJudgeBtn");
  $("#retryFailedBatchJudgeBtn").disabled = true;
  button.disabled = true; button.textContent = "启动中...";
  $("#batchResults").innerHTML = ""; $("#batchProgressBar").style.width = "0%";
  try {
    const job = await api("/api/batch-jobs/start", {
      method: "POST", body: JSON.stringify({ batch_id: batchId, limit }),
    });
    state.batchJobId = job.job_id;
    $("#pauseBatchJudgeBtn").disabled = false;
    $("#resumeBatchJudgeBtn").disabled = true;
    $("#retryFailedBatchJudgeBtn").disabled = true;
    $("#batchProgress").textContent = `已启动自动研判，共 ${num(job.total)} 条。`;
    pollBatchJob(job.job_id);
  } catch (e) {
    $("#batchProgress").textContent = `启动失败：${e.message}`; toast(e.message, true);
    button.disabled = false; button.textContent = "开始自动研判";
  }
}
async function pollBatchJob(jobId) {
  try {
    const job = await api(`/api/batch-jobs/status?job_id=${encodeURIComponent(jobId)}`);
    const percent = job.total ? Math.round(job.processed / job.total * 100) : 0;
    $("#batchProgressBar").style.width = `${percent}%`;
    $("#batchProgress").textContent = job.status === "completed"
      ? `研判完成：成功 ${num(job.succeeded)} 条，失败 ${num(job.failed)} 条。`
      : job.status === "paused"
        ? `任务已暂停：已处理 ${job.processed}/${job.total}，点击“继续”处理剩余样本。`
        : job.status === "pausing"
          ? `正在等待当前样本完成后暂停，进度 ${job.processed}/${job.total}。`
          : `正在研判 ${job.current_md5 || ""}，进度 ${job.processed}/${job.total}，成功 ${job.succeeded}，失败 ${job.failed}。`;
    $("#batchResults").innerHTML = (job.results || []).slice(-20).reverse().map(item =>
      `<div class="batch-result"><strong>${esc(item.md5)}</strong><span>${item.history_reused ? "历史复用" : "新研判"} · ${item.orchestrator === "hermes" ? "Hermes" : "本地编排"} · ${names[item.verdict] || item.verdict}</span><span class="badge ${item.risk_level}">${names[item.risk_level] || item.risk_level} ${score(item.final_score)}</span></div>`
    ).join("") + (job.errors || []).slice(-5).map(item =>
      `<div class="batch-result"><strong>${esc(item.md5)}</strong><span class="badge failed">失败</span><span>${esc(briefErrorText(item.error))}</span></div>`
    ).join("");
    if (job.status === "paused") {
      $("#pauseBatchJudgeBtn").disabled = true;
      $("#resumeBatchJudgeBtn").disabled = false;
      $("#startBatchJudgeBtn").disabled = true;
      $("#retryFailedBatchJudgeBtn").disabled = true;
      $("#startBatchJudgeBtn").textContent = "任务已暂停";
    } else if (job.status !== "completed") {
      $("#pauseBatchJudgeBtn").disabled = job.status === "pausing";
      $("#resumeBatchJudgeBtn").disabled = true;
      $("#retryFailedBatchJudgeBtn").disabled = true;
      setTimeout(() => pollBatchJob(jobId), 800);
    } else {
      $("#startBatchJudgeBtn").disabled = false; $("#startBatchJudgeBtn").textContent = "开始自动研判";
      $("#pauseBatchJudgeBtn").disabled = true; $("#resumeBatchJudgeBtn").disabled = true;
      $("#retryFailedBatchJudgeBtn").disabled = !(job.failed > 0);
      $("#retryFailedBatchJudgeBtn").textContent = "重跑失败";
      toast(`自动研判完成：成功 ${job.succeeded} 条`); await Promise.all([refreshAll(), loadBatches(job.batch_id)]);
    }
  } catch (e) {
    $("#batchProgress").textContent = `状态查询失败：${e.message}`;
    $("#startBatchJudgeBtn").disabled = false; $("#startBatchJudgeBtn").textContent = "开始自动研判";
  }
}
async function pauseBatchJudgement() {
  if (!state.batchJobId) return;
  $("#pauseBatchJudgeBtn").disabled = true;
  try {
    await api("/api/batch-jobs/pause", {
      method: "POST", body: JSON.stringify({ job_id: state.batchJobId }),
    });
    toast("暂停请求已提交，当前样本完成后暂停");
  } catch (e) {
    $("#pauseBatchJudgeBtn").disabled = false;
    toast(`暂停失败：${e.message}`, true);
  }
}
async function resumeBatchJudgement() {
  if (!state.batchJobId) return;
  $("#resumeBatchJudgeBtn").disabled = true;
  try {
    const job = await api("/api/batch-jobs/resume", {
      method: "POST", body: JSON.stringify({ job_id: state.batchJobId }),
    });
    $("#startBatchJudgeBtn").textContent = "研判中";
    $("#pauseBatchJudgeBtn").disabled = false;
    pollBatchJob(job.job_id);
    toast("任务已继续");
  } catch (e) {
    $("#resumeBatchJudgeBtn").disabled = false;
    toast(`继续失败：${e.message}`, true);
  }
}

async function retryFailedBatchJudgement() {
  if (!state.batchJobId) return;
  const button = $("#retryFailedBatchJudgeBtn");
  button.disabled = true;
  button.textContent = "重跑中...";
  try {
    const job = await api("/api/batch-jobs/retry-failed", {
      method: "POST", body: JSON.stringify({ job_id: state.batchJobId }),
    });
    state.batchJobId = job.job_id;
    $("#startBatchJudgeBtn").disabled = true;
    $("#startBatchJudgeBtn").textContent = "研判中";
    $("#pauseBatchJudgeBtn").disabled = false;
    $("#resumeBatchJudgeBtn").disabled = true;
    $("#batchResults").innerHTML = "";
    $("#batchProgressBar").style.width = "0%";
    $("#batchProgress").textContent = `已开始重跑失败样本，共 ${num(job.total)} 条。`;
    pollBatchJob(job.job_id);
    toast("已开始重跑失败样本");
  } catch (e) {
    button.disabled = false;
    button.textContent = "重跑失败";
    toast(`重跑失败样本失败：${e.message}`, true);
  }
}

async function refreshAll() {
  const button = $("#refreshAllBtn");
  const oldText = button.textContent;
  button.disabled = true; button.textContent = "刷新中...";
  try {
    const [overview, engine] = await Promise.all([api("/api/dashboard/overview"), api("/api/engine/stats")]);
    renderOverview(overview); $("#engineStats").textContent = `${engine.by_engine.map(x => `${x.engine}: ${num(x.count)}`).join(" | ")} | 唯一样本 ${num(engine.total_md5)}`;
    await Promise.all([loadTasks(), loadConflicts(), loadBatches(), loadValidation()]);
    if (oldText === "刷新数据") toast("数据已刷新");
  } catch (e) {
    $("#serviceStatus").textContent = "服务异常"; $("#serviceDot").classList.remove("ok");
    toast(`刷新失败：${e.message}`, true); console.error(e);
  } finally {
    button.disabled = false; button.textContent = oldText;
  }
}
async function boot() {
  try {
    const health = await api("/api/health");
    $("#serviceStatus").textContent = "服务在线";
    $("#serviceDot").classList.add("ok");
    $("#versionText").textContent = `版本 ${health.version || "--"} · ${health.build_date || "--"}`;
    $("#versionText").title = `数据目录：${health.data_dir || "--"}`;
    await Promise.all([loadDemo(), loadModelSettings(), loadHermesStatus(), refreshAll()]);
  }
  catch (e) { $("#serviceStatus").textContent = "服务离线"; $("#runHint").textContent = e.message; }
}

$$(".nav-item").forEach(b => b.onclick = () => switchView(b.dataset.view));
$$("[data-go]").forEach(b => b.onclick = () => switchView(b.dataset.go));
$("#refreshAllBtn").onclick = refreshAll; $("#refreshTasksBtn").onclick = loadTasks;
$("#refreshValidationBtn").onclick = loadValidation;
$("#refreshFiveLayerBtn").onclick = loadFiveLayer;
$("#generateFiveLayerBtn").onclick = generateFiveLayer;
$("#fiveLayerSuiteSelect").onchange = async event => {
  state.fiveLayerSuiteId = event.target.value || "";
  if (state.fiveLayerSuiteId) localStorage.setItem("malappFiveLayerSuiteId", state.fiveLayerSuiteId);
  else localStorage.removeItem("malappFiveLayerSuiteId");
  await loadFiveLayer();
};
$("#closeFiveLayerGoldReviewBtn").onclick = () => { $("#fiveLayerGoldReview").hidden = true; };
$("#prepareFiveLayerGoldBtn").onclick = prepareFiveLayerGoldExpansion;
$("#refreshFiveLayerGoldBtn").onclick = loadFiveLayerGoldExpansion;
$("#freezeFiveLayerGoldBtn").onclick = freezeFiveLayerGoldExpansion;
$("#saveFiveLayerGoldBtn").onclick = saveFiveLayerGoldReview;
$("#skipFiveLayerGoldBtn").onclick = skipFiveLayerGoldReview;
$("#fiveLayerGoldRole").onchange = loadFiveLayerGoldExpansion;
$("#fiveLayerGoldReviewer").onchange = loadFiveLayerGoldExpansion;
$("#closeFiveLayerRagReviewBtn").onclick = () => { $("#fiveLayerRagReview").hidden = true; };
$("#saveFiveLayerRagBtn").onclick = saveFiveLayerRagAnnotation;
$("#skipFiveLayerRagBtn").onclick = skipFiveLayerRagAnnotation;
$("#runValidationPageBtn").onclick = runValidationPage;
$("#localQwenToggle").onchange = toggleLocalQwen;
$("#serverModelSettingsBtn").onclick = () => setServerModelSettingsVisible(true);
$("#closeServerModelSettingsBtn").onclick = () => setServerModelSettingsVisible(false);
$("#saveServerModelSettingsBtn").onclick = saveServerModelSettings;
["statusFilter", "riskFilter", "taskSearch", "taskSort"].forEach(id => $(`#${id}`).oninput = renderTasks);
["validationLabelFilter", "validationResultFilter", "validationSearch", "validationLimit"].forEach(id => $(`#${id}`).oninput = loadValidation);
$("#dataFile").onchange = async e => { const file = e.target.files[0]; if (!file) return; try { setImportItems(await parseFile(file), "文件"); $("#fileName").textContent = file.name; toast(`已读取 ${file.name}`); } catch (err) { $("#importProgress").textContent = `解析失败：${err.message}`; toast(err.message, true); } };
$("#excelFile").onchange = e => {
  state.excelFile = e.target.files[0] || null;
  $("#excelFileName").textContent = state.excelFile ? `${state.excelFile.name}（${bytes(state.excelFile.size)}）` : "尚未选择文件";
  $("#previewExcelBtn").disabled = !state.excelFile;
  $("#importExcelBtn").disabled = true;
  $("#excelProgress").textContent = state.excelFile ? "文件已选择，请点击“读取 Excel”。" : "支持 Excel 2007 及以上的 .xlsx 文件";
};
$("#previewExcelBtn").onclick = async () => {
  if (!state.excelFile) return;
  const button = $("#previewExcelBtn"); button.disabled = true; button.textContent = "读取中...";
  try {
    const headerRow = Math.max(1, Number($("#excelHeaderRow").value || 1));
    const data = await api(`/api/data/excel-preview?header_row=${headerRow}`, {
      method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: state.excelFile,
    });
    $("#excelSheet").innerHTML = data.sheets.map(name => `<option value="${esc(name)}" ${name === data.selected_sheet ? "selected" : ""}>${esc(name)}</option>`).join("");
    $("#excelProgress").textContent = `工作表“${data.selected_sheet}”共有 ${num(data.total_rows)} 条数据、${num(data.total_columns)} 列。请设置本次传输数量。`;
    const headers = data.headers.slice(0, 12);
    $("#excelPreview").innerHTML = `<table><thead><tr>${headers.map(h => `<th>${esc(displayText(h))}</th>`).join("")}</tr></thead><tbody>${data.preview_rows.map(row => `<tr>${headers.map((_, i) => `<td>${esc(displayText(row[i] ?? ""))}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
    $("#importExcelBtn").disabled = false; toast("Excel 读取成功");
  } catch (e) { $("#excelProgress").textContent = `读取失败：${e.message}`; toast(e.message, true); }
  finally { button.disabled = false; button.textContent = "读取 Excel"; }
};
$("#importExcelBtn").onclick = async () => {
  if (!state.excelFile) return;
  const button = $("#importExcelBtn"), limit = Math.max(1, Math.min(100000, Number($("#excelLimit").value || 100)));
  const params = new URLSearchParams({
    sheet: $("#excelSheet").value,
    header_row: String(Math.max(1, Number($("#excelHeaderRow").value || 1))),
    start_row: String(Math.max(2, Number($("#excelStartRow").value || 2))),
    limit: String(limit),
    source: `excel:${state.excelFile.name}`,
  });
  button.disabled = true; button.textContent = "传输中..."; $("#excelProgress").textContent = `正在传输最多 ${num(limit)} 条数据，请勿关闭程序。`;
  try {
    const result = await api(`/api/data/import-excel?${params}`, {
      method: "POST", headers: { "Content-Type": "application/octet-stream" }, body: state.excelFile,
    });
    $("#excelProgress").textContent = `传输完成：读取 ${num(result.total)} 条，成功保存 ${num(result.imported)} 条，失败 ${num(result.failed)} 条。`;
    toast(`Excel 成功传输 ${num(result.imported)} 条`);
    await afterBatchCreated(result.batch_id);
    await refreshAll();
  } catch (e) { $("#excelProgress").textContent = `传输失败：${e.message}`; toast(e.message, true); }
  finally { button.disabled = false; button.textContent = "传输所选数据"; }
};
$("#parsePasteBtn").onclick = () => { try { setImportItems(parseTextInput($("#pasteData").value), "粘贴内容"); toast("粘贴内容解析成功"); } catch (e) { $("#importProgress").textContent = `解析失败：${e.message}`; toast(e.message, true); } };
$("#importDataBtn").onclick = importData;
$("#refreshBatchesBtn").onclick = () => loadBatches();
$("#startBatchJudgeBtn").onclick = startBatchJudgement;
$("#pauseBatchJudgeBtn").onclick = pauseBatchJudgement;
$("#resumeBatchJudgeBtn").onclick = resumeBatchJudgement;
$("#retryFailedBatchJudgeBtn").onclick = retryFailedBatchJudgement;
$("#batchSelect").onchange = () => { $("#startBatchJudgeBtn").disabled = !$("#batchSelect").value; $("#retryFailedBatchJudgeBtn").disabled = true; };
$("#clearImportBtn").onclick = () => { state.importItems = []; $("#dataFile").value = ""; $("#pasteData").value = ""; $("#fileName").textContent = "尚未选择文件"; $("#recordPreview").value = "0 条"; $("#importDataBtn").disabled = true; $("#importProgress").textContent = "等待选择文件或粘贴数据"; };
$("#pullConflictsBtn").onclick = async () => { const limit = Math.max(1, Math.min(5000, Number($("#pullLimit").value || 100))); $("#pullResult").textContent = "正在拉取冲突样本..."; try { const r = await api(`/api/preprocess/pull-conflicts?limit=${limit}`, { method: "POST", body: "{}" }); $("#pullResult").textContent = `已拉取并写入 ${num(r.pulled)} 个冲突样本。`; await afterBatchCreated(r.batch_id); await refreshAll(); } catch (e) { $("#pullResult").textContent = `拉取失败：${e.message}`; } };
$("#loadDemoBtn").onclick = loadDemo; $("#loadConflictBtn").onclick = loadConflicts; $("#judgeBtn").onclick = judgeCurrent; $("#clearSampleBtn").onclick = () => { $("#sampleInput").value = ""; };
$("#exportJsonBtn").onclick = () => state.currentReport && download(JSON.stringify(state.currentReport, null, 2), "application/json;charset=utf-8", `${state.currentReport.report_id}.json`);
$("#exportTxtBtn").onclick = () => state.currentReport && download(`恶意 APP 研判报告\n报告编号：${state.currentReport.report_id}\n样本：${state.currentReport.sample?.app_name || state.currentReport.sample?.sample_id}\n结论：${names[state.currentReport.decision?.verdict]}\n风险：${names[state.currentReport.decision?.risk_level]}\n分数：${score(state.currentReport.decision?.final_score)}`, "text/plain;charset=utf-8", `${state.currentReport.report_id}.txt`);
$("#saveHumanReviewBtn").onclick = saveHumanReview;
$("#openTraceBtn").onclick = openCurrentTrace;
$("#exportTrainingDataBtn").onclick = exportTrainingDatasets;
$("#refreshHumanReportsBtn").onclick = loadHumanReviewReports;
$("#humanReportSelect").onchange = pickHumanReviewReport;
window.addEventListener("resize", () => state.overview && drawTrend(state.overview.trend));
boot();
