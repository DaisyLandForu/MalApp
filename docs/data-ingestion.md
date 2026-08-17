# 数据接入与预处理功能实现说明

本文档对应“数据接入与预处理”功能点，说明 MalApp 当前已经实现的功能、对应代码位置和实现边界。

## 1. 冲突样本自动拉取功能

状态：已实现本地 MVP。

代码：

```text
malapp/data_import/preprocess.py
apps/server/main.py
```

核心函数：

```python
pull_conflict_samples(limit=1000)
```

实现方式：

1. 从 SQLite 表 `engine_detections` 中读取 360 与 cm 的共同 MD5。
2. 判断两个引擎是否存在冲突：
   - 分数差 `>= 35`
   - 或检测类型不一致
3. 自动生成冲突样本特征记录。
4. 写入 `sample_features`。
5. 写入 `sample_tasks` 优先级队列。

本地 API：

```text
POST /api/preprocess/pull-conflicts?limit=1000
```

当前已执行一次自动拉取：

```text
engine_conflict_auto_pull: 1000 条
```

实现边界：

当前是从本地 SQLite 调度中心拉取，不是外部高可用 API 网关。

## 2. 异构特征数据流式解析引擎功能

状态：已实现基础版。

代码：

```text
malapp/data_import/preprocess.py
```

核心函数：

```python
parse_feature_payload(payload, payload_format)
```

支持格式：

```text
json
xml
protobuf/proto
```

说明：

- JSON：直接解析为 dict。
- XML：使用 `ElementTree` 解析为 dict。
- Protobuf：当前 MVP 在没有 `.proto` schema 的情况下保存为 hex/text 元数据；生产环境需要接入具体 Protobuf Message schema。

本地 API：

```text
POST /api/preprocess/ingest?format=json&source=api_gateway
POST /api/preprocess/ingest?format=xml&source=api_gateway
POST /api/preprocess/ingest?format=protobuf&source=api_gateway
```

## 3. 增量特征字段动态注册功能

状态：已实现。

代码：

```text
malapp/data_import/preprocess.py
```

数据库表：

```text
feature_registry
```

实现方式：

1. 每次接收新字段时记录原始字段名。
2. 根据字段映射表转换成标准字段名。
3. 保存字段来源、首次出现时间、最后出现时间。
4. 新字段不需要改数据库表结构即可入库。

字段映射配置：

```text
data/field_mapping.json
```

新增的武汉接口字段、人工标注字段、通联字段已经加入映射。

当前字段注册统计：

```text
feature_registry: 186 个字段
```

## 4. 字段归一化功能

状态：已实现。

代码：

```text
malapp/data_import/preprocess.py
malapp/application/judgement.py
data/field_mapping.json
```

核心函数：

```python
normalize_feature_record()
normalize_sample()
```

实现内容：

1. 将不同来源字段映射到统一 schema。
2. 清理 `nan`、空值、不可见字符。
3. 将权限、插件、URL、域名、IP 等多值字段转成列表。
4. 将 fakeApp、isFraud 等字段转成布尔值。

示例：

```text
appName -> app_name
pkgName -> package_name
fakeApp -> fake_app
fraudTypeInfo -> fraud_type_info
subUrls -> sub_urls
domainType -> domain_type
人工审核结果 -> human_label
```

## 5. 威胁指标结构化提取与封装功能

状态：已实现基础版。

代码：

```text
malapp/data_import/preprocess.py
malapp/application/judgement.py
```

核心函数：

```python
build_feature_packages()
extract_iocs()
```

输出两个结构化对象：

```text
static_feature_package
network_ioc_package
```

`static_feature_package` 包含：

```text
样本身份
签名
权限
插件
加壳/混淆
仿冒字段
涉诈业务标签
```

`network_ioc_package` 包含：

```text
IOC 列表
URL
域名
顶级域名
IP
URL 来源
域名类型
是否涉诈 URL
CDN 标记
白名单标记
国家/省份/城市/运营商
```

当前报告中已经输出：

```text
report.preprocess.static_feature_package
report.preprocess.network_ioc_package
```

## 6. 研判任务优先级调度队列功能

状态：已实现本地 MVP。

代码：

```text
malapp/data_import/preprocess.py
apps/server/main.py
```

数据库表：

```text
sample_tasks
```

核心函数：

```python
compute_priority()
next_tasks(limit=20)
```

优先级依据：

```text
engine_conflict：引擎冲突
manual_label：人工标注
fake_app：仿冒
fraud_business：涉诈业务标签
fraud_url：涉诈通联
many_iocs：IOC 数量较多
```

本地 API：

```text
GET /api/tasks/next?limit=20
```

当前队列统计：

```text
sample_tasks: 8217
```

实现边界：

当前是 SQLite 优先级队列，不是 Redis SortedSet。

## 7. 样本去重与研判结果快速缓存功能

状态：已实现本地 MVP。

代码：

```text
malapp/data_import/preprocess.py
malapp/application/judgement.py
```

去重方式：

```text
sample_features 使用 PRIMARY KEY(md5, source, content_hash)
manual_labels 使用 md5 主键
sample_tasks 使用 md5 主键
```

缓存表：

```text
report_cache
```

实现方式：

1. 对样本内容生成 cache key。
2. 短期内重复研判同一内容时直接返回缓存报告。
3. 默认缓存 TTL 为 24 小时。

布隆过滤器：

```text
sample_seen.bloom
```

已实现本地布隆过滤器逻辑；如果中文路径下文件写入失败，会自动跳过，SQLite 唯一键仍保证最终去重。

实现边界：

当前未接入真实 Redis。后续生产部署可以将 `report_cache` 和 `sample_tasks` 替换为 Redis/SortedSet。

## 8. 特征数据持久化存储功能

状态：已实现。

数据库：

```text
data/mvp.db
```

主要表：

```text
engine_detections
app_md5_labels
app_md5_api_cache
feature_registry
sample_features
sample_tasks
report_cache
manual_labels
judgements
```

当前新增数据导入结果：

```text
sample_features: 51586
manual_labels: 7221
feature_registry: 186
sample_tasks: 8217
```

新增来源：

```text
APP研判字段_第001批_共001批_20260608_164012.xlsx
冲突样本分析_人工标注_分身规则更新.xlsx
360/cm 自动冲突拉取
```

实现边界：

当前用 SQLite 作为本地时序/持久化数据库。生产环境可迁移到 PostgreSQL、ClickHouse 或时序数据库。

## 9. 新增导入脚本

代码：

```text
scripts/data/import_feature_workbooks.py
```

功能：

```text
导入 APP 研判字段表
导入人工标注冲突表
自动生成特征包
注册字段
写入优先级任务
写入人工标签
```

运行命令：

```bash
python -m scripts.data.import_feature_workbooks
```

单独导入 APP 研判字段：

```bash
python -m scripts.data.import_feature_workbooks --only app
```

单独导入人工标注冲突表：

```bash
python -m scripts.data.import_feature_workbooks --only conflict
```

## 10. 当前完成度总结

已实现：

```text
冲突样本自动拉取
JSON/XML/Protobuf 接入入口
动态字段注册
字段归一化
威胁指标提取
静态特征包
网络 IOC 包
优先级任务队列
样本去重
研判结果缓存
特征持久化存储
人工标注导入
武汉接口批量结果导入
```

MVP 实现而非生产级实现：

```text
API 网关：当前是本地 HTTP API
Redis：当前是 SQLite 缓存/队列
时序数据库：当前是 SQLite + created_at
Protobuf：当前支持入口与兜底保存，未绑定具体 .proto schema
```
