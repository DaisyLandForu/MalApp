# MalApp 智能研判平台

这是恶意 APP 智能研判项目的本地工作台，包含数据导入、四智能体分析、XGBoost 概率、模型甲/模型乙辩论、批量研判、报告缓存和桌面端打包。

如果你想知道“点哪个按钮会走哪段代码”，先看：

```text
docs/项目使用与调试说明.md
```

常用启动方式：

```powershell
cd C:\Users\啤酒肚\Desktop\工作\test1
.\.venv\Scripts\python.exe -u run.py
```

默认访问：

```text
http://127.0.0.1:8765
```

关键入口：

```text
run.py                         后端 API
web/app.js                     前端交互
engine/pipeline.py             单样本研判主流水线
engine/batch_judgement.py      批量研判
engine/debate_flow.py          双模型辩论
engine/xgb_runtime.py          XGBoost 推理
ml_pipeline/pipeline.py        训练流程
```
