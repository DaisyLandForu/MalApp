$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:MALAPP_USE_LOCAL_QWEN = "1"
$env:MALAPP_QWEN_MODEL = "Qwen/Qwen2.5-0.5B-Instruct"
$env:MALAPP_DEBATE_ROUNDS = "2"
.\.venv\Scripts\python.exe -u run.py
