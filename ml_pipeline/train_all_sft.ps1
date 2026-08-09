param(
    [Parameter(Mandatory = $true)]
    [string]$Model,
    [switch]$QLoRA
)

$ErrorActionPreference = "Stop"
$python = Join-Path $PSScriptRoot "..\.venv\Scripts\python.exe"
$agents = @("static_analysis", "threat_intel", "impersonation", "business_label")

foreach ($agent in $agents) {
    $arguments = @(
        (Join-Path $PSScriptRoot "train_sft.py"),
        "--agent", $agent,
        "--model", $Model
    )
    if ($QLoRA) {
        $arguments += "--qlora"
    }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "SFT 失败：$agent"
    }
}
