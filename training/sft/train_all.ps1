param(
    [Parameter(Mandatory = $true)]
    [string]$Model,
    [Parameter(Mandatory = $true)]
    [string]$DatasetManifest,
    [switch]$QLoRA
)

$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$agents = @("static_analysis", "threat_intel", "impersonation", "business_label")

foreach ($agent in $agents) {
    $arguments = @(
        (Join-Path $PSScriptRoot "train.py"),
        "--agent", $agent,
        "--model", $Model,
        "--dataset-manifest", $DatasetManifest
    )
    if ($QLoRA) {
        $arguments += "--qlora"
    }
    & $python @arguments
    if ($LASTEXITCODE -ne 0) {
        throw "SFT 失败：$agent"
    }
}
