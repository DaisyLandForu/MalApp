param(
    [Parameter(Mandatory = $false)]
    [string]$SshHost = "10.0.11.82",
    [string]$SshUser = "root",
    [string]$JumpHost = "",
    [string]$JumpUser = "root",
    [string]$ModelDir = "/models/Qwen3-14B",
    [string]$OutputJson = "model_b_remote_fingerprint.json",
    [string]$BaselineOutputDir = ""
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$collectorPath = Join-Path $PSScriptRoot "collect_model_b_remote_fingerprint.sh"
$snapshotPath = Join-Path $PSScriptRoot "snapshot_model_b_baseline.py"
$pythonPath = Join-Path $projectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $collectorPath)) {
    throw "Remote collector was not found: $collectorPath"
}
if (-not (Test-Path -LiteralPath $pythonPath)) {
    $pythonPath = "python"
}

$sshArgs = @(
    "-o", "StrictHostKeyChecking=accept-new",
    "-o", "BatchMode=no",
    "-o", "ConnectTimeout=15"
)
if ($JumpHost) {
    $sshArgs += @("-J", "$JumpUser@$JumpHost")
}
$sshArgs += @("$SshUser@$SshHost", "bash -s -- '$ModelDir'")

Write-Host "Starting read-only model fingerprint collection on $SshUser@$SshHost." -ForegroundColor Cyan
if ($JumpHost) {
    Write-Host "SSH jump host: $JumpUser@$JumpHost" -ForegroundColor Cyan
}
Write-Host "If SSH requests a password, enter it only in this terminal. It will not be saved." -ForegroundColor Yellow

$collector = (Get-Content -LiteralPath $collectorPath -Raw -Encoding UTF8) -replace "`r", ""
$remoteOutput = $collector | & ssh @sshArgs
if ($LASTEXITCODE -ne 0) {
    throw "Remote SSH collection failed with exit code $LASTEXITCODE"
}

try {
    $parsed = $remoteOutput | ConvertFrom-Json
} catch {
    throw "The remote output is not valid JSON. Run this on the host/container that owns the vLLM process and ensure python3 is installed."
}

$outputPath = if ([System.IO.Path]::IsPathRooted($OutputJson)) {
    $OutputJson
} else {
    Join-Path $projectRoot $OutputJson
}
$parsed | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $outputPath -Encoding UTF8
Write-Host "Remote fingerprint saved: $outputPath" -ForegroundColor Green

$snapshotArgs = @($snapshotPath, "--remote-manifest", $outputPath)
if ($BaselineOutputDir) {
    $snapshotArgs += @("--output-dir", $BaselineOutputDir)
}
& $pythonPath @snapshotArgs
if ($LASTEXITCODE -ne 0) {
    throw "Local baseline merge failed with exit code $LASTEXITCODE"
}

Write-Host "Collection and merge completed. Check remote_fingerprint_validation.complete in the new manifest." -ForegroundColor Green
