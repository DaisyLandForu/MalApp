param(
    [string]$HermesHome = "$HOME\.hermes",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourceSkills = Join-Path $PSScriptRoot "skills"
$targetSkills = Join-Path $HermesHome "skills"
$targetSoul = Join-Path $HermesHome "SOUL.md"
$mcpOutput = Join-Path $HermesHome "mcp-malapp.json"

New-Item -ItemType Directory -Force -Path $targetSkills | Out-Null

Get-ChildItem -LiteralPath $sourceSkills -Directory | ForEach-Object {
    $destination = Join-Path $targetSkills $_.Name
    if ((Test-Path -LiteralPath $destination) -and -not $Force) {
        throw "Skill already exists: $destination. Use -Force to replace it."
    }
    if (Test-Path -LiteralPath $destination) {
        Remove-Item -LiteralPath $destination -Recurse -Force
    }
    Copy-Item -LiteralPath $_.FullName -Destination $destination -Recurse
}

if ((Test-Path -LiteralPath $targetSoul) -and -not $Force) {
    $backup = "$targetSoul.malapp-backup"
    Copy-Item -LiteralPath $targetSoul -Destination $backup -Force
    Write-Host "Existing SOUL.md backed up to $backup"
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "SOUL.md") -Destination $targetSoul -Force

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$server = Join-Path $PSScriptRoot "mcp_server.py"
$mcp = @{
    mcpServers = @{
        "malapp-analysis" = @{
            command = $python
            args = @($server)
            env = @{
                PYTHONPATH = $projectRoot
                PYTHONUTF8 = "1"
            }
        }
    }
}
$mcp | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $mcpOutput -Encoding utf8

Write-Host "Installed malicious-APP skills into $targetSkills"
Write-Host "Installed supervisor role into $targetSoul"
Write-Host "Generated MCP definition at $mcpOutput"
Write-Host "Register that MCP definition in Hermes, then select the malapp-supervisor skill."
