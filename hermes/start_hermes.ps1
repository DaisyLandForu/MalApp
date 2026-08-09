$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot

if (-not (Get-Command hermes -ErrorAction SilentlyContinue)) {
    throw "Hermes CLI is not installed. Install the official NousResearch/hermes-agent package first."
}

if (-not $env:OPENAI_BASE_URL) {
    throw "OPENAI_BASE_URL is required and must point to your OpenAI-compatible model service."
}
if (-not $env:OPENAI_API_KEY) {
    throw "OPENAI_API_KEY is required."
}

Set-Location -LiteralPath $projectRoot
& hermes
