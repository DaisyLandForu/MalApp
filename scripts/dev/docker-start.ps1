$ErrorActionPreference = "Stop"
$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location -LiteralPath $projectRoot

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker CLI is not installed."
}

docker info | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Docker Engine is not running. Start Docker Desktop and retry."
}

if (-not (Test-Path -LiteralPath ".env") -and (Test-Path -LiteralPath ".env.docker.example")) {
    Copy-Item -LiteralPath ".env.docker.example" -Destination ".env"
    Write-Host "Created .env from .env.docker.example. Review model API settings before production use."
}

docker compose up --build -d
docker compose ps
$publishedPort = if ($env:MALAPP_PUBLISHED_PORT) { $env:MALAPP_PUBLISHED_PORT } else { "8765" }
Write-Host "Malicious APP judgement platform: http://127.0.0.1:$publishedPort"
