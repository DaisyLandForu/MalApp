param(
    [string]$ModelAUrl = "http://127.0.0.1:10000/v1",
    [string]$ModelBUrl = "http://127.0.0.1:18012/v1"
)

$ErrorActionPreference = "Continue"

$targets = @(
    @{ Name = "model_a"; Url = $ModelAUrl },
    @{ Name = "model_b"; Url = $ModelBUrl }
)

foreach ($target in $targets) {
    $modelsUrl = $target.Url.TrimEnd("/") + "/models"
    Write-Host "Checking $($target.Name): $modelsUrl"
    try {
        $response = Invoke-RestMethod -Uri $modelsUrl -TimeoutSec 15
        Write-Host "$($target.Name) is available." -ForegroundColor Green
        $response | ConvertTo-Json -Depth 6
    } catch {
        Write-Host "$($target.Name) is unavailable: $($_.Exception.Message)" -ForegroundColor Red
    }
}
