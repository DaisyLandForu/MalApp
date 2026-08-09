param(
    [string]$JumpHost = "10.0.11.82",
    [string]$JumpUser = "root",
    [string]$ModelAHost = "10.0.11.55",
    [int]$ModelAPort = 10000,
    [string]$ModelBHost = "10.0.11.83",
    [int]$ModelBPort = 18012,
    [int]$LocalModelAPort = 10000,
    [int]$LocalModelBPort = 18012
)

$ErrorActionPreference = "Stop"

Write-Host "Checking jump host ${JumpHost}:22 ..."
$jumpReady = Test-NetConnection $JumpHost -Port 22 -WarningAction SilentlyContinue
if (-not $jumpReady.TcpTestSucceeded) {
    Write-Host "Cannot connect to ${JumpHost}:22. The 82 jump tunnel cannot be created." -ForegroundColor Red
    Write-Host "Please enable the EasyConnect/bastion SSH resource for 82 and make sure route 10.0.11.0/24 is available." -ForegroundColor Yellow
    Write-Host "You can test with: Test-NetConnection $JumpHost -Port 22"
    exit 2
}

foreach ($port in @($LocalModelAPort, $LocalModelBPort)) {
    $used = Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort $port -ErrorAction SilentlyContinue
    if ($used) {
        Write-Host "Local port 127.0.0.1:$port is already in use. Close the process or choose another port." -ForegroundColor Red
        exit 3
    }
}

$forwardA = "127.0.0.1:{0}:{1}:{2}" -f $LocalModelAPort, $ModelAHost, $ModelAPort
$forwardB = "127.0.0.1:{0}:{1}:{2}" -f $LocalModelBPort, $ModelBHost, $ModelBPort

Write-Host "Creating model tunnel:" -ForegroundColor Cyan
Write-Host ("  Model A: 127.0.0.1:{0} -> {1}:{2}" -f $LocalModelAPort, $ModelAHost, $ModelAPort)
Write-Host ("  Model B: 127.0.0.1:{0} -> {1}:{2}" -f $LocalModelBPort, $ModelBHost, $ModelBPort)
Write-Host "Keep this window open. SSH will ask for the 82 login password." -ForegroundColor Yellow

$sshArgs = @(
    "-N",
    "-o", "ExitOnForwardFailure=yes",
    "-o", "ServerAliveInterval=30",
    "-o", "ServerAliveCountMax=3",
    "-L", $forwardA,
    "-L", $forwardB,
    "$JumpUser@$JumpHost"
)

& ssh @sshArgs
