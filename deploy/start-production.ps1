param()

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$envPath = Join-Path $repoRoot ".env"
$liveKitConfig = Join-Path $PSScriptRoot "livekit.generated.yaml"

if (-not (Test-Path -LiteralPath $envPath)) {
    throw "Missing .env. Run deploy/initialize-production.ps1 first."
}
if (-not (Test-Path -LiteralPath $liveKitConfig)) {
    throw "Missing deploy/livekit.generated.yaml. Run deploy/initialize-production.ps1 first."
}
if ((Get-Content -Raw -LiteralPath $envPath) -match 'CHANGE_ME|example\.invalid') {
    throw "Deployment configuration still contains a placeholder."
}

Push-Location $repoRoot
try {
    docker compose --profile production config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose configuration validation failed." }
    docker compose --profile production up -d --build
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose deployment failed." }

    $deadline = (Get-Date).AddMinutes(2)
    $healthy = $false
    do {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:8080/readyz" -TimeoutSec 3
            if ($health.status -eq "ready") { $healthy = $true; break }
        } catch {
            Start-Sleep -Seconds 2
        }
    } while ((Get-Date) -lt $deadline)

    if (-not $healthy) {
        throw "Relay did not become production-ready within two minutes. Check PostgreSQL and Firebase Admin configuration."
    }
    docker compose --profile production ps
    Write-Output "OmniRelay production services are healthy."
} finally {
    Pop-Location
}
