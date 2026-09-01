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
    $composeArguments = @("compose", "-f", "compose.yaml")
    $firebaseKey = Join-Path $repoRoot ".secrets\firebase-admin.json"
    if (Test-Path -LiteralPath $firebaseKey -PathType Leaf) {
        $composeArguments += @("-f", "compose.firebase.yaml")
    }
    $databaseUrl = Get-Content -LiteralPath $envPath |
        Where-Object { $_.StartsWith("DATABASE_URL=") } |
        Select-Object -First 1
    $usingNeon = $databaseUrl -and $databaseUrl.Substring("DATABASE_URL=".Length).Contains(".neon.tech")
    if ($usingNeon) {
        $composeArguments += @("-f", "compose.neon.yaml")
    }
    $composeArguments += @("--profile", "production")

    docker @composeArguments config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose configuration validation failed." }
    if ($usingNeon) {
        docker @composeArguments up -d --build --no-deps backend livekit coturn caddy
    } else {
        docker @composeArguments up -d --build
    }
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
    docker @composeArguments ps
    Write-Output "OmniRelay production services are healthy."
} finally {
    Pop-Location
}
