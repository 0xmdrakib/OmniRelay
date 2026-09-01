param()

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$envPath = Join-Path $repoRoot ".env"
$liveKitConfig = Join-Path $PSScriptRoot "livekit.generated.yaml"

if (-not (Test-Path -LiteralPath $envPath)) {
    throw "Missing .env. Run deploy/initialize-local.ps1 first."
}
if (-not (Test-Path -LiteralPath $liveKitConfig)) {
    throw "Missing deploy/livekit.generated.yaml. Run deploy/initialize-local.ps1 first."
}
if ((Get-Content -Raw -LiteralPath $envPath) -match "CHANGE_ME|example\.invalid") {
    throw "Local configuration still contains a placeholder."
}
if ((Get-Content -Raw -LiteralPath $liveKitConfig) -match "REPLACE_WITH_") {
    throw "Generated LiveKit configuration still contains a placeholder."
}

Push-Location $repoRoot
try {
    $composeArguments = @("compose", "-f", "compose.yaml", "-f", "compose.local.yaml")
    $firebaseKey = Join-Path $repoRoot ".secrets\firebase-admin.json"
    if (Test-Path -LiteralPath $firebaseKey -PathType Leaf) {
        $composeArguments += @("-f", "compose.firebase.yaml")
        Write-Output "Firebase Admin key detected; account registration and push are enabled."
    }
    $databaseUrl = Get-Content -LiteralPath $envPath |
        Where-Object { $_.StartsWith("DATABASE_URL=") } |
        Select-Object -First 1
    $usingNeon = $databaseUrl -and $databaseUrl.Substring("DATABASE_URL=".Length).Contains(".neon.tech")
    if ($usingNeon) {
        $composeArguments += @("-f", "compose.neon.yaml")
        Write-Output "Neon database configuration detected; local PostgreSQL will stay stopped."
    }

    docker @composeArguments config --quiet
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose configuration validation failed." }

    if ($usingNeon) {
        docker @composeArguments up -d --build --no-deps backend livekit coturn
    } else {
        docker @composeArguments up -d --build postgres backend livekit coturn
    }
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose local startup failed." }

    $deadline = (Get-Date).AddMinutes(3)
    $healthy = $false
    do {
        try {
            $health = Invoke-RestMethod "http://127.0.0.1:8080/healthz" -TimeoutSec 3
            if ($health.status -eq "ok") { $healthy = $true; break }
        } catch {
            Start-Sleep -Seconds 2
        }
    } while ((Get-Date) -lt $deadline)

    if (-not $healthy) {
        docker @composeArguments ps
        docker @composeArguments logs --tail 100 backend postgres
        throw "Local relay did not become healthy within three minutes."
    }

    docker @composeArguments ps
    Write-Output "OmniRelay local Docker services are healthy."
    if (!(Test-Path -LiteralPath $firebaseKey -PathType Leaf)) {
        Write-Output "Firebase Admin remains disabled until a local credential is configured."
    }
} finally {
    Pop-Location
}
