param(
    [Parameter(Mandatory = $true)]
    [string]$CredentialPath,
    [string]$ProjectId = "omnirelay-a3f00"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$sourcePath = (Resolve-Path -LiteralPath $CredentialPath).Path
$secretDirectory = Join-Path $repoRoot ".secrets"
$targetPath = Join-Path $secretDirectory "firebase-admin.json"
$envPath = Join-Path $repoRoot ".env"

if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
    throw "Firebase credential must be a JSON file."
}
if ((Get-Item -LiteralPath $sourcePath).Length -gt 65KB) {
    throw "Firebase credential file is unexpectedly large."
}

$credential = Get-Content -Raw -LiteralPath $sourcePath | ConvertFrom-Json
if ($credential.type -ne "service_account" -or
    $credential.project_id -ne $ProjectId -or
    [string]::IsNullOrWhiteSpace($credential.client_email) -or
    [string]::IsNullOrWhiteSpace($credential.private_key)) {
    throw "Credential is not a valid service-account key for project '$ProjectId'."
}

New-Item -ItemType Directory -Path $secretDirectory -Force | Out-Null
if ($sourcePath -ne $targetPath) {
    Copy-Item -LiteralPath $sourcePath -Destination $targetPath -Force
}

if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "Missing .env. Run the appropriate initialize script first."
}
$lines = [System.Collections.Generic.List[string]]::new()
foreach ($line in Get-Content -LiteralPath $envPath) { $lines.Add([string]$line) }
foreach ($entry in @(
    "FIREBASE_PROJECT_ID=$ProjectId",
    "GOOGLE_APPLICATION_CREDENTIALS=",
    "FIREBASE_SERVICE_ACCOUNT_JSON="
)) {
    $name = $entry.Substring(0, $entry.IndexOf("="))
    $index = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].StartsWith("$name=")) { $index = $i; break }
    }
    if ($index -ge 0) { $lines[$index] = $entry } else { $lines.Add($entry) }
}
[System.IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))

Push-Location $repoRoot
try {
    git check-ignore --quiet -- .secrets/firebase-admin.json
    if ($LASTEXITCODE -ne 0) { throw "Firebase key is not protected by .gitignore." }
} finally {
    Pop-Location
}

Write-Output "Firebase Admin credential configured locally without exposing private key material."
