param(
    [Parameter(Mandatory = $true)]
    [string]$PooledDatabaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$DirectDatabaseUrl
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$envPath = Join-Path $repoRoot ".env"

function Assert-NeonUrl([string]$Value, [bool]$ExpectPooler) {
    $uri = [Uri]$Value
    if ($uri.Scheme -notin @("postgres", "postgresql") -or
        -not $uri.Host.EndsWith(".neon.tech", [StringComparison]::OrdinalIgnoreCase)) {
        throw "Expected an official Neon PostgreSQL connection URL."
    }
    if ($ExpectPooler -and -not $uri.Host.Contains("-pooler")) {
        throw "Runtime DATABASE_URL must use the Neon pooled endpoint."
    }
    if (-not $ExpectPooler -and $uri.Host.Contains("-pooler")) {
        throw "DATABASE_MIGRATION_URL must use the direct Neon endpoint."
    }
    if (-not $uri.Query.Contains("sslmode=require")) {
        throw "Neon URLs must require TLS with sslmode=require."
    }
}

Assert-NeonUrl $PooledDatabaseUrl $true
Assert-NeonUrl $DirectDatabaseUrl $false
if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "Missing .env. Run the appropriate initialize script first."
}

$lines = [System.Collections.Generic.List[string]]::new()
foreach ($line in Get-Content -LiteralPath $envPath) { $lines.Add([string]$line) }
foreach ($entry in @(
    "DATABASE_URL=$PooledDatabaseUrl",
    "DATABASE_MIGRATION_URL=$DirectDatabaseUrl"
)) {
    $name = $entry.Substring(0, $entry.IndexOf("="))
    $index = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i].StartsWith("$name=")) { $index = $i; break }
    }
    if ($index -ge 0) { $lines[$index] = $entry } else { $lines.Add($entry) }
}
[System.IO.File]::WriteAllLines($envPath, $lines, (New-Object System.Text.UTF8Encoding($false)))

Write-Output "Neon runtime and migration connections configured without printing credentials."
