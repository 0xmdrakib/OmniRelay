param(
    [Parameter(Mandatory = $true)]
    [string]$PooledDatabaseUrl,
    [Parameter(Mandatory = $true)]
    [string]$DirectDatabaseUrl
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path $PSScriptRoot -Parent
$envPath = Join-Path $repoRoot ".env"
. (Join-Path $PSScriptRoot "neon-config.ps1")
$PooledDatabaseUrl = ConvertTo-NeonVerifyFullUrl $PooledDatabaseUrl
$DirectDatabaseUrl = ConvertTo-NeonVerifyFullUrl $DirectDatabaseUrl
Assert-NeonDatabasePair $PooledDatabaseUrl $DirectDatabaseUrl
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
