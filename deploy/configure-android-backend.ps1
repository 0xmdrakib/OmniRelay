param(
    [Parameter(Mandatory = $true)]
    [string]$BackendUrl
)

$ErrorActionPreference = "Stop"
$uri = [Uri]$BackendUrl
if ($uri.Scheme -notin @("http", "https") -or [string]::IsNullOrWhiteSpace($uri.Host)) {
    throw "BackendUrl must be an absolute HTTP or HTTPS URL."
}
$parsedAddress = $null
if ($uri.Scheme -eq "http" -and
    $uri.Host -ne "localhost" -and
    $uri.Host -ne "127.0.0.1" -and
    -not [System.Net.IPAddress]::TryParse($uri.Host, [ref]$parsedAddress)) {
    throw "Plain HTTP is accepted only for local development hosts."
}

$gradleDirectory = Join-Path $env:USERPROFILE ".gradle"
$propertiesPath = Join-Path $gradleDirectory "gradle.properties"
New-Item -ItemType Directory -Path $gradleDirectory -Force | Out-Null
$lines = [System.Collections.Generic.List[string]]::new()
if (Test-Path -LiteralPath $propertiesPath) {
    foreach ($line in Get-Content -LiteralPath $propertiesPath) { $lines.Add([string]$line) }
}
$name = "OMNIRELAY_BACKEND_URL"
$entry = "$name=$($BackendUrl.TrimEnd('/'))"
$index = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i].StartsWith("$name=")) { $index = $i; break }
}
if ($index -ge 0) { $lines[$index] = $entry } else { $lines.Add($entry) }
[System.IO.File]::WriteAllLines($propertiesPath, $lines, (New-Object System.Text.UTF8Encoding($false)))

Write-Output "Android builds are configured for the selected backend without printing other Gradle properties."
