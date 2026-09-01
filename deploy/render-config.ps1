param(
    [Parameter(Mandatory = $true)][string]$PublicHost,
    [Parameter(Mandatory = $true)][string]$LiveKitApiKey,
    [Parameter(Mandatory = $true)][string]$LiveKitApiSecret,
    [Parameter(Mandatory = $true)][string]$TurnSharedSecret,
    [string]$NodeIp = $PublicHost,
    [bool]$UseExternalIp = $true
)

$templatePath = Join-Path $PSScriptRoot "livekit.yaml"
$outputPath = Join-Path $PSScriptRoot "livekit.generated.yaml"
$content = Get-Content -Raw -LiteralPath $templatePath
$content = $content.Replace("REPLACE_WITH_PUBLIC_HOST", $PublicHost)
$content = $content.Replace("REPLACE_WITH_LIVEKIT_API_KEY", $LiveKitApiKey)
$content = $content.Replace("REPLACE_WITH_LIVEKIT_API_SECRET", $LiveKitApiSecret)
$content = $content.Replace("REPLACE_WITH_TURN_SHARED_SECRET", $TurnSharedSecret)
$content = $content.Replace("REPLACE_WITH_NODE_IP", $NodeIp)
$content = $content.Replace("REPLACE_WITH_USE_EXTERNAL_IP", $UseExternalIp.ToString().ToLowerInvariant())
Set-Content -LiteralPath $outputPath -Value $content -NoNewline
Write-Output $outputPath
