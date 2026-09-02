function Get-DotEnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $prefix = "$Name="
    $line = Get-Content -LiteralPath $Path |
        Where-Object { $_.StartsWith($prefix, [StringComparison]::Ordinal) } |
        Select-Object -Last 1
    if ([string]::IsNullOrWhiteSpace($line)) { return $null }
    return $line.Substring($prefix.Length).Trim()
}

function ConvertTo-NeonVerifyFullUrl {
    param([Parameter(Mandatory = $true)][string]$Value)

    return [regex]::Replace(
        $Value,
        '(?i)([?&])sslmode=require(?=(&|$))',
        '$1sslmode=verify-full'
    )
}

function Assert-NeonDatabasePair {
    param(
        [Parameter(Mandatory = $true)][string]$PooledDatabaseUrl,
        [Parameter(Mandatory = $true)][string]$DirectDatabaseUrl
    )

    function Assert-NeonUrl([string]$Value, [bool]$ExpectPooler, [string]$VariableName) {
        $uri = $null
        if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri) -or
            $uri.Scheme -notin @("postgres", "postgresql") -or
            -not $uri.Host.EndsWith(".neon.tech", [StringComparison]::OrdinalIgnoreCase)) {
            throw "$VariableName must be an official Neon PostgreSQL connection URL."
        }
        if ($ExpectPooler -and -not $uri.Host.Contains("-pooler")) {
            throw "DATABASE_URL must use the Neon pooled endpoint."
        }
        if (-not $ExpectPooler -and $uri.Host.Contains("-pooler")) {
            throw "DATABASE_MIGRATION_URL must use the direct Neon endpoint."
        }
        if ($uri.UserInfo -notmatch '.+:.+' -or $uri.AbsolutePath -eq "/") {
            throw "$VariableName must include a database role, password, and database name."
        }
        if ($uri.Query -notmatch '(?i)(?:^|[?&])sslmode=(?:require|verify-full)(?:&|$)') {
            throw "$VariableName must enforce TLS certificate validation."
        }
        if ($uri.Query -notmatch '(?i)(?:^|[?&])channel_binding=require(?:&|$)') {
            throw "$VariableName must enforce SCRAM channel binding."
        }
        return $uri
    }

    $pooled = Assert-NeonUrl $PooledDatabaseUrl $true "DATABASE_URL"
    $direct = Assert-NeonUrl $DirectDatabaseUrl $false "DATABASE_MIGRATION_URL"
    $normalizedPooledHost = $pooled.Host.Replace("-pooler", "")
    if (-not $normalizedPooledHost.Equals($direct.Host, [StringComparison]::OrdinalIgnoreCase) -or
        -not $pooled.AbsolutePath.Equals($direct.AbsolutePath, [StringComparison]::Ordinal) -or
        -not $pooled.UserInfo.Split(':')[0].Equals($direct.UserInfo.Split(':')[0], [StringComparison]::Ordinal)) {
        throw "Runtime and migration URLs must target the same Neon project, database, and role."
    }
}
