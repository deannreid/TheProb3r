# ================================================================
# Module  : Integrations.NIST.psm1
# Purpose : NVD / CPE / CVE enrichment integration
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncEnsureCacheRoot {
    param([Parameter(Mandatory=$true)][string]$CacheRoot)
    if (-not (Test-Path -LiteralPath $CacheRoot)) {
        New-Item -ItemType Directory -Path $CacheRoot -Force | Out-Null
    }
}

function fncConvertToHashtableSafe {
    param($Obj)

    $ht = @{}
    if ($null -eq $Obj) { return $ht }

    if ($Obj -is [hashtable]) { return $Obj }

    try {
        foreach ($p in $Obj.PSObject.Properties) {
            $ht[$p.Name] = $p.Value
        }
    } catch { }

    return $ht
}

function fncUtcParseSafe {
    param([string]$Iso)
    try {
        if ([string]::IsNullOrWhiteSpace($Iso)) { return $null }
        return ([datetime]::Parse($Iso)).ToUniversalTime()
    } catch { return $null }
}

function fncIsExpired {
    param(
        [string]$RetrievedUtcIso,
        [int]$MaxAgeHours
    )

    if ($MaxAgeHours -le 0) { return $false }
    $dt = fncUtcParseSafe $RetrievedUtcIso
    if ($null -eq $dt) { return $true }

    $age = (New-TimeSpan -Start $dt -End (Get-Date).ToUniversalTime()).TotalHours
    return ($age -gt $MaxAgeHours)
}

# ------------------------------------------------------------
# Internal: URL cache (per-URL entries with expiry)
# File schema:
# {
#   RetrievedUtc: "...",
#   UrlToEntry: {
#       "<url>": { RetrievedUtc: "...", Payload: <object> }
#   }
# }
# Legacy support:
# { UrlToPayload: { "<url>": <object> } }
# ------------------------------------------------------------
function fncGetNvdUrlCache {
    param(
        [Parameter(Mandatory=$true)][string]$CacheRoot
    )

    fncEnsureCacheRoot -CacheRoot $CacheRoot
    $path = Join-Path $CacheRoot "NvdUrlCache.json"

    $c = fncReadJsonFileSafe -Path $path -Default $null

    if ($null -eq $c) {
        $c = [pscustomobject]@{
            RetrievedUtc = fncGetUtcNowIso
            UrlToEntry   = @{}
        }
        fncWriteJsonFileSafe -Path $path -Object $c -Depth 15 | Out-Null
        return $c
    }

    if ((fncSafeHasProp $c "UrlToEntry") -and ($null -ne $c.UrlToEntry)) {
        return $c
    }

    if (fncSafeHasProp $c "UrlToPayload") {
        $legacy = fncConvertToHashtableSafe (fncSafeGetProp $c "UrlToPayload" $null)
        $map = @{}
        foreach ($k in $legacy.Keys) {
            $map[$k] = [pscustomobject]@{
                RetrievedUtc = fncGetUtcNowIso
                Payload      = $legacy[$k]
            }
        }

        $c = [pscustomobject]@{
            RetrievedUtc = fncGetUtcNowIso
            UrlToEntry   = $map
        }

        fncWriteJsonFileSafe -Path $path -Object $c -Depth 15 | Out-Null
        return $c
    }

    $c = [pscustomobject]@{
        RetrievedUtc = fncGetUtcNowIso
        UrlToEntry   = @{}
    }
    fncWriteJsonFileSafe -Path $path -Object $c -Depth 15 | Out-Null
    return $c
}

function fncSaveNvdUrlCache {
    param(
        [Parameter(Mandatory=$true)][string]$CacheRoot,
        [Parameter(Mandatory=$true)]$Cache
    )

    fncEnsureCacheRoot -CacheRoot $CacheRoot
    $path = Join-Path $CacheRoot "NvdUrlCache.json"
    fncWriteJsonFileSafe -Path $path -Object $Cache -Depth 20 | Out-Null
}

# ------------------------------------------------------------
# Internal: Rate limit / backoff aware GET wrapper
# - Handles 429 / 503 and honours Retry-After when present
# - Exponential backoff with jitter
# ------------------------------------------------------------
function fncInvokeNvdApi {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$CacheRoot,

        [string]$ApiKey,
        [int]$DelayMs = 900,

        [switch]$UseCache,
        [int]$CacheMaxAgeHours = 72,

        [int]$MaxRetries = 6,
        [int]$BaseBackoffMs = 750
    )

    $cache = $null
    $map   = @{}

    if ($UseCache) {
        $cache = fncGetNvdUrlCache -CacheRoot $CacheRoot
        $map = fncConvertToHashtableSafe (fncSafeGetProp $cache "UrlToEntry" $null)

        if ($map.ContainsKey($Url)) {
            $entry = $map[$Url]
            $ts = fncToSafeString (fncSafeGetProp $entry "RetrievedUtc" "")
            if (-not (fncIsExpired -RetrievedUtcIso $ts -MaxAgeHours $CacheMaxAgeHours)) {
                return (fncSafeGetProp $entry "Payload" $null)
            }
        }
    }

    $headers = @{}
    if (-not [string]::IsNullOrWhiteSpace($ApiKey)) {
        $headers["apiKey"] = $ApiKey
    }

    # Gentle spacing between calls (NVD is touchy)
    if ($DelayMs -gt 0) { Start-Sleep -Milliseconds $DelayMs }

    $attempt = 0
    while ($attempt -le $MaxRetries) {

        try {
            $payload = Invoke-RestMethod -Uri $Url -Headers $headers -Method GET -ErrorAction Stop

            if ($UseCache) {
                try {
                    if ($null -eq $cache) {
                        $cache = fncGetNvdUrlCache -CacheRoot $CacheRoot
                    }

                    $map = fncConvertToHashtableSafe (fncSafeGetProp $cache "UrlToEntry" $null)
                    if ($null -eq $map) { $map = @{} }

                    $map[$Url] = [pscustomobject]@{
                        RetrievedUtc = fncGetUtcNowIso
                        Payload      = $payload
                    }

                    $cache.UrlToEntry   = $map
                    $cache.RetrievedUtc = fncGetUtcNowIso

                    fncSaveNvdUrlCache -CacheRoot $CacheRoot -Cache $cache
                } catch { }
            }

            return $payload
        }
        catch {

            $attempt++

            # Try to detect HTTP status + Retry-After
            $status = $null
            $retryAfterSec = $null

            try {
                $resp = $_.Exception.Response
                if ($null -ne $resp) {
                    $status = [int]$resp.StatusCode
                    try {
                        $ra = $resp.Headers["Retry-After"]
                        if (-not [string]::IsNullOrWhiteSpace($ra)) {
                            # Retry-After can be seconds OR an HTTP date
                            if ($ra -match '^\d+$') {
                                $retryAfterSec = [int]$ra
                            } else {
                                $dt = [datetime]::Parse($ra).ToUniversalTime()
                                $retryAfterSec = [int][math]::Ceiling((New-TimeSpan -Start (Get-Date).ToUniversalTime() -End $dt).TotalSeconds)
                                if ($retryAfterSec -lt 0) { $retryAfterSec = 0 }
                            }
                        }
                    } catch { }
                }
            } catch { }

            $isRetryable = $false
            if ($status -in 429, 503) { $isRetryable = $true }

            if (-not $isRetryable -or $attempt -gt $MaxRetries) {
                return $null
            }

            # Backoff: prefer Retry-After; else exponential with jitter
            if ($null -ne $retryAfterSec) {
                Start-Sleep -Seconds $retryAfterSec
            }
            else {
                $pow = [math]::Pow(2, [math]::Min($attempt, 6))
                $sleepMs = [int]($BaseBackoffMs * $pow)
                $jitter = Get-Random -Minimum 0 -Maximum 250
                Start-Sleep -Milliseconds ($sleepMs + $jitter)
            }
        }
    }

    return $null
}

function fncNormaliseToken {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $t = $Text.ToLowerInvariant()
    $t = $t -replace '\(.*?\)', ''
    $t = $t -replace '[^a-z0-9\.\+\- ]', ' '
    $t = $t -replace '\s+', ' '
    return $t.Trim()
}

function fncScoreCpeCandidate {
    param(
        [string]$Vendor,
        [string]$Product,
        [string]$CpeName
    )

    $v = (fncNormaliseToken $Vendor)
    $p = (fncNormaliseToken $Product)
    $c = (fncToSafeString $CpeName).ToLowerInvariant()

    $score = 0
    if (-not [string]::IsNullOrWhiteSpace($v) -and $c -like ("*:{0}:*" -f $v.Replace(" ","_"))) { $score += 30 }
    if (-not [string]::IsNullOrWhiteSpace($p) -and $c -like ("*:{0}:*" -f $p.Replace(" ","_"))) { $score += 50 }

    if (-not [string]::IsNullOrWhiteSpace($v) -and $c -like ("*{0}*" -f $v.Replace(" ","_"))) { $score += 10 }
    if (-not [string]::IsNullOrWhiteSpace($p) -and $c -like ("*{0}*" -f $p.Replace(" ","_"))) { $score += 10 }

    return $score
}

# ------------------------------------------------------------
# Internal: CPE candidates cache with expiry
# File schema:
# {
#   RetrievedUtc: "...",
#   KeywordToEntry: {
#       "<vendor product>": { RetrievedUtc: "...", Cpes: [ "cpe:2.3:..." ] }
#   }
# }
# Legacy support:
# { KeywordToCpes: { "<keyword>": [ "cpe..." ] } }
# ------------------------------------------------------------
function fncGetCpeCandidatesCache {
    param([Parameter(Mandatory=$true)][string]$CacheRoot)

    fncEnsureCacheRoot -CacheRoot $CacheRoot
    $path = Join-Path $CacheRoot "CpeCandidates.json"

    $c = fncReadJsonFileSafe -Path $path -Default $null

    if ($null -eq $c) {
        $c = [pscustomobject]@{
            RetrievedUtc   = fncGetUtcNowIso
            KeywordToEntry = @{}
        }
        fncWriteJsonFileSafe -Path $path -Object $c -Depth 15 | Out-Null
        return $c
    }

    if (fncSafeHasProp $c "KeywordToEntry") {
        return $c
    }

    if (fncSafeHasProp $c "KeywordToCpes") {
        $legacy = fncConvertToHashtableSafe (fncSafeGetProp $c "KeywordToCpes" $null)
        $map = @{}
        foreach ($k in $legacy.Keys) {
            $map[$k] = [pscustomobject]@{
                RetrievedUtc = fncGetUtcNowIso
                Cpes         = @($legacy[$k])
            }
        }

        $c = [pscustomobject]@{
            RetrievedUtc   = fncGetUtcNowIso
            KeywordToEntry = $map
        }

        fncWriteJsonFileSafe -Path $path -Object $c -Depth 15 | Out-Null
        return $c
    }

    # Unknown shape -> reset safely
    $c = [pscustomobject]@{
        RetrievedUtc   = fncGetUtcNowIso
        KeywordToEntry = @{}
    }
    fncWriteJsonFileSafe -Path $path -Object $c -Depth 15 | Out-Null
    return $c
}

function fncSaveCpeCandidatesCache {
    param(
        [Parameter(Mandatory=$true)][string]$CacheRoot,
        [Parameter(Mandatory=$true)]$Cache
    )

    fncEnsureCacheRoot -CacheRoot $CacheRoot
    $path = Join-Path $CacheRoot "CpeCandidates.json"
    fncWriteJsonFileSafe -Path $path -Object $Cache -Depth 20 | Out-Null
}

function fncResolveCpeCandidates {
    param(
        [Parameter(Mandatory=$true)][string]$Vendor,
        [Parameter(Mandatory=$true)][string]$Product,
        [Parameter(Mandatory=$true)][string]$CacheRoot,

        [string]$ApiKey,

        [int]$MaxCandidates = 5,
        [int]$DelayMs = 900,

        [int]$CacheMaxAgeHours = 168  # 7 days
    )

    $keyword = ("{0} {1}" -f $Vendor, $Product).Trim()
    if ([string]::IsNullOrWhiteSpace($keyword)) { return @() }

    # Cache lookup
    $cache = fncGetCpeCandidatesCache -CacheRoot $CacheRoot
    $map   = fncConvertToHashtableSafe (fncSafeGetProp $cache "KeywordToEntry" $null)

    if ($map.ContainsKey($keyword)) {
        $entry = $map[$keyword]
        $ts = fncToSafeString (fncSafeGetProp $entry "RetrievedUtc" "")
        if (-not (fncIsExpired -RetrievedUtcIso $ts -MaxAgeHours $CacheMaxAgeHours)) {
            return @((fncSafeGetProp $entry "Cpes" @()))
        }
    }

    $enc = [uri]::EscapeDataString($keyword)
    $url = "https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=$enc&resultsPerPage=200&startIndex=0"

    $resp = fncInvokeNvdApi `
        -Url $url `
        -CacheRoot $CacheRoot `
        -ApiKey $ApiKey `
        -DelayMs $DelayMs `
        -UseCache `
        -CacheMaxAgeHours 72

    if ($null -eq $resp) { return @() }

    $products = @()
    if (fncSafeHasProp $resp "products") { $products = @($resp.products) }

    $out = @()
    foreach ($pr in $products) {

        $cpe = $null
        if ($null -ne $pr -and (fncSafeHasProp $pr "cpe")) { $cpe = $pr.cpe }
        if ($null -eq $cpe) { continue }

        $cpeName = fncToSafeString (fncSafeGetProp $cpe "cpeName" "")
        if ([string]::IsNullOrWhiteSpace($cpeName)) { continue }

        $out += [pscustomobject]@{
            cpeName = $cpeName
            score   = (fncScoreCpeCandidate -Vendor $Vendor -Product $Product -CpeName $cpeName)
        }
    }

    $picked = @(
        $out |
        Sort-Object -Property @{Expression='score'; Descending=$true} |
        Select-Object -First $MaxCandidates |
        ForEach-Object { $_.cpeName }
    )

    $map[$keyword] = [pscustomobject]@{
        RetrievedUtc = fncGetUtcNowIso
        Cpes         = @($picked)
    }

    $cache = [pscustomobject]@{
        RetrievedUtc   = fncGetUtcNowIso
        KeywordToEntry = $map
    }

    fncSaveCpeCandidatesCache -CacheRoot $CacheRoot -Cache $cache
    return @($picked)
}

function fncExtractCvssFromCve {
    param($Cve)

    $best = [pscustomobject]@{
        Version  = ""
        Score    = 0.0
        Vector   = ""
        Severity = ""
    }

    try {
        $metrics = fncSafeGetProp $Cve "metrics" $null
        if ($null -eq $metrics) { return $best }

        # v3.1
        if (fncSafeHasProp $metrics "cvssMetricV31") {
            $arr = @($metrics.cvssMetricV31)
            if ($arr.Count -gt 0) {
                $d = fncSafeGetProp $arr[0] "cvssData" $null
                if ($null -ne $d) {
                    $best.Version  = "3.1"
                    $best.Score    = [double](fncSafeGetProp $d "baseScore" 0.0)
                    $best.Vector   = fncToSafeString (fncSafeGetProp $d "vectorString" "")
                    $best.Severity = fncToSafeString (fncSafeGetProp $d "baseSeverity" "")
                    return $best
                }
            }
        }

        # v3.0
        if (fncSafeHasProp $metrics "cvssMetricV30") {
            $arr = @($metrics.cvssMetricV30)
            if ($arr.Count -gt 0) {
                $d = fncSafeGetProp $arr[0] "cvssData" $null
                if ($null -ne $d) {
                    $best.Version  = "3.0"
                    $best.Score    = [double](fncSafeGetProp $d "baseScore" 0.0)
                    $best.Vector   = fncToSafeString (fncSafeGetProp $d "vectorString" "")
                    $best.Severity = fncToSafeString (fncSafeGetProp $d "baseSeverity" "")
                    return $best
                }
            }
        }

        # v2
        if (fncSafeHasProp $metrics "cvssMetricV2") {
            $arr = @($metrics.cvssMetricV2)
            if ($arr.Count -gt 0) {
                $d = fncSafeGetProp $arr[0] "cvssData" $null
                if ($null -ne $d) {
                    $best.Version  = "2.0"
                    $best.Score    = [double](fncSafeGetProp $d "baseScore" 0.0)
                    $best.Vector   = fncToSafeString (fncSafeGetProp $d "vectorString" "")
                    $best.Severity = fncToSafeString (fncSafeGetProp $arr[0] "baseSeverity" "")
                    return $best
                }
            }
        }
    }
    catch { }

    return $best
}

function fncGetNvdCvesForCpe {
    param(
        [Parameter(Mandatory=$true)][string]$CpeName,
        [Parameter(Mandatory=$true)][string]$CacheRoot,

        [string]$ApiKey,

        [int]$ResultsPerPage = 200,
        [int]$MaxPages = 3,
        [int]$DelayMs = 900,

        [int]$UrlCacheMaxAgeHours = 72
    )

    if ([string]::IsNullOrWhiteSpace($CpeName)) { return @() }

    $cves  = @()
    $start = 0
    $pages = 0

    while ($pages -lt $MaxPages) {

        $enc = [uri]::EscapeDataString($CpeName)
        $url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=$enc&startIndex=$start&resultsPerPage=$ResultsPerPage"

        $resp = fncInvokeNvdApi `
            -Url $url `
            -CacheRoot $CacheRoot `
            -ApiKey $ApiKey `
            -DelayMs $DelayMs `
            -UseCache `
            -CacheMaxAgeHours $UrlCacheMaxAgeHours

        if ($null -eq $resp) { break }

        $vulns = @()
        if (fncSafeHasProp $resp "vulnerabilities") { $vulns = @($resp.vulnerabilities) }

        foreach ($v in $vulns) {

            $c = fncSafeGetProp $v "cve" $null
            if ($null -eq $c) { continue }

            $id = fncToSafeString (fncSafeGetProp $c "id" "")
            if ([string]::IsNullOrWhiteSpace($id)) { continue }

            $cvss = fncExtractCvssFromCve -Cve $c

            $cves += [pscustomobject]@{
                CveId     = $id
                CvssVer   = fncToSafeString (fncSafeGetProp $cvss "Version" "")
                CvssScore = [double](fncSafeGetProp $cvss "Score" 0.0)
                Severity  = fncToSafeString (fncSafeGetProp $cvss "Severity" "")
                Vector    = fncToSafeString (fncSafeGetProp $cvss "Vector" "")
            }
        }

        $total = fncSafeGetProp $resp "totalResults" 0
        $start += $ResultsPerPage
        $pages += 1

        if ($start -ge $total) { break }
        if ($vulns.Count -le 0) { break }
    }

    return $cves | Sort-Object CveId -Unique
}

Export-ModuleMember -Function @(
    "fncResolveCpeCandidates",
    "fncGetNvdCvesForCpe"
)