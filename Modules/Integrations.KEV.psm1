# ================================================================
# Module  : Integrations.KEV.psm1
# Purpose : CISA Known Exploited Vulnerabilities integration
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncEnsureKevCacheRoot {
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

function fncIsKevExpired {
    param(
        [string]$RetrievedUtc,
        [int]$MaxAgeHours
    )

    if ($MaxAgeHours -le 0) { return $false }

    $dt = fncUtcParseSafe $RetrievedUtc
    if ($null -eq $dt) { return $true }

    $age = (New-TimeSpan -Start $dt -End (Get-Date).ToUniversalTime()).TotalHours
    return ($age -gt $MaxAgeHours)
}

function fncGetKevData {

    param(
        [Parameter(Mandatory=$true)]
        [string]$CacheRoot,

        [int]$MaxAgeHours = 24,

        [switch]$ForceRefresh,

        [switch]$NoNetwork
    )

    fncEnsureKevCacheRoot -CacheRoot $CacheRoot

    $path = Join-Path $CacheRoot "KevCache.json"

    $cached = fncReadJsonFileSafe -Path $path -Default $null

    $needRefresh = $false

    if ($ForceRefresh) {
        $needRefresh = $true
    }
    elseif ($null -eq $cached) {
        $needRefresh = $true
    }
    elseif (fncIsKevExpired -RetrievedUtc (fncSafeGetProp $cached "RetrievedUtc" "") -MaxAgeHours $MaxAgeHours) {
        $needRefresh = $true
    }

    if ($NoNetwork) {
        $needRefresh = $false
    }

    if ($needRefresh) {

        $url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

        try {

            $resp = Invoke-RestMethod -Uri $url -Method GET -ErrorAction Stop

            $vulns = @()
            if ($null -ne $resp -and (fncSafeHasProp $resp "vulnerabilities")) {
                $vulns = @($resp.vulnerabilities)
            }

            $lookup = @{}

            foreach ($v in $vulns) {

                $cve = fncToSafeString (fncSafeGetProp $v "cveID" "")
                if ([string]::IsNullOrWhiteSpace($cve)) { continue }

                $lookup[$cve] = [pscustomobject]@{
                    cveID            = $cve
                    vendorProject    = fncToSafeString (fncSafeGetProp $v "vendorProject" "")
                    product          = fncToSafeString (fncSafeGetProp $v "product" "")
                    vulnerabilityName= fncToSafeString (fncSafeGetProp $v "vulnerabilityName" "")
                    dateAdded        = fncToSafeString (fncSafeGetProp $v "dateAdded" "")
                    shortDescription = fncToSafeString (fncSafeGetProp $v "shortDescription" "")
                    requiredAction   = fncToSafeString (fncSafeGetProp $v "requiredAction" "")
                    dueDate          = fncToSafeString (fncSafeGetProp $v "dueDate" "")
                }
            }

            $cached = [pscustomobject]@{
                RetrievedUtc = fncGetUtcNowIso
                Source       = $url
                KevCount     = $lookup.Keys.Count
                Lookup       = $lookup
            }

            fncWriteJsonFileSafe -Path $path -Object $cached -Depth 15 | Out-Null
        }
        catch {

            if ($null -eq $cached) {
                $cached = [pscustomobject]@{
                    RetrievedUtc = ""
                    Source       = ""
                    KevCount     = 0
                    Lookup       = @{}
                }
            }
        }
    }

    if ($null -eq $cached) {
        return [pscustomobject]@{
            RetrievedUtc = ""
            Source       = ""
            KevCount     = 0
            Lookup       = @{}
        }
    }

    $lookupRaw = fncSafeGetProp $cached "Lookup" $null
    $lookup = fncConvertToHashtableSafe $lookupRaw

    return [pscustomobject]@{
        RetrievedUtc = fncSafeGetProp $cached "RetrievedUtc" ""
        Source       = fncSafeGetProp $cached "Source" ""
        KevCount     = $lookup.Keys.Count
        Lookup       = $lookup
    }
}

Export-ModuleMember -Function @(
    "fncGetKevData",
    "fncGetKevCache"
)