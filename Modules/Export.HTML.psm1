# ================================================================
# Module  : Export.HTML.psm1
# Purpose : Export full engagement report to standalone HTML
# Notes   : PowerShell 5.1 compatible
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ================================================================
# Function: fncResolveRepoRoot
# ================================================================
function fncResolveRepoRoot {

    if ($PSScriptRoot) {
        return (Split-Path -Path $PSScriptRoot -Parent)
    }

    return $PWD.Path
}

# ================================================================
# Function: fncResolveTemplatePath
# ================================================================
function fncResolveTemplatePath {

    $root = fncResolveRepoRoot
    return (Join-Path $root "data\ThePr0b3r_blank.html")
}

# ================================================================
# Function: fncSafeProp
# ================================================================
function fncSafeProp {

    param(
        [AllowNull()][object]$Object,
        [string]$Name,
        [AllowNull()][object]$Default = $null
    )

    if ($null -eq $Object) { return $Default }

    if ($Object.PSObject.Properties.Name -contains $Name) {
        $val = $Object.$Name
        if ($null -ne $val) { return $val }
    }

    return $Default
}

# ================================================================
# Function: fncExtractTechniqueIds
# ================================================================
function fncExtractTechniqueIds {

    param(
        [string]$Message,
        [string]$Prefix
    )

    if ([string]::IsNullOrWhiteSpace($Message)) { return @() }

    $pattern = "(?im)^\s*$Prefix\s+([A-Za-z0-9\.\-\/]+)\s*$"

    return [regex]::Matches($Message, $pattern) |
           ForEach-Object { $_.Groups[1].Value } |
           Select-Object -Unique
}

# ================================================================
# Function: fncConvertFindingToHtmlObject
# ================================================================
function fncConvertFindingToHtmlObject {

    param([Parameter(Mandatory)]$Finding)

    $timeFound = fncSafeProp $Finding "Time" $null
    if (-not $timeFound) { $timeFound = fncSafeProp $Finding "Timestamp" $null }
    if (-not $timeFound) { $timeFound = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss") }

    $cvss = fncSafeProp $Finding "Cvss" $null
    if (-not $cvss) { $cvss = fncSafeProp $Finding "CVSS" $null }

    $mitreObjects = @()
    $cweObjects   = @()
    $nistObjects  = @()

    foreach ($m in @((fncSafeProp $Finding "Mitre" @()))) {

        if (-not $m) { continue }

        $id     = fncSafeProp $m "id"     (fncSafeProp $m "Id" "")
        $tactic = fncSafeProp $m "tactic" (fncSafeProp $m "Tactic" "")
        $name   = fncSafeProp $m "name"   (fncSafeProp $m "Name" "")
        $url    = fncSafeProp $m "url"    (fncSafeProp $m "Url" "")

        if ($id) {
            $mitreObjects += [pscustomobject]@{
                id     = $id
                tactic = $tactic
                name   = $name
                url    = $url
            }
        }
    }

    foreach ($c in @((fncSafeProp $Finding "CWE" @()))) {

        if (-not $c) { continue }

        $id   = fncSafeProp $c "id"   (fncSafeProp $c "Id" "")
        $name = fncSafeProp $c "name" (fncSafeProp $c "Name" "")
        $url  = fncSafeProp $c "url"  (fncSafeProp $c "Url" "")

        if ($id) {
            $cweObjects += [pscustomobject]@{
                id   = $id
                name = $name
                url  = $url
            }
        }
    }

    foreach ($n in @((fncSafeProp $Finding "NIST" @()))) {

        if (-not $n) { continue }

        $id   = fncSafeProp $n "id"   (fncSafeProp $n "Id" "")
        $name = fncSafeProp $n "name" (fncSafeProp $n "Name" "")
        $url  = fncSafeProp $n "url"  (fncSafeProp $n "Url" "")

        if ($id) {
            $nistObjects += [pscustomobject]@{
                id   = $id
                name = $name
                url  = $url
            }
        }
    }

    $mitreIds = foreach ($m in @($mitreObjects)) { $m.id }
    $cweIds   = foreach ($c in @($cweObjects))   { $c.id }
    $nistIds  = foreach ($n in @($nistObjects))  { $n.id }

    return [pscustomobject][ordered]@{
        id             = [string](fncSafeProp $Finding "Id" "")
        title          = [string](fncSafeProp $Finding "Title" "")
        category       = [string](fncSafeProp $Finding "Category" "")
        severity       = [string](fncSafeProp $Finding "Severity" "")
        status         = [string](fncSafeProp $Finding "Status" "")
        message        = [string](fncSafeProp $Finding "Message" "")
        recommendation = [string](fncSafeProp $Finding "Recommendation" "")
        exploitation   = [string](fncSafeProp $Finding "Exploitation" "")
        remediation    = [string](fncSafeProp $Finding "Remediation" "")
        evidence       = [string](fncSafeProp $Finding "Evidence" "")
        cvss           = $cvss
        time           = [string]$timeFound
        mitre          = @($mitreIds)
        cwe            = @($cweIds)
        nist           = @($nistIds)
        mitreObjects   = @($mitreObjects)
        cweObjects     = @($cweObjects)
        nistObjects    = @($nistObjects)
        attackChainId  = fncSafeProp $Finding "AttackChainId" ""
        attackStep     = fncSafeProp $Finding "AttackStep" 0
        attackPrev     = fncSafeProp $Finding "AttackPrev" ""
        attackNext     = fncSafeProp $Finding "AttackNext" ""
        scope          = fncSafeProp $Finding "Scope" ""
    }
}

# ================================================================
# Function: fncExportFindingsToHtml
# ================================================================
function fncExportFindingsToHtml {

    param(
        [string]$Path = "",
        [switch]$Force
    )

    if (-not $global:ProberState.Findings -or
        $global:ProberState.Findings.Count -eq 0) {
        Write-Host "No findings to export."
        return
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $root  = fncResolveRepoRoot
        $Path  = Join-Path $root ("ThePr0b3r_Report_{0}.html" -f $stamp)
    }

    if ((Test-Path $Path) -and -not $Force) {
        Write-Host ("HTML already exists: {0}" -f $Path)
        return
    }

    $templatePath = fncResolveTemplatePath
    if (-not (Test-Path $templatePath)) {
        throw "HTML template not found: $templatePath"
    }

    $html = Get-Content $templatePath -Raw -Encoding UTF8

    $exportData = foreach ($f in $global:ProberState.Findings) {
        fncConvertFindingToHtmlObject -Finding $f
    }

    # ---------------- RUN CONTEXT ----------------

    $hostname = $env:COMPUTERNAME
    $user     = [Environment]::UserName

    $ip = "Unknown"
    try {
        $ip = (Get-NetIPAddress -AddressFamily IPv4 |
              Where-Object {$_.IPAddress -notlike "169.*"} |
              Select-Object -First 1 -ExpandProperty IPAddress)
    } catch {}

    $isAdmin = $false
    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin   = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}

    $privilege = if ($isAdmin) { "Admin Context" } else { "Low Priv Context" }

    $hostType = "Unknown"
    try {
        $productType = (Get-CimInstance Win32_OperatingSystem).ProductType
        if ($productType -eq 1) { $hostType = "Workstation" }
        elseif ($productType -eq 2) { $hostType = "Domain Controller" }
        else { $hostType = "Server" }
    } catch {}

    $runId = if ($global:ProberState.RunId) {
        $global:ProberState.RunId
    } else {
        [guid]::NewGuid().ToString()
    }

    $runContext = [pscustomobject]@{
        hostname  = $hostname
        ip        = $ip
        user      = $user
        privilege = $privilege
        hostType  = $hostType
        runId     = $runId
    }

    $runJson = $runContext | ConvertTo-Json -Compress
    $json    = $exportData | ConvertTo-Json -Depth 50 -Compress

    if ($html -notmatch "const\s+FINDINGS\s*=") {
        throw "Template missing 'const FINDINGS = [];' marker."
    }

    $html = [regex]::Replace(
        $html,
        "const\s+FINDINGS\s*=\s*\[\s*\]\s*;",
        ("const FINDINGS = {0};" -f $json)
    )

    $html = [regex]::Replace(
        $html,
        "const\s+RUN_CONTEXT\s*=\s*\{\s*\}\s*;",
        ("const RUN_CONTEXT = {0};" -f $runJson)
    )

    $html | Set-Content -Path $Path -Encoding UTF8 -Force

    Write-Host ("Findings exported to HTML: {0}" -f $Path)
}

Export-ModuleMember -Function @(
    "fncExportFindingsToHtml"
)