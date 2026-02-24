# ================================================================
# Function: fncGetReconInstalledSoftwareInventory
# Purpose : Registry inventory + optional Searchsploit correlation
# Notes   : HKLM 64 + HKLM 32 + HKCU only
# ================================================================
function fncGetReconInstalledSoftwareInventory {

    fncPrintMessage "Enumerating installed software (registry only)..." "info"
    fncPrintMessage "" "plain"

    # Always use script scope for shared arrays
    $script:software       = @()
    $script:offensiveTools = @()
    $script:exploitTargets = @()
    $script:ExploitCache   = @{}

    # ------------------------------------------------------------
    # Offensive Tool Indicators
    # ------------------------------------------------------------
    $toolIndicators = @(
        "Wireshark","Npcap","Nmap","Metasploit","Mimikatz",
        "BloodHound","Sysinternals","Process Hacker",
        "PowerShell 7","Python","Burp","Fiddler",
        "John","Hashcat","Impacket","Kali",
        "Cobalt Strike","TeamViewer","AnyDesk",
        "RustDesk","VNC","FileZilla","WinSCP"
    )

    # ------------------------------------------------------------
    # Normalize Product Name
    # ------------------------------------------------------------
    function fncNormalizeName {
        param([string]$Name)

        if (-not $Name) { return "" }

        $n = $Name.ToLower()
        $n = $n -replace "microsoft",""
        $n = $n -replace "\(.*?\)",""
        $n = $n -replace "[^a-z0-9 ]",""
        $n = $n -replace "\s+"," "
        return $n.Trim()
    }

    # ------------------------------------------------------------
    # Searchsploit Lookup (cached)
    # ------------------------------------------------------------
    function fncGetSearchsploitCount {
        param(
            [string]$Product,
            [string]$Version
        )

        if (-not (Get-Command searchsploit -ErrorAction SilentlyContinue)) {
            return 0
        }

        $query = "$Product $Version"

        if ($script:ExploitCache.ContainsKey($query)) {
            return $script:ExploitCache[$query]
        }

        try {
            $json = searchsploit -j $query 2>$null
            if (-not $json) { return 0 }

            $parsed = $json | ConvertFrom-Json
            $count = 0

            if ($parsed.RESULTS_EXPLOIT) {
                $count = ($parsed.RESULTS_EXPLOIT | Measure-Object).Count
            }

            $script:ExploitCache[$query] = $count
            return $count

        } catch {
            return 0
        }
    }

    # ------------------------------------------------------------
    # Density Score
    # ------------------------------------------------------------
    function fncScoreExploitDensity {
        param([int]$Count)

        if ($Count -ge 26) { return 100 }
        if ($Count -ge 11) { return 75 }
        if ($Count -ge 4)  { return 50 }
        if ($Count -ge 1)  { return 25 }
        return 0
    }

    # ------------------------------------------------------------
    # Add Software (safe scoping)
    # ------------------------------------------------------------
    function fncAddSoftware {
        param($Name,$Version,$Publisher)

        if ([string]::IsNullOrWhiteSpace($Name)) { return }

        $normalized   = fncNormalizeName $Name
        $exploitCount = fncGetSearchsploitCount $normalized $Version
        $densityScore = fncScoreExploitDensity $exploitCount

        $obj = [pscustomobject]@{
            Name              = $Name.Trim()
            NormalizedName    = $normalized
            Version           = $Version
            Publisher         = $Publisher
            ExploitCount      = $exploitCount
            ExploitLikelihood = $densityScore
        }

        $script:software += $obj

        if ($densityScore -ge 50) {
            $script:exploitTargets += $obj
        }

        foreach ($indicator in $toolIndicators) {
            if ($Name -match [regex]::Escape($indicator)) {
                $script:offensiveTools += $obj
                break
            }
        }
    }

    # ------------------------------------------------------------
    # Registry Collection
    # ------------------------------------------------------------
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $paths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                ForEach-Object {
                    fncAddSoftware $_.DisplayName $_.DisplayVersion $_.Publisher
                }
        } catch {}
    }

    # Deduplicate
    $script:software       = $script:software       | Sort-Object Name,Version -Unique
    $script:offensiveTools = $script:offensiveTools | Sort-Object Name,Version -Unique
    $script:exploitTargets = $script:exploitTargets | Sort-Object ExploitLikelihood -Descending

    # ------------------------------------------------------------
    # Print Inventory
    # ------------------------------------------------------------
    fncPrintSectionHeader "Installed Software (Registry Inventory)"
    Write-Host ("  -> Total Installed Applications: {0}" -f $script:software.Count)
    fncPrintMessage "" "plain"

    $script:software |
        Sort-Object Name |
        Format-Table Name,Version,ExploitCount,ExploitLikelihood -AutoSize

    fncPrintMessage "" "plain"

    fncPrintSectionHeader "Exploit Candidates (Searchsploit Density)"

    if ($script:exploitTargets.Count -gt 0) {
        $script:exploitTargets |
            Format-Table Name,Version,ExploitCount,ExploitLikelihood -AutoSize
    }
    else {
        fncPrintMessage "No high-density exploit candidates detected." "success"
    }

    fncPrintMessage "" "plain"

    fncPrintSectionHeader "Offensive / Recon Tooling"

    if ($script:offensiveTools.Count -gt 0) {
        $script:offensiveTools |
            Format-Table Name,Version -AutoSize
    }
    else {
        fncPrintMessage "No obvious offensive tooling detected." "success"
    }

    fncPrintMessage "" "plain"

    try {

        if (-not $global:LogFile) {
            throw "Global LogFile not initialised."
        }

        # Derive Logs\<RunID> from LogFile path
        $runFolder = Split-Path -Parent $global:LogFile
        $telemetryDir = Join-Path $runFolder "Telemetry"

        if (-not (Test-Path $telemetryDir)) {
            New-Item -ItemType Directory -Path $telemetryDir -Force | Out-Null
        }

        $jsonPath = Join-Path $telemetryDir "InstalledSoftware.json"
        $txtPath  = Join-Path $telemetryDir "InstalledSoftware.txt"

        # JSON export
        $script:software |
            ConvertTo-Json -Depth 4 |
            Set-Content -LiteralPath $jsonPath -Encoding UTF8

        # Table export
        $tableOutput = $script:software |
            Sort-Object Name |
            Format-Table Name,Version,ExploitCount,ExploitLikelihood -AutoSize |
            Out-String

        Set-Content -LiteralPath $txtPath -Value $tableOutput -Encoding UTF8

        fncPrintMessage "Software telemetry written successfully." "success"

    } catch {

        fncLogException $_.Exception "SoftwareTelemetryPersist"
        fncPrintMessage "Failed to persist software telemetry." "warning"

    }
}