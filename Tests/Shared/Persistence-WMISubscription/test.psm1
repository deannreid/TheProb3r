# ================================================================
# Function: fncGetWMIPersistence
# Purpose : Enumerate WMI event subscriptions (root\subscription)
# Notes   : Flags suspicious consumers/filters + writable targets + scoring
# ================================================================
function fncGetWMIPersistence {

    fncPrintMessage "Enumerating WMI event subscriptions in root\subscription (WMI persistence)..." "info"
    fncPrintMessage "Initialising WMI persistence scan." "debug"
    Write-Host ""

    # ----------------------------------------------------------
    # Heuristics
    # ----------------------------------------------------------
    $lolbins = @(
        "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe",
        "rundll32.exe","regsvr32.exe","schtasks.exe","msiexec.exe","wmic.exe",
        "bitsadmin.exe","certutil.exe","curl.exe"
    )

    fncPrintMessage ("Loaded LOLBin heuristic list ({0} entries)" -f $lolbins.Count) "debug"

    $suspiciousPathHints = @(
        "\appdata\local\temp\",
        "\appdata\locallow\",
        "\appdata\roaming\",
        "\windows\temp\",
        "\temp\",
        "\users\public\",
        "\programdata\",
        "\perflogs\"
    )

    fncPrintMessage ("Loaded suspicious path hints ({0} entries)" -f $suspiciousPathHints.Count) "debug"

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    function fncGetExecutableFromCommandLine {
        param([string]$CommandLine)

        if (-not $CommandLine) { return $null }
        $cmd = $CommandLine.Trim()
        if ($cmd -match '^\s*"(.*?)"') { return $matches[1] }
        return ($cmd.Split(" ")[0])
    }

    function fncTryResolvePath {
        param([string]$PathValue)

        if (-not $PathValue) { return $null }

        try {
            $expanded = [Environment]::ExpandEnvironmentVariables($PathValue)
            if ($expanded -match '^\s*"(.*?)"\s*$') { $expanded = $matches[1] }

            if (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue) {
                return (Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue).FullName
            }
        } catch {}

        return $null
    }

    function fncIsSuspiciousPath {
        param([string]$Path)

        if (-not $Path) { return $false }
        $p = $Path.ToLowerInvariant()

        foreach ($hint in $suspiciousPathHints) {
            if ($p -like ("*" + $hint + "*")) { return $true }
        }

        return $false
    }

    function fncIsLolbin {
        param([string]$CommandLine)

        if (-not $CommandLine) { return $false }
        $exe = fncGetExecutableFromCommandLine $CommandLine
        if (-not $exe) { return $false }

        $leaf = [System.IO.Path]::GetFileName($exe).ToLowerInvariant()
        return ($lolbins -contains $leaf)
    }

    function fncScoreWmiSubscription {
        param(
            [string]$FilterName,
            [string]$FilterQuery,
            [string]$ConsumerName,
            [string]$CommandLineTemplate,
            [string]$ResolvedTarget
        )

        $score = 0
        $reasons = @()

        # Base: the combo itself is persistence-y
        $score += 20
        $reasons += "WMI subscription present"

        # Weird naming (very lightweight heuristic)
        $nameBlob = (($FilterName + " " + $ConsumerName) -as [string])
        if ($nameBlob -match "^[a-f0-9]{8,}$" -or $nameBlob -match "update|driver|telemetry|security|svc" -or $nameBlob.Length -gt 40) {
            $score += 5
            $reasons += "Name heuristic triggered"
        }

        # Query heuristics
        if ($FilterQuery) {
            if ($FilterQuery -match "Win32_ProcessStartTrace|__InstanceCreationEvent|__InstanceModificationEvent|__InstanceDeletionEvent") {
                $score += 5
                $reasons += "Common persistence trigger class"
            }
            if ($FilterQuery -match "WITHIN\s+\d+") {
                $score += 3
                $reasons += "Polling interval present"
            }
        }

        # Consumer command heuristics
        if ($CommandLineTemplate) {
            $score += 10
            $reasons += "CommandLineEventConsumer present"

            if (fncIsLolbin $CommandLineTemplate) {
                $score += 15
                $reasons += "LOLBIN in command"
            }

            if ($CommandLineTemplate -match "http(s)?:\/\/") {
                $score += 10
                $reasons += "URL in command"
            }
        }

        # Target path heuristics (resolved)
        if ($ResolvedTarget) {

            if (fncIsSuspiciousPath $ResolvedTarget) {
                $score += 15
                $reasons += "Target path suspicious"
            }

            $fileWritable = $false
            $dirWritable  = $false

            try { $fileWritable = Test-CurrentUserCanModifyPath -Path $ResolvedTarget } catch {}
            try {
                $dir = [System.IO.Path]::GetDirectoryName($ResolvedTarget)
                if ($dir) { $dirWritable = (Test-CurrentUserCanModifyPath -Path $dir) }
            } catch {}

            if ($fileWritable) { $score += 25; $reasons += "Target writable file" }
            if ($dirWritable)  { $score += 15; $reasons += "Target writable directory" }
        }

        if ($score -gt 100) { $score = 100 }

        $severity = "Info"
        if ($score -ge 85) { $severity = "Critical" }
        elseif ($score -ge 70) { $severity = "High" }
        elseif ($score -ge 45) { $severity = "Medium" }
        elseif ($score -ge 20) { $severity = "Low" }

        return [PSCustomObject]@{
            Score    = $score
            Severity = $severity
            Reasons  = ($reasons | Sort-Object -Unique)
        }
    }

    # ----------------------------------------------------------
    # Query WMI
    # ----------------------------------------------------------
    fncPrintMessage "Querying WMI root\subscription namespace..." "debug"

    $filters   = @()
    $consumers = @()
    $bindings  = @()

    try {
        $filters   = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue)
        $consumers = @(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue)
        $bindings  = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue)
    } catch {
        fncPrintMessage ("Error querying WMI root\subscription: {0}" -f $_.Exception.Message) "warning"
    }

    fncPrintMessage ("Filters discovered   : {0}" -f $filters.Count) "debug"
    fncPrintMessage ("Consumers discovered : {0}" -f $consumers.Count) "debug"
    fncPrintMessage ("Bindings discovered  : {0}" -f $bindings.Count) "debug"

    if (($filters.Count -eq 0) -and ($consumers.Count -eq 0) -and ($bindings.Count -eq 0)) {

        fncPrintMessage "No WMI event filters/consumers/bindings found (or access denied)." "success"

        fncAddFinding `
            -Id "WMI_PERSIST_NONE" `
            -Category "Persistence" `
            -Title "No WMI Event Subscriptions Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No WMI event filters/consumers/bindings were found under root\subscription (or access was denied)." `
            -Recommendation "No action required."

        return
    }

    # ----------------------------------------------------------
    # Map objects by __RELPATH for easier binding resolution
    # ----------------------------------------------------------
    fncPrintMessage "Building RELPATH lookup maps..." "debug"

    $filterByRel = @{}
    foreach ($f in $filters) {
        try { if ($f.__RELPATH) { $filterByRel[$f.__RELPATH] = $f } } catch {}
    }

    $consumerByRel = @{}
    foreach ($c in $consumers) {
        try { if ($c.__RELPATH) { $consumerByRel[$c.__RELPATH] = $c } } catch {}
    }

    fncPrintMessage ("Filter RELPATH entries   : {0}" -f $filterByRel.Count) "debug"
    fncPrintMessage ("Consumer RELPATH entries : {0}" -f $consumerByRel.Count) "debug"

    # ----------------------------------------------------------
    # Output (summary + scored entries)
    # ----------------------------------------------------------
    fncPrintSectionHeader "WMI Subscriptions (Bindings)"

    $hitCount = 0

    $total = $bindings.Count
    $i = 0

    foreach ($b in $bindings) {

        $i++
        Write-Progress -Id 51 `
            -Activity "Enumerating WMI bindings" `
            -Status ("{0}/{1}" -f $i,$total) `
            -PercentComplete ([int](($i / [Math]::Max($total,1)) * 100))

        try {

            $filterRef   = [string]$b.Filter
            $consumerRef = [string]$b.Consumer

            $filterObj   = $null
            $consumerObj = $null

            if ($filterRef -and $filterByRel.ContainsKey($filterRef)) { $filterObj = $filterByRel[$filterRef] }
            if ($consumerRef -and $consumerByRel.ContainsKey($consumerRef)) { $consumerObj = $consumerByRel[$consumerRef] }

            $filterName   = $null
            $filterQuery  = $null
            $consumerName = $null
            $cmdTemplate  = $null

            if ($filterObj) {
                try { $filterName  = [string]$filterObj.Name } catch {}
                try { $filterQuery = [string]$filterObj.Query } catch {}
            }
            if ($consumerObj) {
                try { $consumerName = [string]$consumerObj.Name } catch {}
                try { $cmdTemplate  = [string]$consumerObj.CommandLineTemplate } catch {}
            }

            # Resolve the command target best-effort
            $resolved = $null
            if ($cmdTemplate) {
                $exeRaw = fncGetExecutableFromCommandLine $cmdTemplate
                $resolved = fncTryResolvePath $exeRaw
            }

            fncPrintMessage ("Scoring WMI binding: Filter='{0}' Consumer='{1}'" -f $filterName,$consumerName) "debug"

            $scoreObj = fncScoreWmiSubscription `
                -FilterName $filterName `
                -FilterQuery $filterQuery `
                -ConsumerName $consumerName `
                -CommandLineTemplate $cmdTemplate `
                -ResolvedTarget $resolved

            $reasonsStr = ($scoreObj.Reasons -join "; ")

            $line = "Filter='$filterName' Consumer='$consumerName' Score=$($scoreObj.Score) Severity=$($scoreObj.Severity)"
            if ($cmdTemplate) { $line += " | Cmd='$cmdTemplate'" }
            if ($resolved) { $line += " | Resolved='$resolved'" }
            if ($filterQuery) { $line += " | Query='$filterQuery'" }
            $line += " | $reasonsStr"

            if ($scoreObj.Severity -in @("High","Critical")) {
                Write-Host ("[!] {0}" -f $line) -ForegroundColor Yellow
            } else {
                Write-Host ("  -> {0}" -f $line) -ForegroundColor Cyan
            }

            $fid = "WMI_PERSIST_" + (
                [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($filterName + "|" + $consumerName + "|" + $filterRef + "|" + $consumerRef))) -replace '[^A-Za-z0-9]',''
            )

            fncAddFinding `
                -Id $fid `
                -Category "Persistence" `
                -Title "WMI Event Subscription" `
                -Severity $scoreObj.Severity `
                -Status "Detected" `
                -Message $line `
                -Recommendation "Validate WMI subscription ownership and intent. Remove unapproved filters/consumers/bindings. If malicious, investigate referenced binaries/paths and event timeline."

            $hitCount++

        } catch {}
    }

    Write-Progress -Id 51 -Activity "Enumerating WMI bindings" -Completed

    Write-Host ""

    if ($hitCount -eq 0) {
        fncPrintMessage "WMI objects were present, but no bindings were processed." "info"
    } else {
        fncPrintMessage ("Found {0} WMI subscription binding(s). Review High/Critical scored entries first." -f $hitCount) "warning"
    }

    fncPrintMessage "WMI persistence scan complete." "debug"

    Write-Host ""
}

Export-ModuleMember -Function fncGetWMIPersistence
