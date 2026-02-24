# ================================================================
# Function: fncGetIFEOAndSilentProcessExit
# Purpose : Detect IFEO Debugger / GlobalFlag / SilentProcessExit abuse
# Notes   : Adds risk scoring + writable target checks + path heuristics
# ================================================================
function fncGetIFEOAndSilentProcessExit {

    fncPrintMessage "Checking IFEO and SilentProcessExit persistence locations (advanced)..." "info"
    fncPrintMessage "Initialising IFEO persistence scan." "debug"
    fncPrintMessage "" "plain"

    # ----------------------------------------------------------
    # Config / Heuristics
    # ----------------------------------------------------------
    $ifeoRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    )

    fncPrintMessage ("Configured IFEO roots: {0}" -f ($ifeoRoots -join ", ")) "debug"

    $lolbins = @(
        "cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe",
        "rundll32.exe","regsvr32.exe","schtasks.exe","msiexec.exe","wmic.exe",
        "bitsadmin.exe","certutil.exe","curl.exe"
    )

    fncPrintMessage ("Loaded LOLBin list ({0} entries)" -f $lolbins.Count) "debug"

    $suspiciousPathHints = @(
        "\AppData\Local\Temp\",
        "\AppData\LocalLow\",
        "\AppData\Roaming\",
        "\Windows\Temp\",
        "\Temp\",
        "\Users\Public\",
        "\ProgramData\",
        "\Perflogs\"
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

            # Strip surrounding quotes if any
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
            if ($p -like ("*" + ($hint.ToLowerInvariant()) + "*")) { return $true }
        }

        return $false
    }

    function fncGetPathRiskFlags {
        param(
            [string]$RawValue,
            [string]$ResolvedPath
        )

        $flags = @()

        if ($RawValue -and ($RawValue -match 'http(s)?:\/\/')) {
            $flags += "url_target"
            fncPrintMessage "Debugger/Monitor contains URL target." "debug"
        }

        if ($ResolvedPath -and (fncIsSuspiciousPath $ResolvedPath)) {
            $flags += "suspicious_path"
            fncPrintMessage ("Suspicious path detected: {0}" -f $ResolvedPath) "debug"
        }

        if ($ResolvedPath) {

            $fileWritable = $false
            $dirWritable  = $false

            try { $fileWritable = Test-CurrentUserCanModifyPath -Path $ResolvedPath } catch {}
            try {
                $dir = [System.IO.Path]::GetDirectoryName($ResolvedPath)
                if ($dir) { $dirWritable = (Test-CurrentUserCanModifyPath -Path $dir) }
            } catch {}

            if ($fileWritable) {
                fncPrintMessage ("Writable debugger/monitor file detected: {0}" -f $ResolvedPath) "debug"
                $flags += "writable_file"
            }

            if ($dirWritable) {
                fncPrintMessage ("Writable debugger/monitor directory detected: {0}" -f $ResolvedPath) "debug"
                $flags += "writable_dir"
            }
        }

        return ,$flags
    }

    function fncGetLolbinChainFlag {
        param([string]$RawValue)

        if (-not $RawValue) { return $false }
        $exe = fncGetExecutableFromCommandLine $RawValue
        if (-not $exe) { return $false }

        $leaf = [System.IO.Path]::GetFileName($exe).ToLowerInvariant()

        if ($lolbins -contains $leaf) {
            fncPrintMessage ("LOLBIN chain detected: {0}" -f $leaf) "debug"
            return $true
        }

        return $false
    }

    # ----------------------------------------------------------
    # Scan
    # ----------------------------------------------------------
    $hitCount = 0
    $advCount = 0

    foreach ($root in $ifeoRoots) {

        if (-not (Test-Path $root -ErrorAction SilentlyContinue)) {
            fncPrintMessage ("IFEO root not present: {0}" -f $root) "debug"
            continue
        }

        fncPrintMessage ("Scanning IFEO root: {0}" -f $root) "debug"
        fncPrintSectionHeader ("IFEO Root: {0}" -f $root)

        try {

            $subKeys = @(Get-ChildItem -Path $root -ErrorAction SilentlyContinue)
            fncPrintMessage ("Discovered {0} IFEO entries" -f $subKeys.Count) "debug"

            $total = $subKeys.Count
            $i = 0

            foreach ($sub in $subKeys) {

                $i++

                Write-Progress -Id 41 `
                    -Activity "Enumerating IFEO entries" `
                    -Status ("{0}/{1} : {2}" -f $i,$total,$sub.PSChildName) `
                    -PercentComplete ([int](($i / [Math]::Max($total,1)) * 100))

                try {

                    $subKeyPath = $sub.PSPath
                    $exeName    = $sub.PSChildName

                    $props = Get-ItemProperty -Path $subKeyPath -ErrorAction SilentlyContinue
                    if (-not $props) { continue }

                    $debuggerRaw   = $null
                    $globalFlagRaw = $null

                    try { $debuggerRaw   = [string]$props.Debugger } catch {}
                    try { $globalFlagRaw = [string]$props.GlobalFlag } catch {}

                    $debuggerResolved = $null
                    if ($debuggerRaw) {

                        fncPrintMessage ("Debugger detected for {0}" -f $exeName) "debug"

                        $dbgExe = fncGetExecutableFromCommandLine $debuggerRaw
                        $debuggerResolved = fncTryResolvePath $dbgExe
                    }

                    # SilentProcessExit
                    $silentKey = Join-Path $root ("SilentProcessExit\" + $exeName)

                    $hasSilent = $false
                    $monitorRaw = $null
                    $reportMode = $null
                    $monitorResolved = $null

                    if (Test-Path $silentKey -ErrorAction SilentlyContinue) {

                        fncPrintMessage ("SilentProcessExit detected for {0}" -f $exeName) "debug"

                        $hasSilent = $true

                        $spProps = Get-ItemProperty -Path $silentKey -ErrorAction SilentlyContinue
                        if ($spProps) {
                            try { $monitorRaw = [string]$spProps.MonitorProcess } catch {}
                            try { $reportMode = [string]$spProps.ReportingMode } catch {}
                        }

                        if ($monitorRaw) {
                            $monExe = fncGetExecutableFromCommandLine $monitorRaw
                            $monitorResolved = fncTryResolvePath $monExe
                        }
                    }

                    if (-not $debuggerRaw -and -not $globalFlagRaw -and -not $hasSilent) {
                        continue
                    }

                    fncPrintMessage ("Scoring IFEO entry: {0}" -f $exeName) "debug"

                    $scoreObj = fncScoreIFEOEntry `
                        -HiveRoot $root `
                        -ExeName $exeName `
                        -DebuggerRaw $debuggerRaw `
                        -DebuggerResolved $debuggerResolved `
                        -GlobalFlagRaw $globalFlagRaw `
                        -HasSilentProcessExit $hasSilent `
                        -MonitorProcessRaw $monitorRaw `
                        -MonitorProcessResolved $monitorResolved `
                        -ReportingMode $reportMode

                    $hitCount++

                    $reasonsStr = ($scoreObj.Reasons -join "; ")
                    $msg = "IFEO '$exeName' @ $root | Score=$($scoreObj.Score) Severity=$($scoreObj.Severity) | $reasonsStr"

                    if ($debuggerRaw) {
                        $msg += " | Debugger='$debuggerRaw'"
                        if ($debuggerResolved) { $msg += " (Resolved='$debuggerResolved')" }
                    }

                    if ($globalFlagRaw) {
                        $msg += " | GlobalFlag='$globalFlagRaw'"
                    }

                    if ($hasSilent) {
                        $msg += " | SilentProcessExit='$silentKey'"
                        if ($monitorRaw) {
                            $msg += " MonitorProcess='$monitorRaw'"
                            if ($monitorResolved) { $msg += " (Resolved='$monitorResolved')" }
                        }
                        if ($reportMode) { $msg += " ReportingMode='$reportMode'" }
                    }

                    if ($scoreObj.Severity -in @("High","Critical")) {
                        Write-Host ("[!] {0}" -f $msg) -ForegroundColor Yellow
                    } else {
                        Write-Host ("  -> {0}" -f $msg) -ForegroundColor Cyan
                    }

                    $fid = "IFEO_ADV_" + (
                        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($root + "|" + $exeName)) -replace '[^A-Za-z0-9]',''
                    )

                    fncAddFinding `
                        -Id $fid `
                        -Category "Persistence" `
                        -Title ("IFEO/SilentProcessExit: {0}" -f $exeName) `
                        -Severity $scoreObj.Severity `
                        -Status "Detected" `
                        -Message $msg `
                        -Recommendation "Validate configuration. Remove unapproved entries."

                    $advCount++

                } catch {}
            }

        } catch {
            fncPrintMessage ("Failed enumerating IFEO root {0}" -f $root) "warning"
        }

        fncPrintMessage "" "plain"
    }

    Write-Progress -Id 41 -Activity "Enumerating IFEO entries" -Completed

    # ------------------------------------------------------------
    # Summary Finding
    # ------------------------------------------------------------
    if ($hitCount -eq 0) {

        fncPrintMessage "No IFEO or SilentProcessExit persistence detected." "success"

        fncAddFinding `
            -Id "IFEO_ADV_NONE" `
            -Category "Persistence" `
            -Title "No IFEO Persistence Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No IFEO Debugger, GlobalFlag, or SilentProcessExit entries detected." `
            -Recommendation "No action required."
    }
    else {
        fncPrintMessage ("Detected {0} IFEO/SilentProcessExit configured entries (scored: {1})." -f $hitCount,$advCount) "warning"
    }

    fncPrintMessage "IFEO persistence scan complete." "debug"

    fncPrintMessage "" "plain"
}

Export-ModuleMember -Function fncGetIFEOAndSilentProcessExit
