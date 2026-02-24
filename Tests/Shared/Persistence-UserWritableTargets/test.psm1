# ================================================================
# Function: fncGetUserPersistencePoints
# Purpose : Enumerate user-level persistence locations + weak targets
# Notes   : Uses registry inspection + file/dir writability checks
# ================================================================
function fncGetUserPersistencePoints {

    fncPrintMessage "Enumerating user-level persistence locations (plus)..." "info"
    fncPrintMessage "" "plain"

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # ----------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------
    function fncGetExecutableFromCommandLine {
        param([string]$CommandLine)

        if (-not $CommandLine) { return $null }
        $cmd = $CommandLine.Trim()

        if ($cmd -match '^\s*"(.*?)"') { return $matches[1] }
        return $cmd.Split(" ")[0]
    }

    function fncTryResolvePath {
        param([string]$PathValue)

        if (-not $PathValue) { return $null }

        try {
            $expanded = [Environment]::ExpandEnvironmentVariables($PathValue)
            if (Test-Path -LiteralPath $expanded -ErrorAction SilentlyContinue) {
                return (Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue).FullName
            }
        } catch {}
        return $null
    }

    function fncCheckWritableTarget {
        param(
            [string]$TargetPath,
            [string]$Context,
            [string]$FindingPrefix,
            [string]$Title,
            [string]$Recommendation
        )

        if (-not $TargetPath) { return $false }

        $fileWritable = $false
        $dirWritable  = $false

        try { $fileWritable = Test-CurrentUserCanModifyPath -Path $TargetPath } catch {}

        $dir = $null
        try { $dir = [System.IO.Path]::GetDirectoryName($TargetPath) } catch { $dir = $null }
        if ($dir) {
            try { $dirWritable = Test-CurrentUserCanModifyPath -Path $dir } catch {}
        }

        if (-not $fileWritable -and -not $dirWritable) { return $false }

        $w = @()
        if ($fileWritable) { $w += "file" }
        if ($dirWritable)  { $w += "directory" }

        $msg = "$Context -> '$TargetPath' is writable by $currentUser via $($w -join ', ')."

        Write-Host "[!] Writable persistence target: $msg" -ForegroundColor Yellow

        $fid = $FindingPrefix + "_" + (
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Context + "|" + $TargetPath)) -replace '[^A-Za-z0-9]',''
        )

        fncAddFinding `
            -Id $fid `
            -Category "Persistence" `
            -Title $Title `
            -Severity "Medium" `
            -Status "Detected" `
            -Message $msg `
            -Recommendation $Recommendation

        return $true
    }

    function fncAddPresenceFinding {
        param(
            [string]$Id,
            [string]$Title,
            [string]$Message
        )

        fncAddFinding `
            -Id $Id `
            -Category "Persistence" `
            -Title $Title `
            -Severity "Info" `
            -Status "Detected" `
            -Message $Message `
            -Recommendation "Review legitimacy; remove if unapproved."
    }

    $hitCount = 0

    # ==========================================================
    # 1) Startup folders
    # ==========================================================
    fncPrintSectionHeader "Startup Folder Persistence"

    $startupUser = Join-Path $env:APPDATA     "Microsoft\Windows\Start Menu\Programs\Startup"
    $startupAll  = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup"

    $startupDirs = @($startupUser,$startupAll) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }

    foreach ($dir in $startupDirs) {
        try {
            Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue | ForEach-Object {
                $p = $_.FullName

                if (fncCheckWritableTarget `
                        -TargetPath $p `
                        -Context ("Startup item in " + $dir) `
                        -FindingPrefix "USERPERSIST_STARTUP" `
                        -Title "Writable Startup Item" `
                        -Recommendation "Restrict write access to Startup items and folder.") {
                    $hitCount++
                } else {
                    Write-Host ("  -> {0}" -f $p) -ForegroundColor Cyan
                }
            }
        } catch {}
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # 2) HKCU Run / RunOnce
    # ==========================================================
    fncPrintSectionHeader "HKCU Run / RunOnce Persistence"

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($rk in $runKeys) {
        try {
            if (-not (Test-Path $rk -ErrorAction SilentlyContinue)) { continue }

            $props = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like "PS*") { continue }

                $val = [string]$prop.Value
                if (-not $val) { continue }

                $exeRaw = fncGetExecutableFromCommandLine $val
                $target = fncTryResolvePath $exeRaw

                $ctx = "Run entry '$($prop.Name)' in '$rk' -> $val"

                if ($target) {
                    if (fncCheckWritableTarget `
                            -TargetPath $target `
                            -Context $ctx `
                            -FindingPrefix "USERPERSIST_RUN" `
                            -Title "Writable HKCU Run Target" `
                            -Recommendation "Restrict write permissions on target binary and its directory.") {
                        $hitCount++
                    } else {
                        Write-Host ("  -> {0}" -f $ctx) -ForegroundColor Cyan
                    }
                } else {
                    Write-Host ("  -> {0} (target missing/unresolved)" -f $ctx) -ForegroundColor Cyan
                }
            }
        } catch {}
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # 3) Scheduled Task user persistence (HKCU tasks / user context)
    # ==========================================================
    fncPrintSectionHeader "Scheduled Task Persistence (User Context)"

    if (Get-Command -Name Get-ScheduledTask -ErrorAction SilentlyContinue) {
        try {
            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
            foreach ($t in $tasks) {

                try {
                    if ($t.State -eq "Disabled") { continue }

                    $principal = $t.Principal
                    $userId    = $principal.UserId

                    # User-context tasks (best-effort heuristic)
                    if (-not $userId) { continue }
                    if ($userId -match "SYSTEM|LocalService|NetworkService") { continue }

                    foreach ($a in $t.Actions) {
                        if (-not $a.Execute) { continue }

                        $cmdLine = $a.Execute + " " + ($a.Arguments -join " " -replace $null, "")

                        $exeRaw  = fncGetExecutableFromCommandLine $cmdLine
                        $target  = fncTryResolvePath $exeRaw

                        $ctx = "Task '$($t.TaskPath)$($t.TaskName)' runs as '$userId' -> $cmdLine"

                        if ($target) {
                            # Presence finding (task exists)
                            fncAddPresenceFinding `
                                -Id ("USERPERSIST_TASK_PRESENT_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t.TaskPath+$t.TaskName)) -replace '[^A-Za-z0-9]','')) `
                                -Title "Scheduled Task Persistence (User)" `
                                -Message $ctx

                            if (fncCheckWritableTarget `
                                    -TargetPath $target `
                                    -Context $ctx `
                                    -FindingPrefix "USERPERSIST_TASK_WRITABLE" `
                                    -Title "Writable Scheduled Task Target" `
                                    -Recommendation "Restrict write permissions or remove/disable task if unapproved.") {
                                $hitCount++
                            } else {
                                Write-Host ("  -> {0}" -f $ctx) -ForegroundColor Cyan
                            }
                        } else {
                            Write-Host ("  -> {0} (target missing/unresolved)" -f $ctx) -ForegroundColor Cyan
                        }
                    }
                } catch {}
            }
        } catch {
            fncPrintMessage "Failed enumerating scheduled tasks." "warning"
        }
    } else {
        fncPrintMessage "Get-ScheduledTask cmdlet not available." "warning"
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # 4) Shell extensions (HKCU)
    # ==========================================================
    fncPrintSectionHeader "Shell Extensions (HKCU)"

    $shellExtKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved",
        "HKCU:\Software\Classes\*\shellex",
        "HKCU:\Software\Classes\AllFileSystemObjects\shellex",
        "HKCU:\Software\Classes\Directory\shellex",
        "HKCU:\Software\Classes\Folder\shellex"
    )

    foreach ($k in $shellExtKeys) {
        try {
            if (-not (Test-Path $k -ErrorAction SilentlyContinue)) { continue }

            Write-Host ("  -> {0}" -f $k) -ForegroundColor Cyan

            # If Approved, values are GUIDs; resolve to InprocServer32 if possible
            if ($k -like "*\Approved") {
                $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if ($p) {
                    foreach ($prop in $p.PSObject.Properties) {
                        if ($prop.Name -like "PS*") { continue }
                        $guid = $prop.Name
                        $clsid = "HKCU:\Software\Classes\CLSID\$guid\InprocServer32"
                        if (-not (Test-Path $clsid -ErrorAction SilentlyContinue)) {
                            $clsid = "HKLM:\Software\Classes\CLSID\$guid\InprocServer32"
                        }
                        if (Test-Path $clsid -ErrorAction SilentlyContinue) {
                            $dll = (Get-ItemProperty -Path $clsid -ErrorAction SilentlyContinue).'(default)'
                            $target = fncTryResolvePath $dll
                            $ctx = "Shell extension GUID $guid -> $dll"
                            fncAddPresenceFinding `
                                -Id ("USERPERSIST_SHELLEX_" + ($guid -replace '[^A-Za-z0-9]','')) `
                                -Title "Shell Extension Present" `
                                -Message $ctx

                            if ($target) {
                                if (fncCheckWritableTarget `
                                        -TargetPath $target `
                                        -Context $ctx `
                                        -FindingPrefix "USERPERSIST_SHELLEX_WRITABLE" `
                                        -Title "Writable Shell Extension DLL" `
                                        -Recommendation "Restrict write access to shell extension DLLs; remove unapproved extensions.") {
                                    $hitCount++
                                }
                            }
                        }
                    }
                }
            }
        } catch {}
    }

    fncPrintMessage "" "plain"

# ==========================================================
# 5) User COM hijacks (HKCU Classes)
# ==========================================================
fncPrintSectionHeader "User COM Hijacks (HKCU\Software\Classes\CLSID)"

$hkcuClsid = "HKCU:\Software\Classes\CLSID"

if (Test-Path $hkcuClsid -ErrorAction SilentlyContinue) {

    try {

        fncPrintMessage "Enumerating HKCU COM registrations..." "info"

        # ---------------------------
        # Pre-count entries
        # ---------------------------
        $clsidEntries = Get-ChildItem -Path $hkcuClsid -ErrorAction SilentlyContinue

        if (-not $clsidEntries) {
            fncPrintMessage "No CLSID entries found." "info"
        }
        else {

            $totalEntries = $clsidEntries.Count
            $processed    = 0

            foreach ($entry in $clsidEntries) {

                $processed++

                # ---------------------------
                # Progress Bar
                # ---------------------------
                if ($totalEntries -gt 0) {
                    $percent = [int](($processed / $totalEntries) * 100)
                }
                else {
                    $percent = 0
                }

                Write-Progress -Id 2 `
                    -Activity "Enumerating HKCU COM Hijacks" `
                    -Status ("Processing {0} of {1}" -f $processed,$totalEntries) `
                    -PercentComplete $percent

                try {

                    $guidKey = $entry.PSPath

                    $inproc = Join-Path $guidKey "InprocServer32"
                    $local  = Join-Path $guidKey "LocalServer32"

                    foreach ($serverKey in @($inproc,$local)) {

                        if (-not (Test-Path $serverKey -ErrorAction SilentlyContinue)) { continue }

                        $def = (Get-ItemProperty -Path $serverKey -ErrorAction SilentlyContinue).'(default)'
                        if (-not $def) { continue }

                        $target = fncTryResolvePath $def
                        $ctx = "HKCU COM server $serverKey -> $def"

                        fncAddPresenceFinding `
                            -Id ("USERPERSIST_COM_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($serverKey)) -replace '[^A-Za-z0-9]','')) `
                            -Title "HKCU COM Server Present" `
                            -Message $ctx

                        if ($target) {

                            if (fncCheckWritableTarget `
                                    -TargetPath $target `
                                    -Context $ctx `
                                    -FindingPrefix "USERPERSIST_COM_WRITABLE" `
                                    -Title "Writable HKCU COM Server Target" `
                                    -Recommendation "Investigate COM registration and restrict write permissions.") {

                                $hitCount++
                            }
                        }
                    }

                } catch {}
            }

            Write-Progress -Id 2 -Completed
        }

    }
    catch {
        fncPrintMessage "Failed enumerating HKCU CLSID keys." "warning"
    }

}
else {
    fncPrintMessage "HKCU CLSID hive not present." "info"
}

fncPrintMessage "" "plain"


    # ==========================================================
    # 6) User services persistence (HKCU service-ish locations)
    # ==========================================================
    fncPrintSectionHeader "User Services Persistence (Heuristic)"

    # Windows 10/11 support per-user services (registered under HKLM generally),
    # but HKCU persistence often manifests via Run keys / tasks / COM. We still
    # check common "Services" keys under HKCU if present in odd builds.
    $hkcuServices = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServices",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
    )

    foreach ($k in $hkcuServices) {
        try {
            if (-not (Test-Path $k -ErrorAction SilentlyContinue)) { continue }

            $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
            if (-not $props) { continue }

            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -like "PS*") { continue }

                $val = [string]$prop.Value
                if (-not $val) { continue }

                $exeRaw = fncGetExecutableFromCommandLine $val
                $target = fncTryResolvePath $exeRaw
                $ctx = "RunServices entry '$($prop.Name)' in '$k' -> $val"

                fncAddPresenceFinding `
                    -Id ("USERPERSIST_RUNSERV_PRESENT_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($k+$prop.Name)) -replace '[^A-Za-z0-9]','')) `
                    -Title "HKCU RunServices Entry Present" `
                    -Message $ctx

                if ($target) {
                    if (fncCheckWritableTarget `
                            -TargetPath $target `
                            -Context $ctx `
                            -FindingPrefix "USERPERSIST_RUNSERV_WRITABLE" `
                            -Title "Writable RunServices Target" `
                            -Recommendation "Restrict write permissions and remove unapproved entries.") {
                        $hitCount++
                    }
                }
            }
        } catch {}
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # 7) Explorer load hijacks (HKCU)
    # ==========================================================
    fncPrintSectionHeader "Explorer Load Points (HKCU)"

    $explorerKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
    )

    foreach ($k in $explorerKeys) {
        try {
            if (-not (Test-Path $k -ErrorAction SilentlyContinue)) { continue }

            if ($k -like "*\Windows") {
                # Common value: Load / Run
                $ip = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                foreach ($valName in @("Load","Run")) {
                    $v = $null
                    try { $v = [string]$ip.$valName } catch { $v = $null }
                    if (-not $v) { continue }

                    $exeRaw = fncGetExecutableFromCommandLine $v
                    $target = fncTryResolvePath $exeRaw
                    $ctx = "Explorer $k value '$valName' -> $v"

                    fncAddPresenceFinding `
                        -Id ("USERPERSIST_EXPLORER_" + ($valName -replace '[^A-Za-z0-9]','')) `
                        -Title "Explorer Load/Run Value Present" `
                        -Message $ctx

                    if ($target) {
                        if (fncCheckWritableTarget `
                                -TargetPath $target `
                                -Context $ctx `
                                -FindingPrefix "USERPERSIST_EXPLORER_WRITABLE" `
                                -Title "Writable Explorer Load Target" `
                                -Recommendation "Remove unapproved Load/Run entries; restrict write permissions.") {
                            $hitCount++
                        }
                    }
                }
            }
            else {
                # Policies\Explorer\Run contains named values
                $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -like "PS*") { continue }

                    $v = [string]$prop.Value
                    if (-not $v) { continue }

                    $exeRaw = fncGetExecutableFromCommandLine $v
                    $target = fncTryResolvePath $exeRaw
                    $ctx = "Explorer policy run '$($prop.Name)' -> $v"

                    fncAddPresenceFinding `
                        -Id ("USERPERSIST_EXPLORERPOL_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($k+$prop.Name)) -replace '[^A-Za-z0-9]','')) `
                        -Title "Explorer Policy Run Entry Present" `
                        -Message $ctx

                    if ($target) {
                        if (fncCheckWritableTarget `
                                -TargetPath $target `
                                -Context $ctx `
                                -FindingPrefix "USERPERSIST_EXPLORERPOL_WRITABLE" `
                                -Title "Writable Explorer Policy Run Target" `
                                -Recommendation "Remove unapproved policy run entries; restrict write permissions.") {
                            $hitCount++
                        }
                    }
                }
            }
        } catch {}
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # 8) OneDrive autorun abuse (HKCU)
    # ==========================================================
    fncPrintSectionHeader "OneDrive Autorun (HKCU)"

    $oneDriveKeys = @(
        "HKCU:\Software\Microsoft\OneDrive",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($k in $oneDriveKeys) {
        try {
            if (-not (Test-Path $k -ErrorAction SilentlyContinue)) { continue }

            if ($k -like "*\Run") {
                # look for OneDrive values in Run
                $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
                if (-not $props) { continue }

                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -like "PS*") { continue }

                    if ($prop.Name -notmatch "OneDrive") { continue }

                    $v = [string]$prop.Value
                    if (-not $v) { continue }

                    $exeRaw = fncGetExecutableFromCommandLine $v
                    $target = fncTryResolvePath $exeRaw
                    $ctx = "OneDrive Run entry '$($prop.Name)' -> $v"

                    fncAddPresenceFinding `
                        -Id ("USERPERSIST_ONEDRIVE_RUN_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($k+$prop.Name)) -replace '[^A-Za-z0-9]','')) `
                        -Title "OneDrive Autorun Entry Present" `
                        -Message $ctx

                    if ($target) {
                        if (fncCheckWritableTarget `
                                -TargetPath $target `
                                -Context $ctx `
                                -FindingPrefix "USERPERSIST_ONEDRIVE_WRITABLE" `
                                -Title "Writable OneDrive Autorun Target" `
                                -Recommendation "Restrict write permissions; review OneDrive startup configuration.") {
                            $hitCount++
                        }
                    }
                }
            }
        } catch {}
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # 9) Office Add-ins (HKCU)
    # ==========================================================
    fncPrintSectionHeader "Office Add-ins (HKCU)"

    $officeAddinRoots = @(
        "HKCU:\Software\Microsoft\Office",
        "HKCU:\Software\WOW6432Node\Microsoft\Office"
    )

    foreach ($root in $officeAddinRoots) {

        try {

            if (-not (Test-Path $root -ErrorAction SilentlyContinue)) { continue }

            # Look for ...\Addins keys anywhere under Office (best-effort; can be large)
            Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.PSPath -match "\\Addins$" } |
                ForEach-Object {

                    try {

                        $addinsKey = $_.PSPath
                        Write-Host ("  -> {0}" -f $addinsKey) -ForegroundColor Cyan

                        Get-ChildItem -Path $addinsKey -ErrorAction SilentlyContinue | ForEach-Object {

                            try {

                                $addin = $_.PSPath
                                $ip = Get-ItemProperty -Path $addin -ErrorAction SilentlyContinue
                                if (-not $ip) { return }

                                # Common value names
                                $manifest = $null
                                $loadBehavior = $null

                                try { $manifest = [string]$ip.Manifest } catch {}
                                try { $loadBehavior = [string]$ip.LoadBehavior } catch {}

                                $ctx = "Office Add-in '$addin' LoadBehavior=$loadBehavior Manifest=$manifest"

                                fncAddPresenceFinding `
                                    -Id ("USERPERSIST_OFFICEADDIN_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($addin)) -replace '[^A-Za-z0-9]','')) `
                                    -Title "Office Add-in Present" `
                                    -Message $ctx

                                if ($manifest) {
                                    # Manifest can be file path or URL; handle file path best-effort
                                    $target = fncTryResolvePath $manifest
                                    if ($target) {
                                        if (fncCheckWritableTarget `
                                                -TargetPath $target `
                                                -Context $ctx `
                                                -FindingPrefix "USERPERSIST_OFFICEADDIN_WRITABLE" `
                                                -Title "Writable Office Add-in Manifest" `
                                                -Recommendation "Restrict write permissions; remove unapproved add-ins.") {
                                            $hitCount++
                                        }
                                    }
                                }
                            } catch { return }
                        }
                    } catch { return }
                }

        } catch {}
    }

    fncPrintMessage "" "plain"

    # ==========================================================
    # Summary
    # ==========================================================
    if ($hitCount -eq 0) {
        fncPrintMessage "No obvious writable user persistence targets detected." "success"

        fncAddFinding `
            -Id "USERPERSIST_PLUS_NONE" `
            -Category "Persistence" `
            -Title "No Writable User Persistence Targets Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No user-level persistence entries with writable targets were identified." `
            -Recommendation "No action required."
    }
    else {
        fncPrintMessage ("Found {0} writable user persistence targets." -f $hitCount) "warning"
    }

    fncPrintMessage "" "plain"
}

Export-ModuleMember -Function fncGetUserPersistencePoints
