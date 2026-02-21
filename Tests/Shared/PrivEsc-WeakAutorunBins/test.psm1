# ================================================================
# Function: fncGetWeakAutoRunBinaries
# Purpose : Identify SYSTEM-owned autorun executables writable by current user
# Notes   : Reviews Run keys, Services, and Scheduled Tasks
# ================================================================
function fncGetWeakAutoRunBinaries {

    fncPrintMessage "Scanning autoruns for SYSTEM-owned executables writable by current user..." "info"
    fncPrintMessage "Initialising autorun enumeration routine." "debug"
    Write-Host ""

    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    fncPrintMessage ("Current user context: {0}" -f $currentUser) "debug"

    # ----------------------------------------------------------
    # Interesting root locations
    # ----------------------------------------------------------
    $interestingRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        (Join-Path $env:USERPROFILE "AppData"),
        (Join-Path $env:USERPROFILE "AppData\Local"),
        (Join-Path $env:USERPROFILE "AppData\Roaming"),
        (Join-Path $env:USERPROFILE "AppData\LocalLow")
    ) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }

    fncPrintMessage ("Interesting root paths resolved: {0}" -f $interestingRoots.Count) "debug"

    # ----------------------------------------------------------
    # Helper: Extract executable
    # ----------------------------------------------------------
    function fncGetExecutableFromCommandLine {
        param([string]$CommandLine)

        if (-not $CommandLine) { return $null }

        $cmd = $CommandLine.Trim()

        if ($cmd -match '^\s*"(.*?)"') {
            return $matches[1]
        }

        return $cmd.Split(" ")[0]
    }

    $results  = @()
    $findings = @()

    # ----------------------------------------------------------
    # Registry Run Keys
    # ----------------------------------------------------------
    $runKeys = @(
        @{ Hive = "HKCU"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKCU"; Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "HKLM"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKLM"; Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" }
    )

    fncPrintMessage ("Enumerating registry autorun keys ({0} locations)." -f $runKeys.Count) "debug"

    foreach ($rk in $runKeys) {
        try {

            if (-not (Test-Path $rk.Path -ErrorAction SilentlyContinue)) {
                fncPrintMessage ("Registry path not found: {0}" -f $rk.Path) "debug"
                continue
            }

            $itemProps = Get-ItemProperty -Path $rk.Path -ErrorAction SilentlyContinue
            if (-not $itemProps) { continue }

            foreach ($prop in $itemProps.PSObject.Properties) {

                if ($prop.Name -in @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")) { continue }

                $value = fncSafeString $prop.Value
                if (-not $value) { continue }

                $exePathRaw = fncGetExecutableFromCommandLine $value
                if (-not $exePathRaw) { continue }

                $expanded = [Environment]::ExpandEnvironmentVariables($exePathRaw)

                fncPrintMessage ("Autorun entry found (Registry): {0}" -f $expanded) "debug"

                $results += [PSCustomObject]@{
                    Source      = "RegistryRun"
                    Hive        = $rk.Hive
                    Location    = $rk.Path
                    Name        = $prop.Name
                    CommandLine = $value
                    Executable  = $expanded
                }
            }
        }
        catch {
            fncPrintMessage ("Error processing registry autorun key {0}: {1}" -f $rk.Path,$_.Exception.Message) "debug"
            continue
        }
    }

    # ----------------------------------------------------------
    # Services (Auto Start)
    # ----------------------------------------------------------
    try {

        fncPrintMessage "Enumerating auto-start services..." "debug"

        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
                    Where-Object { $_.StartMode -eq "Auto" }

        foreach ($svc in fncSafeArray $services) {

            $pathName = fncSafeString $svc.PathName
            if (-not $pathName) { continue }

            $exePathRaw = fncGetExecutableFromCommandLine $pathName
            if (-not $exePathRaw) { continue }

            $expanded = [Environment]::ExpandEnvironmentVariables($exePathRaw)

            fncPrintMessage ("Autorun entry found (Service): {0}" -f $expanded) "debug"

            $results += [PSCustomObject]@{
                Source      = "Service"
                Hive        = "N/A"
                Location    = ("Service: {0}" -f $svc.Name)
                Name        = $svc.Name
                CommandLine = $pathName
                Executable  = $expanded
            }
        }
    }
    catch {
        fncPrintMessage ("Service enumeration error: {0}" -f $_.Exception.Message) "debug"
    }

    # ----------------------------------------------------------
    # Scheduled Tasks
    # ----------------------------------------------------------
    try {

        if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {

            fncPrintMessage "Enumerating scheduled tasks..." "debug"

            $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

            foreach ($task in fncSafeArray $tasks) {

                if ($task.State -eq "Disabled") { continue }

                foreach ($action in fncSafeArray $task.Actions) {

                    if (-not $action.Execute) { continue }

                    $exePathRaw = fncGetExecutableFromCommandLine $action.Execute
                    if (-not $exePathRaw) { continue }

                    $expanded = [Environment]::ExpandEnvironmentVariables($exePathRaw)

                    fncPrintMessage ("Autorun entry found (Scheduled Task): {0}" -f $expanded) "debug"

                    $results += [PSCustomObject]@{
                        Source      = "ScheduledTask"
                        Hive        = "N/A"
                        Location    = ("Task: {0}{1}" -f $task.TaskPath,$task.TaskName)
                        Name        = $task.TaskName
                        CommandLine = ($action.Execute + " " + (fncSafeString $action.Arguments))
                        Executable  = $expanded
                    }
                }
            }
        }
    }
    catch {
        fncPrintMessage ("Scheduled task enumeration error: {0}" -f $_.Exception.Message) "debug"
    }

    # ----------------------------------------------------------
    # Filter results
    # ----------------------------------------------------------
    if ($results.Count -eq 0) {
        fncPrintMessage "No autorun entries found to analyse." "info"
        fncPrintMessage "Autorun results collection returned zero entries." "debug"
        return
    }

    fncPrintMessage ("Collected {0} raw autorun entries before filtering." -f $results.Count) "debug"

    $results = $results |
        Where-Object {
            $_.Executable -match '\.(exe|bat|cmd|ps1)$'
        } |
        Sort-Object Executable, Source, Location -Unique

    fncPrintMessage ("Autorun entries after filtering executable types: {0}" -f $results.Count) "debug"

    # ----------------------------------------------------------
    # Evaluate Permissions
    # ----------------------------------------------------------
    foreach ($entry in $results) {

        try {

            if (-not (Test-Path $entry.Executable -ErrorAction SilentlyContinue)) {
                fncPrintMessage ("Executable path missing: {0}" -f $entry.Executable) "debug"
                continue
            }

            $fullPath = (Get-Item -LiteralPath $entry.Executable -ErrorAction SilentlyContinue).FullName
            if (-not $fullPath) { continue }

            fncPrintMessage ("Evaluating ACLs for: {0}" -f $fullPath) "debug"

            $underInterestingRoot = $false
            $lowerPath = $fullPath.ToLowerInvariant()

            foreach ($root in $interestingRoots) {
                if ($lowerPath.StartsWith($root.ToLowerInvariant())) {
                    $underInterestingRoot = $true
                    break
                }
            }

            if (-not $underInterestingRoot) {
                fncPrintMessage ("Path outside interesting roots: {0}" -f $fullPath) "debug"
                continue
            }

            $acl   = Get-Acl -LiteralPath $fullPath -ErrorAction SilentlyContinue
            if (-not $acl) { continue }

            $owner = fncSafeString $acl.Owner
            fncPrintMessage ("Owner of {0} => {1}" -f $fullPath,$owner) "debug"

            if ($owner -notmatch "SYSTEM") { continue }

            $fileWritable = Test-CurrentUserCanModifyPath -Path $fullPath

            $dirPath     = [System.IO.Path]::GetDirectoryName($fullPath)
            $dirWritable = $false
            if ($dirPath) {
                $dirWritable = Test-CurrentUserCanModifyPath -Path $dirPath
            }

            if (-not ($fileWritable -or $dirWritable)) {
                fncPrintMessage ("No writable permissions detected for {0}" -f $fullPath) "debug"
                continue
            }

            $writableWhere = @()
            if ($fileWritable) { $writableWhere += "file" }
            if ($dirWritable)  { $writableWhere += "directory" }

            fncPrintMessage ("Writable autorun candidate identified: {0} via {1}" -f $fullPath,($writableWhere -join ", ")) "debug"

            $findingText = "Autorun target '$fullPath' (Owner=$owner) is writable by $currentUser via $($writableWhere -join ', '). " +
                           "Source=$($entry.Source), Location=$($entry.Location)"

            Write-Host ("[!] Potential priv-esc: {0}" -f $findingText) -ForegroundColor Red

            $findingId = "WEAK_AUTORUN_" + (
                [Convert]::ToBase64String(
                    [Text.Encoding]::UTF8.GetBytes($fullPath)
                ) -replace '[^A-Za-z0-9]',''
            )

            fncAddFinding `
                -Id $findingId `
                -Category "Privilege Escalation" `
                -Title "SYSTEM Autorun Binary Writable By Current User" `
                -Severity "High" `
                -Status "Detected" `
                -Message "SYSTEM-owned autorun executable is writable by the current user." `
                -Recommendation "Fix ACLs on executable or directory and validate startup persistence chain." `
                -Evidence $findingText

            $findings += [PSCustomObject]@{
                Source     = $entry.Source
                Location   = $entry.Location
                Executable = $fullPath
                Owner      = $owner
                Writable   = ($writableWhere -join ", ")
            }
        }
        catch {
            fncPrintMessage ("Error evaluating autorun entry {0}: {1}" -f $entry.Executable,$_.Exception.Message) "debug"
            continue
        }
    }

    # ----------------------------------------------------------
    # Summary
    # ----------------------------------------------------------
    if ($findings.Count -eq 0) {

        fncPrintMessage "No SYSTEM-owned writable autorun binaries detected." "success"
        fncPrintMessage "ACL evaluation completed with zero privilege escalation findings." "debug"

        fncAddFinding `
            -Id "WEAK_AUTORUN_NONE" `
            -Category "Privilege Escalation" `
            -Title "No Weak Autorun Binaries Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No SYSTEM-owned autorun binaries were writable by the current user." `
            -Recommendation "No action required."

        return
    }

    fncPrintSectionHeader "Weak Autorun Binary Candidates"
    fncPrintMessage "Displaying identified autorun privilege escalation candidates." "debug"

    foreach ($f in $findings) {
        Write-Host ("Source     : {0}" -f $f.Source)
        Write-Host ("Location   : {0}" -f $f.Location)
        Write-Host ("Executable : {0}" -f $f.Executable)
        Write-Host ("Owner      : {0}" -f $f.Owner)
        Write-Host ("Writable   : {0}" -f $f.Writable)
        Write-Host "----------------------------------------"
    }

    fncPrintMessage ("Found {0} potential autorun privilege escalation candidates." -f $findings.Count) "warning"
    fncPrintMessage "Autorun enumeration routine completed." "debug"
}

Export-ModuleMember -Function fncGetWeakAutoRunBinaries
