# ================================================================
# Function: fncGetScheduledTaskPrivEscCandidates
# Purpose : Identify high privilege scheduled tasks with writable action targets
# ================================================================
function fncGetScheduledTaskPrivEscCandidates {

    fncPrintMessage "Scanning scheduled tasks for high privilege principals and writable action targets..." "info"
    fncPrintMessage "Initialising scheduled task privilege escalation scan." "debug"
    Write-Host ""

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUser     = $currentIdentity.Name

    fncPrintMessage ("Current identity: {0}" -f $currentUser) "debug"

    # ----------------------------------------------------------
    # Helper: Extract Executable From Command Line
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

    $hits = @()

    # ----------------------------------------------------------
    # Validate Scheduled Task Cmdlet
    # ----------------------------------------------------------
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {

        fncPrintMessage "Get-ScheduledTask cmdlet not available." "warning"
        fncPrintMessage "Cannot enumerate scheduled tasks via native cmdlet." "debug"

        $fingerprint = "SCHEDTASK_CMDLET_MISSING"
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("SCHEDTASK_CMDLET_MISSING_$tag") `
            -Category "Privilege Escalation" `
            -Title "Scheduled Task Cmdlet Not Available" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Get-ScheduledTask cmdlet is not available on this system." `
            -Recommendation "Upgrade PowerShell or query tasks via alternate methods."

        return
    }

    # ----------------------------------------------------------
    # Enumerate Scheduled Tasks
    # ----------------------------------------------------------
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        fncPrintMessage ("Enumerated scheduled tasks: {0}" -f (($tasks | Measure-Object).Count)) "debug"
    }
    catch {

        fncPrintMessage "Failed to enumerate scheduled tasks." "warning"
        fncPrintMessage ("Scheduled task enumeration exception: {0}" -f $_.Exception.Message) "debug"

        $fingerprint = "SCHEDTASK_ENUM_FAILED"
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("SCHEDTASK_ENUM_FAILED_$tag") `
            -Category "Privilege Escalation" `
            -Title "Scheduled Task Enumeration Failed" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Unable to enumerate scheduled tasks." `
            -Recommendation "Verify permissions." `
            -Evidence $_.Exception.Message

        return
    }

    foreach ($task in $tasks) {

        try {

            if ($task.State -eq "Disabled") {
                fncPrintMessage ("Skipping disabled task: {0}{1}" -f $task.TaskPath,$task.TaskName) "debug"
                continue
            }

            $principal = $task.Principal
            $userId    = fncSafeString $principal.UserId
            $runLevel  = fncSafeString $principal.RunLevel

            fncPrintMessage ("Evaluating task: {0}{1} (UserId={2}, RunLevel={3})" -f `
                $task.TaskPath,$task.TaskName,$userId,$runLevel) "debug"

            # ------------------------------------------------------
            # Determine High Privilege Principal
            # ------------------------------------------------------
            $isHighPrivPrincipal = $false

            if ($userId -match "SYSTEM" -or
                $userId -match "LocalService" -or
                $userId -match "NetworkService") {

                $isHighPrivPrincipal = $true
                fncPrintMessage "Principal classified as built-in high privilege." "debug"
            }
            elseif ($runLevel -eq "Highest") {
                $isHighPrivPrincipal = $true
                fncPrintMessage "Principal classified as high privilege via RunLevel Highest." "debug"
            }

            if (-not $isHighPrivPrincipal) {
                fncPrintMessage "Skipping task (not high privilege)." "debug"
                continue
            }

            # ------------------------------------------------------
            # Inspect Task Actions
            # ------------------------------------------------------
            foreach ($action in $task.Actions) {

                try {

                    if (-not $action.Execute) {
                        fncPrintMessage "Task action has no Execute target. Skipping." "debug"
                        continue
                    }

                    $cmdline = $action.Execute + " " + (fncSafeString $action.Arguments)
                    fncPrintMessage ("Task command line: {0}" -f $cmdline) "debug"

                    $exePathRaw = fncGetExecutableFromCommandLine -CommandLine $cmdline
                    if (-not $exePathRaw) {
                        fncPrintMessage "Executable could not be parsed from command line." "debug"
                        continue
                    }

                    $expanded = [Environment]::ExpandEnvironmentVariables($exePathRaw)
                    fncPrintMessage ("Expanded executable path: {0}" -f $expanded) "debug"

                    if (-not (Test-Path $expanded -ErrorAction SilentlyContinue)) {
                        fncPrintMessage "Executable path does not exist. Skipping." "debug"
                        continue
                    }

                    $fullPath = (Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue).FullName
                    if (-not $fullPath) {
                        fncPrintMessage "Resolved executable path was null." "debug"
                        continue
                    }

                    $acl   = Get-Acl -LiteralPath $fullPath -ErrorAction SilentlyContinue
                    if (-not $acl) {
                        fncPrintMessage "Failed retrieving ACL for executable." "debug"
                        continue
                    }

                    $owner = fncSafeString $acl.Owner

                    $fileWritable = Test-CurrentUserCanModifyPath -Path $fullPath
                    $dirPath      = [System.IO.Path]::GetDirectoryName($fullPath)

                    $dirWritable  = $false
                    if ($dirPath) {
                        $dirWritable = Test-CurrentUserCanModifyPath -Path $dirPath
                    }

                    fncPrintMessage ("Writable check -> File:{0} Dir:{1}" -f $fileWritable,$dirWritable) "debug"

                    if (-not $fileWritable -and -not $dirWritable) {
                        fncPrintMessage "Writable check failed. Skipping task." "debug"
                        continue
                    }

                    # --------------------------------------------------
                    # Writable Location Tracking
                    # --------------------------------------------------
                    $writableWhere = @()
                    if ($fileWritable) { $writableWhere += "file" }
                    if ($dirWritable)  { $writableWhere += "directory" }

                    $msg = "Task '$($task.TaskPath)$($task.TaskName)' runs as '$userId' (RunLevel=$runLevel) " +
                           "with action '$cmdline' (Owner=$owner). Writable by $currentUser via $($writableWhere -join ', ')."

                    Write-Host ("[!] High-priv scheduled task candidate: {0}" -f $msg) -ForegroundColor Red

                    fncPrintMessage "Privilege escalation candidate identified." "debug"

                    $fingerprint = $task.TaskPath + $task.TaskName
                    $tag = fncShortHashTag $fingerprint

                    fncAddFinding `
                        -Id ("SCHEDTASK_PRIVESC_$tag") `
                        -Category "Privilege Escalation" `
                        -Title "Writable High Privilege Scheduled Task" `
                        -Severity "High" `
                        -Status "Detected" `
                        -Message "Scheduled task runs with elevated privileges and references a writable executable or directory." `
                        -Recommendation "Restrict file or directory permissions and review task configuration." `
                        -Evidence $msg

                    $hits += [PSCustomObject]@{
                        TaskName    = $task.TaskName
                        TaskPath    = $task.TaskPath
                        Principal   = $userId
                        RunLevel    = $runLevel
                        CommandLine = $cmdline
                        Executable  = $fullPath
                        Owner       = $owner
                        WritableVia = ($writableWhere -join ", ")
                    }
                }
                catch {
                    fncPrintMessage ("Exception processing task action: {0}" -f $_.Exception.Message) "debug"
                    continue
                }
            }
        }
        catch {
            fncPrintMessage ("Exception processing task: {0}" -f $_.Exception.Message) "debug"
            continue
        }
    }

    # ----------------------------------------------------------
    # Results Summary
    # ----------------------------------------------------------
    if ($hits.Count -eq 0) {

        fncPrintMessage "No scheduled task privilege escalation candidates detected." "success"
        fncPrintMessage "Scheduled task scan completed with zero findings." "debug"

        $fingerprint = "SCHEDTASK_NO_PRIVESC"
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("SCHEDTASK_NO_PRIVESC_$tag") `
            -Category "Privilege Escalation" `
            -Title "No Writable High Privilege Scheduled Tasks Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No scheduled tasks with writable elevated execution paths were identified." `
            -Recommendation "No action required."

        return
    }

    fncPrintSectionHeader "Writable High Privilege Scheduled Tasks"

    foreach ($h in $hits) {

        Write-Host ("Task      : {0}{1}" -f $h.TaskPath,$h.TaskName)
        Write-Host ("Principal : {0}" -f $h.Principal)
        Write-Host ("RunLevel  : {0}" -f $h.RunLevel)
        Write-Host ("Command   : {0}" -f $h.CommandLine)
        Write-Host ("Executable: {0}" -f $h.Executable)
        Write-Host ("Owner     : {0}" -f $h.Owner)
        Write-Host ("Writable  : {0}" -f $h.WritableVia)
        Write-Host ("Exploit   : Modify or replace executable or drop file into writable directory.")
        Write-Host "-------------------------------------------"
    }

    fncPrintMessage ("Found {0} writable high privilege scheduled tasks." -f $hits.Count) "warning"
    fncPrintMessage "Scheduled task privilege escalation scan completed." "debug"
}

Export-ModuleMember -Function fncGetScheduledTaskPrivEscCandidates
