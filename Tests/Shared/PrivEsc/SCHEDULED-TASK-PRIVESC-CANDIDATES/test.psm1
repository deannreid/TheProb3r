# ================================================================
# Function: fncGetScheduledTaskPrivEscCandidates
# Purpose : Identify high privilege scheduled tasks with writable action targets
# ================================================================
function fncGetScheduledTaskPrivEscCandidates {

    fncPrintMessage "Scanning scheduled tasks for writable elevated execution paths..." "info"
    fncPrintMessage "Initialising scheduled task privilege escalation scan (v5)." "debug"
    Write-Host ""
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

    # ----------------------------------------------------------
    # Validate Cmdlet
    # ----------------------------------------------------------
    if (-not (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue)) {

        fncAddFinding `
            -Id ("SCHEDTASK_CMDLET_MISSING_" + (fncShortHashTag "CMDLET_MISSING")) `
            -Category "Privilege Escalation" `
            -Title "Scheduled Task Cmdlet Not Available" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Get-ScheduledTask cmdlet is not available." `
            -Recommendation "Upgrade PowerShell or use alternate enumeration."

        return
    }

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    }
    catch {

        fncAddFinding `
            -Id ("SCHEDTASK_ENUM_FAILED_" + (fncShortHashTag "ENUM_FAIL")) `
            -Category "Privilege Escalation" `
            -Title "Scheduled Task Enumeration Failed" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Unable to enumerate scheduled tasks." `
            -Recommendation "Verify permissions." `
            -Evidence $_.Exception.Message

        return
    }

    $found = $false

    foreach ($task in $tasks) {

        try {

            if ($task.State -eq "Disabled") { continue }

            $principal = $task.Principal
            $userId    = fncSafeString $principal.UserId
            $runLevel  = fncSafeString $principal.RunLevel

            $isHighPriv = $false

            if ($userId -match "SYSTEM" -or
                $userId -match "LocalService" -or
                $userId -match "NetworkService") {
                $isHighPriv = $true
            }
            elseif ($runLevel -eq "Highest") {
                $isHighPriv = $true
            }

            if (-not $isHighPriv) { continue }

            foreach ($action in $task.Actions) {

                if (-not $action.Execute) { continue }

                $cmdline   = $action.Execute + " " + (fncSafeString $action.Arguments)
                $exeRaw    = fncGetExecutableFromCommandLine $cmdline
                if (-not $exeRaw) { continue }

                $expanded  = [Environment]::ExpandEnvironmentVariables($exeRaw)
                if (-not (Test-Path $expanded -ErrorAction SilentlyContinue)) { continue }

                $fullPath  = (Get-Item -LiteralPath $expanded -ErrorAction SilentlyContinue).FullName
                if (-not $fullPath) { continue }

                $fileWritable = Test-CurrentUserCanModifyPath -Path $fullPath
                $dirPath      = [System.IO.Path]::GetDirectoryName($fullPath)
                $dirWritable  = $false

                if ($dirPath) {
                    $dirWritable = Test-CurrentUserCanModifyPath -Path $dirPath
                }

                if (-not $fileWritable -and -not $dirWritable) { continue }

                $found = $true

                $writableWhere = @()
                if ($fileWritable) { $writableWhere += "file" }
                if ($dirWritable)  { $writableWhere += "directory" }

                $evidence = "Task '$($task.TaskPath)$($task.TaskName)' runs as '$userId' (RunLevel=$runLevel) " +
                            "and references '$fullPath' writable via $($writableWhere -join ', ')."

                $fingerprint = $task.TaskPath + $task.TaskName + $fullPath
                $tag = fncShortHashTag $fingerprint

                fncAddFinding `
                    -Id ("SCHEDTASK_PRIVESC_$tag") `
                    -Category "Privilege Escalation" `
                    -Title "Writable High Privilege Scheduled Task" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message "Elevated scheduled task references writable execution path." `
                    -Recommendation "Restrict file/directory permissions or reconfigure task." `
                    -Evidence $evidence
            }
        }
        catch {
            continue
        }
    }

    if (-not $found) {

        fncAddFinding `
            -Id ("SCHEDTASK_NO_PRIVESC_" + (fncShortHashTag "NONE_FOUND")) `
            -Category "Privilege Escalation" `
            -Title "No Writable High Privilege Scheduled Tasks Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No scheduled tasks with writable elevated execution paths were identified." `
            -Recommendation "No action required."
    }

    fncPrintMessage "Scheduled task privilege escalation scan completed." "debug"
}

Export-ModuleMember -Function fncGetScheduledTaskPrivEscCandidates