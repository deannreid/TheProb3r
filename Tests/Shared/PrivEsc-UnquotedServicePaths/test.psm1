# ================================================================
# Function: fncGetUnquotedServicePaths
# Purpose : Detect unquoted service paths with writable segments
# ================================================================
function fncGetUnquotedServicePaths {

    fncPrintMessage "Scanning for unquoted service paths with writable segments..." "info"
    fncPrintMessage "Initialising unquoted service path analysis." "debug"
    fncPrintMessage "" "plain"

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $currentUser     = $currentIdentity.Name

    fncPrintMessage ("Current user context: {0}" -f $currentUser) "debug"

    $hits = @()
    $serviceCount = 0

    # ----------------------------------------------------------
    # Enumerate Services
    # ----------------------------------------------------------
    try {
        fncPrintMessage "Enumerating Win32_Service instances via CIM." "debug"
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        fncPrintMessage ("Total services retrieved: {0}" -f $services.Count) "debug"
    }
    catch {

        fncPrintMessage "Failed to enumerate services." "warning"
        fncPrintMessage ("Service enumeration exception: {0}" -f $_.Exception.Message) "debug"

        fncAddFinding `
            -Id "UNQUOTED_SERVICE_ENUM_FAILED" `
            -Category "Privilege Escalation" `
            -Title "Service Enumeration Failed" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Unable to enumerate Windows services." `
            -Recommendation "Verify permissions or WMI availability." `
            -Evidence $_.Exception.Message

        return
    }

    foreach ($svc in $services) {

        $serviceCount++

        try {

            $pathName = fncSafeString $svc.PathName
            if (-not $pathName) {
                fncPrintMessage ("Service '{0}' has empty PathName." -f $svc.Name) "debug"
                continue
            }

            $trimmed = $pathName.Trim()

            fncPrintMessage ("Evaluating service '{0}' path: {1}" -f $svc.Name,$trimmed) "debug"

            # Must be unquoted, contain spaces, and reference an EXE
            if ($trimmed.StartsWith('"')) {
                fncPrintMessage ("Skipping quoted path for service '{0}'." -f $svc.Name) "debug"
                continue
            }

            if ($trimmed -notmatch "\.exe") {
                fncPrintMessage ("Skipping non-executable path for service '{0}'." -f $svc.Name) "debug"
                continue
            }

            if ($trimmed -notmatch ' ') {
                fncPrintMessage ("Skipping service '{0}' because path contains no spaces." -f $svc.Name) "debug"
                continue
            }

            # Extract executable portion
            $exePart = $trimmed.Substring(0, $trimmed.IndexOf(".exe") + 4)

            fncPrintMessage ("Executable portion extracted: {0}" -f $exePart) "debug"

            $components = $exePart -split '\\'
            if ($components.Count -lt 2) {
                fncPrintMessage ("Skipping malformed path for service '{0}'." -f $svc.Name) "debug"
                continue
            }

            # ------------------------------------------------------
            # Build Candidate Partial Paths
            # ------------------------------------------------------
            $partialPaths = @()
            $current = $components[0]

            for ($i = 1; $i -lt $components.Count; $i++) {
                $current = "$current\$($components[$i])"
                $partialPaths += $current
            }

            fncPrintMessage ("Generated {0} partial path candidates for '{1}'." -f $partialPaths.Count,$svc.Name) "debug"

            $writableCandidates = @()

            foreach ($p in $partialPaths) {

                if ($p -notmatch ' ') { continue }

                $dirName  = [System.IO.Path]::GetDirectoryName($p)
                $fileName = [System.IO.Path]::GetFileName($p)

                if (-not $dirName) { continue }

                fncPrintMessage ("Testing directory write access: {0}" -f $dirName) "debug"

                $dirWritable = Test-CurrentUserCanModifyPath -Path $dirName

                if ($dirWritable) {
                    fncPrintMessage ("Writable directory discovered: {0}" -f $dirName) "debug"

                    $writableCandidates += [PSCustomObject]@{
                        Directory = $dirName
                        FileName  = $fileName
                    }
                }
            }

            # ------------------------------------------------------
            # Record Findings
            # ------------------------------------------------------
            if ($writableCandidates.Count -gt 0) {

                foreach ($wc in $writableCandidates) {

                    $msg = "Service '$($svc.Name)' (DisplayName='$($svc.DisplayName)') has unquoted path '$pathName'. " +
                           "User $currentUser can write to '$($wc.Directory)' and potentially create '$($wc.FileName)'."

                    fncPrintMessage ("Unquoted path vulnerability identified for service '{0}'." -f $svc.Name) "debug"

                    Write-Host ("[!] Unquoted service path vulnerability: {0}" -f $msg) -ForegroundColor Red

                    $findingId = "UNQUOTED_SVC_PATH_" + (
                        [Convert]::ToBase64String(
                            [Text.Encoding]::UTF8.GetBytes($svc.Name)
                        ) -replace '[^A-Za-z0-9]',''
                    )

                    fncAddFinding `
                        -Id $findingId `
                        -Category "Privilege Escalation" `
                        -Title "Unquoted Service Path Vulnerability" `
                        -Severity "High" `
                        -Status "Detected" `
                        -Message "Service executable path is unquoted and contains user-writable segments." `
                        -Recommendation "Quote service paths and restrict directory write permissions." `
                        -Evidence $msg

                    $hits += [PSCustomObject]@{
                        ServiceName  = fncSafeString $svc.Name
                        DisplayName  = fncSafeString $svc.DisplayName
                        PathName     = $pathName
                        WritableDir  = $wc.Directory
                        CandidateExe = $wc.FileName
                    }
                }
            }
        }
        catch {
            fncPrintMessage ("Error processing service '{0}': {1}" -f $svc.Name,$_.Exception.Message) "debug"
            continue
        }
    }

    # ----------------------------------------------------------
    # Summary
    # ----------------------------------------------------------
    fncPrintMessage "" "plain"
    fncPrintMessage ("Unquoted service path scan complete. Services inspected: {0}" -f $serviceCount) "info"
    fncPrintMessage ("Total vulnerable candidates identified: {0}" -f $hits.Count) "debug"

    if ($hits.Count -eq 0) {

        fncPrintMessage "No exploitable unquoted service path vulnerabilities detected." "success"

        fncAddFinding `
            -Id "UNQUOTED_SERVICE_PATH_NONE" `
            -Category "Privilege Escalation" `
            -Title "No Unquoted Service Path Vulnerabilities Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No unquoted service paths with writable directory segments were identified." `
            -Recommendation "No action required."

        return
    }

    fncPrintSectionHeader "Unquoted Service Path Candidates"
    fncPrintMessage "Displaying vulnerable service path candidates." "debug"

    foreach ($h in $hits) {

        Write-Host ("Service   : {0} ({1})" -f $h.ServiceName,$h.DisplayName)
        Write-Host ("Path      : {0}" -f $h.PathName)
        Write-Host ("Writable  : {0}" -f $h.WritableDir)
        Write-Host ("Candidate : {0}" -f $h.CandidateExe)
        Write-Host ("Exploit   : Drop executable into writable directory and restart service or reboot.")
        Write-Host "-------------------------------------------"
    }

    fncPrintMessage ("Found {0} potential unquoted service path exploitation opportunities." -f $hits.Count) "warning"
    fncPrintMessage "Unquoted service path analysis completed." "debug"
}

Export-ModuleMember -Function fncGetUnquotedServicePaths
