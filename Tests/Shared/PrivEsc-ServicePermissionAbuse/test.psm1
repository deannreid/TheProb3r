# ================================================================
# Function: fncGetPrivEscServicePermissionAbuse
# Purpose : Detect weak service ACLs allowing privilege escalation
# Notes   : Token-aware service DACL evaluation + heuristic scoring
# ================================================================
function fncGetPrivEscServicePermissionAbuse {

    fncPrintMessage "Enumerating service ACL permissions for potential privilege escalation..." "info"
    fncPrintMessage "Initialising service permission abuse scan." "debug"
    Write-Host ""

    # ==========================================================
    # Helpers
    # ==========================================================
    function fncGetTokenSids {
        try {
            fncPrintMessage "Building token SID set (User + Groups)." "debug"

            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            if (-not $id) {
                fncPrintMessage "WindowsIdentity.GetCurrent() returned null." "debug"
                return $null
            }

            $sids = New-Object System.Collections.Generic.HashSet[string]
            if ($id.User) {
                [void]$sids.Add($id.User.Value)
                fncPrintMessage ("Added user SID: {0}" -f $id.User.Value) "debug"
            }

            foreach ($g in $id.Groups) {
                try {
                    [void]$sids.Add($g.Value)
                } catch {}
            }

            fncPrintMessage ("Token SID set size: {0}" -f $sids.Count) "debug"
            return $sids

        } catch {
            fncPrintMessage ("Failed building token SID set: {0}" -f $_.Exception.Message) "debug"
            return $null
        }
    }

    function fncIsHighPrivServiceAccount {
        param([string]$StartName)

        if (-not $StartName) { return $false }

        return (
            $StartName -match "LocalSystem" -or
            $StartName -match "NT AUTHORITY\\SYSTEM"
        )
    }

    function fncScoreServicePermissionSurface {
        param(
            [bool]$CanChangeConfig,
            [bool]$CanStartStop,
            [bool]$CanWriteDac,
            [bool]$CanWriteOwner,
            [bool]$RunsAsSystem,
            [string]$StartMode
        )

        $score = 0

        if ($CanChangeConfig) { $score += 60 }
        if ($CanStartStop)    { $score += 35 }
        if ($CanWriteDac)     { $score += 50 }
        if ($CanWriteOwner)   { $score += 50 }

        if ($RunsAsSystem) { $score += 25 }
        if ($StartMode -eq "Auto") { $score += 10 }

        if ($score -gt 100) { $score = 100 }
        return $score
    }

    function fncScoreToSeverityAndConfidence {
        param([int]$Score)

        if ($Score -ge 85) { return @{ Severity="Critical"; Confidence="High" } }
        elseif ($Score -ge 70) { return @{ Severity="High"; Confidence="High" } }
        elseif ($Score -ge 50) { return @{ Severity="Medium"; Confidence="Medium" } }
        elseif ($Score -ge 30) { return @{ Severity="Low"; Confidence="Medium" } }
        else { return @{ Severity="Info"; Confidence="Low" } }
    }

    function fncPrintSurface {
        param([string]$Header,[array]$Items)

        fncPrintMessage ("Rendering results section: {0}" -f $Header) "debug"

        fncPrintSectionHeader $Header

        if (-not $Items -or $Items.Count -eq 0) {
            fncPrintMessage "None detected." "success"
            Write-Host ""
            return
        }

        foreach ($i in $Items) {

            $colour = fncGetSeverityColour $i.Severity

            Write-Host ("  -> [{0}/100 | {1} | {2}] {3}" -f `
                $i.Score,$i.Severity,$i.Confidence,$i.Summary) `
                -ForegroundColor $colour

            Write-Host ("       Offsec: Impact={0}`n       Trigger={1}`n       Effort={2}`n       Stealth={3}" -f `
                $i.Impact,$i.Trigger,$i.Effort,$i.Stealth) `
                -ForegroundColor DarkGray
        }

        Write-Host ""
    }

    # ==========================================================
    # Enumeration
    # ==========================================================
    $tokenSids = fncGetTokenSids
    if (-not $tokenSids) {
        fncPrintMessage "Failed to build token SID set; ACL checks may be unreliable." "warning"
        fncPrintMessage "Continuing with scan but matches may be incomplete." "debug"
    }

    $findings = @()

    $services = @()
    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        $svcTotal = ($services | Measure-Object).Count
        fncPrintMessage ("Enumerated services: {0}" -f $svcTotal) "debug"
    } catch {
        fncPrintMessage ("Service enumeration failed: {0}" -f $_.Exception.Message) "debug"
        $services = @()
    }

    $svcTotal = ($services | Measure-Object).Count
    $svcIdx = 0

    foreach ($svc in $services) {

        $svcIdx++

        if (($svcIdx % 20) -eq 0) {
            Write-Progress -Id 31 `
                -Activity "Evaluating service permission abuse" `
                -Status ("{0}/{1} services" -f $svcIdx,$svcTotal) `
                -PercentComplete ([int](($svcIdx / [Math]::Max($svcTotal,1)) * 100))
        }

        try {

            $svcName   = fncSafeString $svc.Name
            $startName = fncSafeString $svc.StartName
            $startMode = fncSafeString $svc.StartMode

            if ([string]::IsNullOrWhiteSpace($svcName)) { continue }

            fncPrintMessage ("Evaluating: {0} (StartName={1}, StartMode={2})" -f $svcName,$startName,$startMode) "debug"

            $sd = sc.exe sdshow $svcName 2>$null
            if (-not $sd) {
                fncPrintMessage ("No SD returned for {0} (sc sdshow empty)." -f $svcName) "debug"
                continue
            }

            $rawSddl = ($sd | Select-Object -First 1)
            if (-not $rawSddl) {
                fncPrintMessage ("No SDDL line parsed for {0}." -f $svcName) "debug"
                continue
            }

            $csd = New-Object System.Security.AccessControl.CommonSecurityDescriptor $false,$false,$rawSddl

            $canChangeConfig = $false
            $canStartStop    = $false
            $canWriteDac     = $false
            $canWriteOwner   = $false

            foreach ($ace in $csd.DiscretionaryAcl) {

                try {
                    $sid = $ace.SecurityIdentifier.Value
                } catch { continue }

                if ($tokenSids -and (-not $tokenSids.Contains($sid))) { continue }

                $mask = $ace.AccessMask

                # SERVICE_CHANGE_CONFIG
                if ($mask -band 0x0002) { $canChangeConfig = $true }

                # SERVICE_START | SERVICE_STOP
                if ( ($mask -band 0x0010) -or ($mask -band 0x0020) ) { $canStartStop = $true }

                # WRITE_DAC
                if ($mask -band 0x40000) { $canWriteDac = $true }

                # WRITE_OWNER
                if ($mask -band 0x80000) { $canWriteOwner = $true }
            }

            fncPrintMessage ("Surface: ChangeConfig={0} StartStop={1} WriteDac={2} WriteOwner={3}" -f `
                $canChangeConfig,$canStartStop,$canWriteDac,$canWriteOwner) "debug"

            if (-not ($canChangeConfig -or $canStartStop -or $canWriteDac -or $canWriteOwner)) {
                continue
            }

            $runsAsSystem = fncIsHighPrivServiceAccount $startName
            fncPrintMessage ("RunsAsSystem={0}" -f $runsAsSystem) "debug"

            $score = fncScoreServicePermissionSurface `
                -CanChangeConfig:$canChangeConfig `
                -CanStartStop:$canStartStop `
                -CanWriteDac:$canWriteDac `
                -CanWriteOwner:$canWriteOwner `
                -RunsAsSystem:$runsAsSystem `
                -StartMode $startMode

            $sc = fncScoreToSeverityAndConfidence $score

            $impact  = if ($runsAsSystem) { "SYSTEM Privilege" } else { "Service Account Context" }
            $trigger = "Service Reconfiguration / Restart"
            $effort  = if ($canChangeConfig) { "Low" } else { "Medium" }
            $stealth = "Moderate"

            $summary = "Service '$svcName' StartName='$startName' Permissions: ChangeConfig=$canChangeConfig StartStop=$canStartStop WriteDac=$canWriteDac WriteOwner=$canWriteOwner"

            fncPrintMessage ("Hit: Score={0} Severity={1} Confidence={2}" -f $score,$sc.Severity,$sc.Confidence) "debug"

            $findings += [PSCustomObject]@{
                Score      = $score
                Severity   = $sc.Severity
                Confidence = $sc.Confidence
                Summary    = $summary
                Impact     = $impact
                Trigger    = $trigger
                Effort     = $effort
                Stealth    = $stealth
            }

            $fingerprint = $svcName
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("PRIVESC_SVC_PERM_$tag") `
                -Category "Privilege Escalation" `
                -Title "Weak Service Permissions Allow Privilege Escalation" `
                -Severity $sc.Severity `
                -Status "Detected" `
                -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
                -Recommendation "Restrict service control permissions using sc sdset or group policy. Ensure only Administrators or SYSTEM can modify service configuration."

        } catch {
            fncPrintMessage ("Exception evaluating service: {0}" -f $_.Exception.Message) "debug"
            continue
        }
    }

    Write-Progress -Id 31 -Activity "Evaluating service permission abuse" -Completed -Status "Done"
    fncPrintMessage "Service permission abuse scan complete. Rendering results." "debug"

    $findings = $findings | Sort-Object Score -Descending

    fncPrintSurface "Service Permission Abuse Opportunities" $findings

    if (-not $findings -or $findings.Count -eq 0) {

        fncPrintMessage "No weak service permission abuse opportunities detected." "success"

        $fingerprint = "PRIVESC_SERVICEPERM_NONE"
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("PRIVESC_SERVICEPERM_NONE_$tag") `
            -Category "Privilege Escalation" `
            -Title "No Weak Service Permissions Detected" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No service control permission weaknesses were detected." `
            -Recommendation "No action required."
    }
}

Export-ModuleMember -Function fncGetPrivEscServicePermissionAbuse
