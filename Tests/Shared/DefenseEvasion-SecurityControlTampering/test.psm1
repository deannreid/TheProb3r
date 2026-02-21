# ================================================================
# Function: fncGetDefenseEvasionSecurityControlTampering
# Purpose : Detect disabled or weakened security controls
# Notes   : Heuristic scoring + offsec context modelling
# ================================================================
function fncGetDefenseEvasionSecurityControlTampering {

    fncPrintMessage "Checking for security control tampering indicators..." "info"
    fncPrintMessage "Initialising security service tamper analysis." "debug"
    Write-Host ""

    # ==========================================================
    # Helpers
    # ==========================================================
    function fncScoreSecurityControl {
        param(
            [string]$ServiceName,
            [string]$Status,
            [string]$StartType
        )

        $score = 0

        if ($Status -ne "Running") { $score += 60 }
        if ($StartType -eq "Disabled") { $score += 40 }
        elseif ($StartType -eq "Manual") { $score += 20 }

        switch ($ServiceName) {
            "WinDefend" { $score += 25 }
            "Sense"     { $score += 20 }
            "WdNisSvc"  { $score += 15 }
        }

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

    function fncGetOffsecContext {
        param([string]$ServiceName)

        $impact  = "Reduced Detection"
        $trigger = "Security Tool Disabled"
        $effort  = "Low"
        $stealth = "High"

        switch ($ServiceName) {

            "WinDefend" {
                $impact = "Malware Execution + AV Bypass"
                $stealth = "Very High"
            }

            "Sense" {
                $impact = "EDR Visibility Reduction"
            }

            "WdNisSvc" {
                $impact = "Network Inspection Disabled"
            }

            "SecurityHealthService" {
                $impact = "Security Posture Monitoring Disabled"
            }
        }

        return @{
            Impact  = $impact
            Trigger = $trigger
            Effort  = $effort
            Stealth = $stealth
        }
    }

    function fncPrintSurface {
        param(
            [string]$Header,
            [array]$Items
        )

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

            if ($i.ServiceName) {

                $rt = fncGetOffsecContext -ServiceName $i.ServiceName

                Write-Host ("       Offsec: Impact={0}`n       Trigger={1}`n       Effort={2}`n       Stealth={3}" -f `
                    $rt.Impact,$rt.Trigger,$rt.Effort,$rt.Stealth) `
                    -ForegroundColor DarkGray
            }
        }

        Write-Host ""
    }

    # ==========================================================
    # Security Services
    # ==========================================================
    $securityServices = @(
        "WinDefend",
        "WdNisSvc",
        "Sense",
        "SecurityHealthService"
    )

    fncPrintMessage ("Security services targeted for analysis: {0}" -f ($securityServices -join ", ")) "debug"

    $findings = @()
    $inspectedCount = 0
    $hitCount = 0

    foreach ($svcName in $securityServices) {

        try {

            fncPrintMessage ("Inspecting security service: {0}" -f $svcName) "debug"

            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue

            if (-not $svc) {
                fncPrintMessage ("Service '{0}' not present on system." -f $svcName) "debug"
                continue
            }

            $inspectedCount++

            $status    = [string]$svc.Status
            $startType = [string]$svc.StartType

            fncPrintMessage (
                "Service state collected: Name='{0}', Status='{1}', StartType='{2}'" -f `
                $svcName,$status,$startType
            ) "debug"

            if ($status -eq "Running" -and $startType -ne "Disabled") {
                fncPrintMessage ("Service '{0}' appears healthy. Skipping." -f $svcName) "debug"
                continue
            }

            $score = fncScoreSecurityControl `
                -ServiceName $svcName `
                -Status $status `
                -StartType $startType

            $sc = fncScoreToSeverityAndConfidence $score

            fncPrintMessage (
                "Tamper indicator scored: Service='{0}', Score={1}, Severity={2}, Confidence={3}" -f `
                $svcName,$score,$sc.Severity,$sc.Confidence
            ) "debug"

            $summary = "Security service '$svcName' Status='$status' StartType='$startType'"

            $findings += [PSCustomObject]@{
                Score       = $score
                Severity    = $sc.Severity
                Confidence  = $sc.Confidence
                Summary     = $summary
                ServiceName = $svcName
            }

            $hitCount++

            $fingerprint = "$svcName|$status|$startType"
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("DEF_EVASION_SERVICE_$tag") `
                -Category "Defense Evasion" `
                -Title "Security Control Disabled or Misconfigured" `
                -Severity $sc.Severity `
                -Status "Detected" `
                -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
                -Recommendation "Investigate service configuration and restore security control functionality."

        }
        catch {
            fncPrintMessage (
                "Error evaluating service '{0}': {1}" -f `
                $svcName,$_.Exception.Message
            ) "debug"
            continue
        }
    }

    fncPrintMessage ("Security service inspection completed. Services inspected: {0}" -f $inspectedCount) "debug"
    fncPrintMessage ("Tampering indicators identified: {0}" -f $hitCount) "debug"

    # ==========================================================
    # Output
    # ==========================================================
    $findings = $findings | Sort-Object Score -Descending

    fncPrintSurface "Security Control Tampering Indicators" $findings

    if (-not $findings -or $findings.Count -eq 0) {

        fncPrintMessage "No security control tampering indicators detected." "success"

        fncAddFinding `
            -Id ("DEF_EVASION_SECURITY_NONE_" + (fncShortHashTag "SECURITY_CONTROL_NONE")) `
            -Category "Defense Evasion" `
            -Title "No Security Control Tampering Detected" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "Security monitoring services appear operational." `
            -Recommendation "No action required."
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetDefenseEvasionSecurityControlTampering
