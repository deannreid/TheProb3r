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
    # Severity Mapping
    # ==========================================================
    function fncScoreToSeverityAndConfidence {
        param([int]$Score)

        if ($Score -ge 85) { return @{ Severity="Critical"; Confidence="High" } }
        elseif ($Score -ge 70) { return @{ Severity="High"; Confidence="High" } }
        elseif ($Score -ge 50) { return @{ Severity="Medium"; Confidence="Medium" } }
        elseif ($Score -ge 30) { return @{ Severity="Low"; Confidence="Medium" } }
        else { return @{ Severity="Info"; Confidence="Low" } }
    }

    function fncScoreSecurityControl {
        param([string]$ServiceName,[string]$Status,[string]$StartType)

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

    # ==========================================================
    # Target Security Services
    # ==========================================================
    $securityServices = @(
        "WinDefend",
        "WdNisSvc",
        "Sense",
        "SecurityHealthService"
    )

    $findings = @()

    foreach ($svcName in $securityServices) {

        try {

            $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $svc) { continue }

            $status    = [string]$svc.Status
            $startType = [string]$svc.StartType

            if ($status -eq "Running" -and $startType -ne "Disabled") { continue }

            $score = fncScoreSecurityControl -ServiceName $svcName -Status $status -StartType $startType
            $sc = fncScoreToSeverityAndConfidence $score

            $summary = "Security service '$svcName' Status='$status' StartType='$startType'"

            $findings += [PSCustomObject]@{
                Score       = $score
                Severity    = $sc.Severity
                Confidence  = $sc.Confidence
                Summary     = $summary
                ServiceName = $svcName
            }

            # ==================================================
            # Structured Finding
            # ==================================================

            $title = switch ($sc.Severity) {
                "Critical" { "Critical Security Control Tampering Detected" }
                "High"     { "High-Risk Security Control Disabled" }
                "Medium"   { "Security Control Misconfiguration Identified" }
                "Low"      { "Low-Risk Security Control Deviation" }
                default    { "Informational Security Control State Change" }
            }

$exploitation = @"
Core security monitoring service is not operating as expected.

Disabled or misconfigured security services significantly reduce
detection and response capability, enabling attackers to operate
with reduced visibility and lower detection probability.
"@

$remediation = @"
Investigate and restore proper configuration of the affected service:

- Ensure the service is set to Automatic startup.
- Confirm service is running.
- Review recent configuration or policy changes.
- Validate Group Policy or endpoint security policies.
- Audit for potential malicious tampering activity.
"@

            $fingerprint = "$svcName|$status|$startType"
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("DEF_EVASION_SERVICE_$tag") `
                -TestId "DEFENSEEVADE-SECURITY-CONTROL-TAMPERING" `
                -Category "Defense Evasion" `
                -Title $title `
                -Severity $sc.Severity `
                -Status "Detected" `
                -Message ("{0}`nScore={1}/100 | Confidence={2}" -f $summary,$score,$sc.Confidence) `
                -Exploitation $exploitation `
                -Remediation $remediation `
                -Recommendation "Restore service configuration and investigate possible tampering."

        }
        catch {
            fncPrintMessage ("Error evaluating service '{0}': {1}" -f $svcName,$_.Exception.Message) "debug"
            continue
        }
    }

    # ==========================================================
    # Output Summary
    # ==========================================================
    $findings = $findings | Sort-Object Score -Descending

    Write-Host ""
}

Export-ModuleMember -Function fncGetDefenseEvasionSecurityControlTampering