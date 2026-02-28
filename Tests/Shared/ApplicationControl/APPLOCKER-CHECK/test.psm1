# ================================================================
# Function: fncCheckAppLockerPolicy
# Purpose : Enumerate AppLocker configuration + enforcement
# Notes   : Mapping embedded, deterministic ID model
# ================================================================
function fncCheckAppLockerPolicy {

    fncSafeSectionHeader "AppLocker Policy Check"
    fncSafePrintMessage "Enumerating AppLocker configuration..." "info"
    Write-Host ""

    $appIdSvcRunning = $false

    # ------------------------------------------------------------
    # Retrieve test metadata (for mappings)
    # ------------------------------------------------------------
    $thisTest = $null
    try {
        $thisTest = $global:ProberState.Tests |
            Where-Object { (fncSafeString $_.Id) -eq "APPLOCKER-CHECK" } |
            Select-Object -First 1
    } catch {}

    $mappingSummary = ""
    if ($thisTest -and $thisTest.Mappings) {

        $parts = @()

        foreach ($m in (fncSafeArray $thisTest.Mappings.MitreAttack)) {
            $parts += "MITRE $($m.Technique) - $($m.Name)"
        }

        foreach ($c in (fncSafeArray $thisTest.Mappings.CWE)) {
            $parts += "CWE $($c.Id) - $($c.Name)"
        }

        foreach ($n in (fncSafeArray $thisTest.Mappings.Nist)) {
            $parts += "NIST $($n.Control) - $($n.Name)"
        }

        if ($parts.Count -gt 0) {
            $mappingSummary = ($parts -join " | ")
        }
    }

    # ------------------------------------------------------------
    # Exploitation Narrative
    # ------------------------------------------------------------
    $exploitationText = @"
Without application control enforcement, attackers can execute arbitrary
payloads (PowerShell, mshta, rundll32, LOLBINs, custom binaries).
This increases the likelihood of malware execution and privilege escalation.
AppLocker significantly reduces post-exploitation tooling options.
"@

    # ------------------------------------------------------------
    # Remediation Narrative
    # ------------------------------------------------------------
    $remediationText = @"
Implement allow-list based AppLocker rules for:
- Executables
- Scripts
- DLLs
- Packaged apps

Ensure Application Identity (AppIDSvc) is set to Automatic and running.
Test policies in Audit mode before enforcing.
"@

    # ------------------------------------------------------------
    # Check AppIDSvc
    # ------------------------------------------------------------
    try {
        $svc = Get-Service -Name AppIDSvc -ErrorAction Stop
        $appIdSvcRunning = ($svc.Status -eq "Running")
    }
    catch {}

    # ------------------------------------------------------------
    # Cmdlet availability
    # ------------------------------------------------------------
    if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {

        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

        if (Test-Path $regPath) {

            $hashInput = "APPLOCKER|REGISTRY_PRESENT"
            $findingId = "APPLOCKER-" + (fncShortHashTag $hashInput)

            $msg = "AppLocker registry keys exist but cmdlet unavailable."
            if ($mappingSummary) { $msg += "`nMapping: $mappingSummary" }

            fncAddFinding `
                -TestId "APPLOCKER-CHECK" `
                -Id $findingId `
                -Category "Application Control" `
                -Title "AppLocker Registry Policy Present" `
                -Severity "Info" `
                -Status "Detected" `
                -Message $msg `
                -Recommendation "Validate AppLocker configuration via GPO or Local Security Policy." `
                -Exploitation $exploitationText `
                -Remediation $remediationText

        }
        else {

            $hashInput = "APPLOCKER|NOT_PRESENT"
            $findingId = "APPLOCKER-" + (fncShortHashTag $hashInput)

            $msg = "No AppLocker registry or policy detected."
            if ($mappingSummary) { $msg += "`nMapping: $mappingSummary" }

            fncAddFinding `
                -TestId "APPLOCKER-CHECK" `
                -Id $findingId `
                -Category "Application Control" `
                -Title "AppLocker Not Configured" `
                -Severity "Medium" `
                -Status "Not Detected" `
                -Message $msg `
                -Recommendation "Consider implementing application allow-listing." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }

        return
    }

    # ------------------------------------------------------------
    # Retrieve Effective Policy
    # ------------------------------------------------------------
    try {
        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop
    }
    catch {

        $hashInput = "APPLOCKER|POLICY_UNREADABLE"
        $findingId = "APPLOCKER-" + (fncShortHashTag $hashInput)

        fncAddFinding `
            -TestId "APPLOCKER-CHECK" `
            -Id $findingId `
            -Category "Application Control" `
            -Title "AppLocker Policy Could Not Be Retrieved" `
            -Severity "Medium" `
            -Status "Unknown" `
            -Message "Unable to retrieve effective AppLocker policy." `
            -Recommendation "Verify AppLocker deployment and permissions." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    $collections = @( $policy.RuleCollections )
    $totalRules = 0
    foreach ($rc in $collections) {
        $totalRules += @( $rc.Rules ).Count
    }

    # ------------------------------------------------------------
    # Empty Policy
    # ------------------------------------------------------------
    if ($totalRules -eq 0) {

        $hashInput = "APPLOCKER|EMPTY_POLICY"
        $findingId = "APPLOCKER-" + (fncShortHashTag $hashInput)

        fncAddFinding `
            -TestId "APPLOCKER-CHECK" `
            -Id $findingId `
            -Category "Application Control" `
            -Title "AppLocker Policy Contains No Rules" `
            -Severity "High" `
            -Status "Misconfigured" `
            -Message "AppLocker installed but no rules defined." `
            -Recommendation "Create allow-list rules before enforcement." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # Service Stopped
    # ------------------------------------------------------------
    if (-not $appIdSvcRunning) {

        $hashInput = "APPLOCKER|SERVICE_STOPPED"
        $findingId = "APPLOCKER-" + (fncShortHashTag $hashInput)

        fncAddFinding `
            -TestId "APPLOCKER-CHECK" `
            -Id $findingId `
            -Category "Application Control" `
            -Title "AppLocker Service Not Running" `
            -Severity "High" `
            -Status "Not Enforced" `
            -Message "Rules exist but Application Identity service is stopped." `
            -Recommendation "Start and configure AppIDSvc to Automatic." `
            -Exploitation $exploitationText `
            -Remediation $remediationText

        return
    }

    # ------------------------------------------------------------
    # SUCCESS STATE
    # ------------------------------------------------------------
    $hashInput = "APPLOCKER|ACTIVE|$totalRules"
    $findingId = "APPLOCKER-" + (fncShortHashTag $hashInput)

    $msg = "AppLocker rules present ($totalRules total) and enforcement active."
    if ($mappingSummary) { $msg += "`nMapping: $mappingSummary" }
}

Export-ModuleMember -Function fncCheckAppLockerPolicy