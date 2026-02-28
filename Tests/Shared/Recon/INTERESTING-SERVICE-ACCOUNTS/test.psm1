# ================================================================
# Function: fncGetInterestingServiceAccounts
# Purpose : Enumerate services running as non built-in accounts
# Notes   : Identifies potential credential / lateral movement surfaces
# ================================================================
function fncGetInterestingServiceAccounts {

    fncPrintMessage "Enumerating services running as non built-in accounts..." "info"
    Write-Host ""

    $ignoreAccounts = @(
        "LocalSystem",
        "NT AUTHORITY\LocalService",
        "NT AUTHORITY\NetworkService"
    )

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
    }
    catch {
        fncPrintMessage "Failed to enumerate services." "warning"
        return
    }

    $interesting = @()

    foreach ($svc in $services) {

        $account = [string]$svc.StartName
        if (-not $account) { continue }

        if ($ignoreAccounts -contains $account) { continue }

        $interesting += [PSCustomObject]@{
            ServiceName = [string]$svc.Name
            DisplayName = [string]$svc.DisplayName
            StartName   = $account
            StartMode   = [string]$svc.StartMode
            State       = [string]$svc.State
            Path        = [string]$svc.PathName
        }
    }

    # ==========================================================
    # Display + Risk Model
    # ==========================================================
    fncPrintSectionHeader "Services Running As Non Built-In Accounts"

    foreach ($svc in $interesting) {

        Write-Host ("Service     : {0} ({1})" -f $svc.ServiceName,$svc.DisplayName)
        Write-Host ("Runs As     : {0}" -f $svc.StartName)
        Write-Host ("Start Mode  : {0}" -f $svc.StartMode)
        Write-Host ("State       : {0}" -f $svc.State)
        Write-Host "-------------------------------------------"

        # -------------------------------
        # Risk Scoring
        # -------------------------------
        $score = 40

        if ($svc.StartMode -eq "Auto") { $score += 20 }
        if ($svc.State -eq "Running") { $score += 10 }
        if ($svc.Path -match "Users|ProgramData|Temp") { $score += 20 }

        if ($score -gt 100) { $score = 100 }

        if ($score -ge 80) { $severity="High" }
        elseif ($score -ge 60) { $severity="Medium" }
        else { $severity="Low" }

        $title = switch ($severity) {
            "High"   { "High-Risk Custom Service Account Exposure" }
            "Medium" { "Service Running As Custom Account" }
            default  { "Custom Service Account Identified" }
        }

$exploitation = @"
Services running as custom accounts introduce attack surfaces:

- Credential theft (LSASS dumping)
- Token impersonation
- Service binary replacement
- Lateral movement via service reconfiguration
- Kerberoasting (if domain account with SPN)
"@

$remediation = @"
Review service configuration:

- Replace domain accounts with gMSA where possible
- Restrict interactive logon rights
- Remove unnecessary privileges
- Validate service binary path permissions
- Rotate service account passwords
"@

        fncAddFinding `
            -Id ("SERVICE_CUSTOM_" + ($svc.ServiceName -replace '[^A-Za-z0-9]','')) `
            -TestId "INTERESTING-SERVICE-ACCOUNTS" `
            -Category "Reconnaissance" `
            -Title $title `
            -Severity $severity `
            -Status "Detected" `
            -Message ("Service '{0}' runs as '{1}' (StartMode={2}, State={3})`nScore={4}/100" -f `
                        $svc.ServiceName,$svc.StartName,$svc.StartMode,$svc.State,$score) `
            -Exploitation $exploitation `
            -Remediation $remediation `
            -Recommendation "Review service account configuration and restrict privileges."
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetInterestingServiceAccounts