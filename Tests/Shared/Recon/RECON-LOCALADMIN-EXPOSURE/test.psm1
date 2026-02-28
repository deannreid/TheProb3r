# ================================================================
# Function: fncGetReconLocalAdminExposure
# Purpose : Enumerate local Administrators group exposure
# Notes   : Includes RID 500 rename + enablement analysis
# ================================================================
function fncGetReconLocalAdminExposure {

    fncPrintMessage "Enumerating local Administrators group membership..." "info"
    Write-Host ""

    try {
        $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
    }
    catch {
        fncPrintMessage "Unable to enumerate local Administrators group." "warning"
        return
    }

    # ==========================================================
    # RID 500 Built-in Administrator Check
    # ==========================================================
    try {
        $rid500 = Get-LocalUser | Where-Object { $_.SID.Value -match "-500$" }
    }
    catch { $rid500 = $null }

    if ($rid500) {

        $isRenamed = ($rid500.Name -ne "Administrator")
        $isEnabled = $rid500.Enabled
        $score = 0

        if (-not $isRenamed) { $score += 40 }
        if ($isEnabled) { $score += 40 }

        if ($score -gt 100) { $score = 100 }

        if ($score -ge 60) { $severity="High" }
        elseif ($score -ge 40) { $severity="Medium" }
        elseif ($score -eq 0) { $severity="Info" }
        else { $severity="Low" }

        $title = switch ($severity) {
            "High"   { "Built-in Administrator Account Exposure" }
            "Medium" { "Built-in Administrator Hardening Weakness" }
            "Info"   { "Built-in Administrator Properly Hardened" }
            default  { "Built-in Administrator Review" }
        }

$exploitation = @"
The built-in RID 500 Administrator account is a well-known target.

If not renamed and/or left enabled, attackers can:
- Perform brute-force attacks
- Exploit credential reuse
- Leverage password spraying
- Escalate privileges during lateral movement
"@

$remediation = @"
Apply the following hardening controls:

- Rename the built-in Administrator account
- Disable the account where operationally possible
- Monitor logon attempts against RID 500
- Apply strong password and lockout policies
"@

    fncAddFinding `
        -Id "LOCALADMIN_RID500_STATUS" `
        -TestId "RECON-LOCALADMIN-EXPOSURE" `
        -Category "Reconnaissance" `
        -Title $title `
        -Severity $severity `
        -Status ($(if ($severity -eq "Info") { "Not Detected" } else { "Detected" })) `
        -Message ("RID500 Name='{0}', Enabled={1}" -f $rid500.Name,$rid500.Enabled) `
        -Exploitation $exploitation `
        -Remediation $remediation `
        -Recommendation "Harden built-in Administrator account configuration."
    }

    # ==========================================================
    # Domain Principal Exposure
    # ==========================================================
    $exposureHits = 0

    foreach ($m in $members) {

        $name = [string]$m.Name

        if ($name -match "\\" -and $name -notmatch "NT AUTHORITY|BUILTIN") {

            $score = 70
            $severity = "High"

            $summary = "Domain principal '$name' is member of local Administrators"

$exploitation = @"
Domain accounts in local Administrators enable:

- Privilege escalation
- Credential theft amplification
- Lateral movement via SMB/WMI/WinRM
- Pass-the-Hash and token abuse
"@

$remediation = @"
Review necessity of domain principals in local Administrators.

Apply:
- Tiered administration model
- Restricted Groups GPO
- LAPS or local admin rotation
- Remove unnecessary domain memberships
"@

            fncAddFinding `
                -Id ("LOCALADMIN_DOMAIN_" + ($name -replace '[^A-Za-z0-9]','')) `
                -TestId "RECON-LOCALADMIN-EXPOSURE" `
                -Category "Reconnaissance" `
                -Title "Domain Principal in Local Administrators" `
                -Severity $severity `
                -Status "Detected" `
                -Message $summary `
                -Exploitation $exploitation `
                -Remediation $remediation `
                -Recommendation "Restrict domain account local administrator exposure."

            $exposureHits++
        }
    }

    fncPrintSectionHeader "Local Administrators Group Members"

    foreach ($m in $members) {
        Write-Host ("  -> {0} ({1})" -f $m.Name,$m.ObjectClass)
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetReconLocalAdminExposure