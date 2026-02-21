# ================================================================
# Function: fncGetTokenAndPrivilegeInfo
# Purpose : Full token security posture enumeration
# Notes   : Includes admin detection, integrity level, UAC filtering,
#           privilege abuse indicators, delegation signals, and findings
# ================================================================
function fncGetTokenAndPrivilegeInfo {

    fncPrintMessage "Reviewing current token privileges and group memberships..." "info"
    fncPrintMessage "Initialising token posture enumeration." "debug"
    Write-Host ""

    # ----------------------------------------------------------
    # Identity Objects
    # ----------------------------------------------------------
    fncPrintMessage "Acquiring WindowsIdentity/WindowsPrincipal." "debug"

    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity) {
        fncPrintMessage "Failed obtaining Windows identity." "warning"
        fncPrintMessage "WindowsIdentity.GetCurrent() returned null." "debug"
        return
    }

    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)

    try {
        fncPrintMessage ("Identity.Name: {0}" -f (fncSafeString $identity.Name)) "debug"
        fncPrintMessage ("AuthType     : {0}" -f (fncSafeString $identity.AuthenticationType)) "debug"
        fncPrintMessage ("IsSystem     : {0}" -f $identity.IsSystem) "debug"
        fncPrintMessage ("IsGuest      : {0}" -f $identity.IsGuest) "debug"
        fncPrintMessage ("IsAnonymous  : {0}" -f $identity.IsAnonymous) "debug"
    } catch {}

    # ----------------------------------------------------------
    # Admin Detection
    # ----------------------------------------------------------
    fncPrintMessage "Checking token admin elevation." "debug"

    $isAdmin = $false
    try {
        $isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        fncPrintMessage ("Admin check failed: {0}" -f $_.Exception.Message) "debug"
        $isAdmin = $false
    }

    if ($isAdmin) {
        fncPrintMessage "Token indicates Administrator privileges." "warning"
    }
    else {
        fncPrintMessage "Token is NOT elevated." "info"
    }

    # ----------------------------------------------------------
    # Integrity Level Detection
    # ----------------------------------------------------------
    fncPrintSectionHeader "Token Integrity Level"
    fncPrintMessage "Detecting integrity label via whoami /groups." "debug"

    try {
        $ilLine = whoami /groups | Select-String "Mandatory Label"
        if ($ilLine) {
            Write-Host ("  -> {0}" -f ($ilLine.Line.Trim())) -ForegroundColor Cyan
            fncPrintMessage ("Integrity label line: {0}" -f ($ilLine.Line.Trim())) "debug"
        }
        else {
            fncPrintMessage "Integrity level not detected." "warning"
            fncPrintMessage "No 'Mandatory Label' line returned by whoami /groups." "debug"
        }
    }
    catch {
        fncPrintMessage "Failed retrieving integrity level." "warning"
        fncPrintMessage ("Integrity detection exception: {0}" -f $_.Exception.Message) "debug"
    }

    Write-Host ""

    # ----------------------------------------------------------
    # Group Memberships
    # ----------------------------------------------------------
    fncPrintSectionHeader "Group Memberships"
    fncPrintMessage "Resolving token group SIDs -> NTAccount where possible." "debug"

    $groupList = @()

    try {

        foreach ($sid in $identity.Groups) {
            try {
                $translated = $sid.Translate([System.Security.Principal.NTAccount]).Value
                $groupList += $translated
                fncPrintMessage ("Group resolved: {0}" -f (fncSafeString $translated)) "debug"
            }
            catch {
                $groupList += $sid.Value
                fncPrintMessage ("Group SID unresolved, using SID: {0}" -f (fncSafeString $sid.Value)) "debug"
            }
        }

    } catch {
        fncPrintMessage ("Group enumeration failed: {0}" -f $_.Exception.Message) "debug"
    }

    if ($isAdmin) {
        # Some contexts won't explicitly list it, but operator expectation is that it's effectively present.
        $groupList += "BUILTIN\Administrators"
        fncPrintMessage "Appended BUILTIN\\Administrators (admin token detected)." "debug"
    }

    if ($groupList.Count -gt 0) {

        $groupList = $groupList | Sort-Object -Unique
        fncPrintMessage ("Resolved unique groups: {0}" -f $groupList.Count) "debug"

        foreach ($grp in $groupList) {
            Write-Host ("  -> {0}" -f $grp) -ForegroundColor Cyan
        }

        # Dangerous group detection
        $dangerGroups = @(
            "Administrators",
            "Backup Operators",
            "Print Operators",
            "Server Operators",
            "Hyper-V Administrators"
        )

        foreach ($dg in $dangerGroups) {
            if ($groupList -match $dg) {

                fncPrintMessage ("Dangerous group match: {0}" -f $dg) "debug"

                fncAddFinding `
                    -Id ("GROUP_" + ($dg -replace " ", "_")) `
                    -Category "Privilege Escalation" `
                    -Title ("Dangerous Group Membership: {0}" -f $dg) `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("User is member of {0}." -f $dg) `
                    -Recommendation "Review necessity of membership."
            }
        }
    }
    else {
        fncPrintMessage "No groups resolved." "warning"
        fncPrintMessage "Token group list empty after enumeration." "debug"
    }

    Write-Host ""

    # ----------------------------------------------------------
    # Privilege Enumeration
    # ----------------------------------------------------------
    fncPrintMessage "Enumerating privileges via whoami /priv." "debug"

    try {
        $privOutput = whoami /priv
        fncPrintMessage ("whoami /priv returned {0} chars." -f ($privOutput | Out-String).Length) "debug"
    }
    catch {
        fncPrintMessage "Failed to enumerate privileges." "warning"
        fncPrintMessage ("Privilege enumeration exception: {0}" -f $_.Exception.Message) "debug"
        return
    }

    $interestingPrivs = @(
        "SeImpersonatePrivilege",
        "SeAssignPrimaryTokenPrivilege",
        "SeDebugPrivilege",
        "SeBackupPrivilege",
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeLoadDriverPrivilege"
    )

    $enabledPrivs = @()

    foreach ($line in ($privOutput -split "`r?`n")) {
        foreach ($p in $interestingPrivs) {
            if ($line -match $p -and $line -match "Enabled") {
                $enabledPrivs += $p
                fncPrintMessage ("Enabled privilege detected: {0}" -f $p) "debug"
            }
        }
    }

    $enabledPrivs = $enabledPrivs | Sort-Object -Unique
    fncPrintMessage ("Total enabled interesting privileges: {0}" -f $enabledPrivs.Count) "debug"

    # ----------------------------------------------------------
    # Privilege Output
    # ----------------------------------------------------------
    fncPrintSectionHeader "High Risk Enabled Privileges"

    if ($enabledPrivs.Count -gt 0) {

        foreach ($priv in $enabledPrivs) {
            Write-Host ("  -> {0}" -f $priv) -ForegroundColor Red
        }

        fncPrintMessage ("Interesting enabled privileges: {0}" -f ($enabledPrivs -join ", ")) "warning"

        # UAC Split Token Detection
        if ($isAdmin -and -not ($enabledPrivs -contains "SeDebugPrivilege")) {
            fncPrintMessage "User appears admin but token may be UAC filtered." "warning"
            fncPrintMessage "Heuristic: admin=true but SeDebugPrivilege not enabled." "debug"
        }

        # SYSTEM escalation indicator
        if ($enabledPrivs -contains "SeImpersonatePrivilege") {
            fncPrintMessage "SYSTEM escalation via token impersonation likely possible." "warning"
            fncPrintMessage "Indicator: SeImpersonatePrivilege enabled." "debug"
        }
    }
    else {
        fncPrintMessage "None detected" "success"
    }

    Write-Host ""

    # ----------------------------------------------------------
    # Findings Logic
    # ----------------------------------------------------------
    fncPrintMessage "Creating findings for each enabled high-risk privilege." "debug"

    foreach ($p in $enabledPrivs) {

        fncAddFinding `
            -Id ("PRIV_" + $p) `
            -Category "Privilege Escalation" `
            -Title ("Privilege Enabled: {0}" -f $p) `
            -Severity "High" `
            -Status "Detected" `
            -Message ("{0} is enabled." -f $p) `
            -Recommendation "Review privilege assignment and necessity."

        switch ($p) {
            "SeDebugPrivilege" {
                Write-Host "Note: Enables LSASS dumping or SYSTEM injection." -ForegroundColor Yellow
            }
            "SeImpersonatePrivilege" {
                Write-Host "Note: Potato-style token impersonation possible." -ForegroundColor Yellow
            }
            "SeLoadDriverPrivilege" {
                Write-Host "Note: Kernel-level escalation possible." -ForegroundColor Yellow
            }
        }
    }

    # ----------------------------------------------------------
    # Delegation / Service SID Detection
    # ----------------------------------------------------------
    fncPrintSectionHeader "Token Context Indicators"
    fncPrintMessage "Checking group list for Service SIDs / Delegation indicators." "debug"

    if ($groupList -match "NT SERVICE\\") {
        Write-Host "  -> Service SID detected in token" -ForegroundColor Yellow
        fncPrintMessage "Indicator hit: groupList contains 'NT SERVICE\\'." "debug"
    }

    if ($groupList -match "Delegation") {
        Write-Host "  -> Delegation capable token detected" -ForegroundColor Yellow
        fncPrintMessage "Indicator hit: groupList contains 'Delegation'." "debug"
    }

    Write-Host ""
    fncPrintMessage "Token posture enumeration complete." "debug"
}

Export-ModuleMember -Function fncGetTokenAndPrivilegeInfo
