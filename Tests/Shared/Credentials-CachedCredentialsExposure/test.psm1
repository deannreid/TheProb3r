# ================================================================
# Function: fncGetCredentialsCachedExposure
# Purpose : Detect cached credential and plaintext exposure risks
# Notes   : Requires Admin (reads HKLM:\SECURITY hive)
# ================================================================
function fncGetCredentialsCachedExposure {

    fncPrintMessage "Checking cached credential exposure and workstation tiering posture..." "info"
    fncPrintMessage "" "plain"

    # ------------------------------------------------------------
    # Require Admin
    # ------------------------------------------------------------
    if (-not (fncIsAdmin)) {

        fncPrintMessage "Administrator privileges required to enumerate SECURITY hive." "warning"

        fncAddFinding `
            -Id "CACHED_CREDENTIALS_ADMIN_REQUIRED" `
            -Category "Credential Security" `
            -Title "Cached Credential Exposure Check Skipped" `
            -Severity "Info" `
            -Status "Skipped" `
            -Message "Administrator privileges required to fully assess cached credentials." `
            -Recommendation "Re-run test with elevated privileges."

        return
    }

    $finds = 0

    # ------------------------------------------------------------
    # Cached Logons Count
    # ------------------------------------------------------------
    $cachedCount = $null
    try {
        $reg = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $cachedCount = (Get-ItemProperty $reg -Name CachedLogonsCount -ErrorAction SilentlyContinue).CachedLogonsCount
    } catch {}

    if ($cachedCount -and [int]$cachedCount -gt 0) {

        $finds++
        fncPrintMessage "Cached domain logons enabled (Count=$cachedCount)" "warning"

        fncAddFinding `
            -Id "CACHED_CREDENTIALS_ENABLED" `
            -Category "Credential Security" `
            -Title "Cached Domain Credentials Enabled" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "CachedLogonsCount is set to $cachedCount." `
            -Recommendation "Reduce or disable cached logons if not required for offline authentication."
    }
    else {
        fncPrintMessage "Cached logons not configured or set to 0." "success"
    }

    # ------------------------------------------------------------
    # Enumerate Cached Credential Slots (HKLM:\SECURITY\Cache)
    # ------------------------------------------------------------
    $cachedSlots = @()

    try {

        $cachePath = "HKLM:\SECURITY\Cache"

        if (Test-Path $cachePath -ErrorAction SilentlyContinue) {

            $props = Get-ItemProperty -Path $cachePath -ErrorAction SilentlyContinue

            foreach ($p in $props.PSObject.Properties) {

                if ($p.Name -match "^NL\$\d+$") {

                    if ($p.Value -and $p.Value.Length -gt 0) {
                        $cachedSlots += $p.Name
                    }
                }
            }
        }

    } catch {}

    if ($cachedSlots.Count -gt 0) {

        $finds++
        fncPrintMessage ("Detected cached credential slots: {0}" -f ($cachedSlots -join ", ")) "warning"

        fncAddFinding `
            -Id "CACHED_CREDENTIAL_SLOTS_PRESENT" `
            -Category "Credential Security" `
            -Title "Cached Credential Artifacts Present" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("Cached credential registry entries detected: {0}" -f ($cachedSlots -join ", ")) `
            -Recommendation "Consider reducing CachedLogonsCount or enabling Credential Guard."
    }

    # ------------------------------------------------------------
    # WDigest Plaintext
    # ------------------------------------------------------------
    $wdigest = $null
    try {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        $wdigest = (Get-ItemProperty $reg -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
    } catch {}

    if ($wdigest -eq 1) {

        $finds++
        fncPrintMessage "WDigest plaintext credential caching ENABLED" "warning"

        fncAddFinding `
            -Id "WDIGEST_ENABLED" `
            -Category "Credential Security" `
            -Title "WDigest Plaintext Credentials Enabled" `
            -Severity "High" `
            -Status "Detected" `
            -Message "UseLogonCredential is set to 1. LSASS may store plaintext credentials." `
            -Recommendation "Disable WDigest UseLogonCredential or enforce LSA protection."
    }
    else {
        fncPrintMessage "WDigest plaintext credential caching not enabled." "success"
    }

    # ------------------------------------------------------------
    # LSA Protection (RunAsPPL)
    # ------------------------------------------------------------
    $runAsPPL = $null
    try {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $runAsPPL = (Get-ItemProperty $reg -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    } catch {}

    if ($runAsPPL -ne 1) {

        $finds++
        fncPrintMessage "LSA Protection (RunAsPPL) not enforced." "warning"

        fncAddFinding `
            -Id "LSA_PROTECTION_DISABLED" `
            -Category "Credential Security" `
            -Title "LSA Protection Not Enforced" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "RunAsPPL is not enabled. LSASS memory extraction may be easier." `
            -Recommendation "Enable LSA protection (RunAsPPL) via GPO."
    }
    else {
        fncPrintMessage "LSA Protection (RunAsPPL) enabled." "success"
    }

    # ------------------------------------------------------------
    # Credential Guard Status (Device Guard)
    # ------------------------------------------------------------
    $cgStatus = "Unknown"
    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
        if ($dg -and $dg.SecurityServicesRunning) {
            # Credential Guard is commonly represented as "1"
            if ($dg.SecurityServicesRunning -contains 1) { $cgStatus = "Enabled" }
            else { $cgStatus = "Disabled" }
        }
    } catch {}

    if ($cgStatus -ne "Enabled") {

        $finds++
        fncPrintMessage ("Credential Guard not enabled (Status=$cgStatus)." ) "warning"

        fncAddFinding `
            -Id "CREDENTIAL_GUARD_NOT_ENABLED" `
            -Category "Credential Security" `
            -Title "Credential Guard Not Enabled" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("Credential Guard status: {0}" -f $cgStatus) `
            -Recommendation "Enable Credential Guard where supported to reduce credential theft risk."
    }
    else {
        fncPrintMessage "Credential Guard enabled." "success"
    }

    # ------------------------------------------------------------
    # Restricted Admin Mode (RDP)
    #   DisableRestrictedAdmin:
    #     0 or missing => allowed/enabled
    #     1            => disabled
    # ------------------------------------------------------------
    $restrictedAdmin = "Unknown"
    try {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $v = (Get-ItemProperty $reg -Name DisableRestrictedAdmin -ErrorAction SilentlyContinue).DisableRestrictedAdmin
        if ($null -eq $v) { $restrictedAdmin = "EnabledOrDefault" }
        elseif ([int]$v -eq 0) { $restrictedAdmin = "Enabled" }
        elseif ([int]$v -eq 1) { $restrictedAdmin = "Disabled" }
        else { $restrictedAdmin = "Unknown" }
    } catch {}

    if ($restrictedAdmin -eq "Disabled") {

        $finds++
        fncPrintMessage "Restricted Admin Mode appears disabled for RDP." "warning"

        fncAddFinding `
            -Id "RDP_RESTRICTED_ADMIN_DISABLED" `
            -Category "Credential Security" `
            -Title "Restricted Admin Mode Disabled" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "DisableRestrictedAdmin=1 detected." `
            -Recommendation "Consider enabling Restricted Admin Mode to reduce credential exposure during RDP."
    }
    else {
        fncPrintMessage ("Restricted Admin Mode status: {0}" -f $restrictedAdmin) "success"
    }

    # ------------------------------------------------------------
    # DisableDomainCreds (network logon credential storage)
    #   1 => disabled (good)
    #   0/missing => enabled/default (risk)
    # ------------------------------------------------------------
    $disableDomainCreds = $null
    try {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $disableDomainCreds = (Get-ItemProperty $reg -Name DisableDomainCreds -ErrorAction SilentlyContinue).DisableDomainCreds
    } catch {}

    if ($disableDomainCreds -ne 1) {

        $finds++
        fncPrintMessage "DisableDomainCreds not enforced (domain creds may be stored for network auth)." "warning"

        fncAddFinding `
            -Id "DISABLE_DOMAIN_CREDS_NOT_ENFORCED" `
            -Category "Credential Security" `
            -Title "DisableDomainCreds Not Enforced" `
            -Severity "Low" `
            -Status "Detected" `
            -Message "DisableDomainCreds is not set to 1." `
            -Recommendation "Consider enabling DisableDomainCreds where operationally possible."
    }
    else {
        fncPrintMessage "DisableDomainCreds enforced (DisableDomainCreds=1)." "success"
    }

    # ------------------------------------------------------------
    # SMB Signing Posture
    # ------------------------------------------------------------
    $smbClient = $null
    $smbServer = $null

    if (fncCommandExists "Get-SmbClientConfiguration") {
        try { $smbClient = Get-SmbClientConfiguration -ErrorAction SilentlyContinue } catch {}
    }
    if (fncCommandExists "Get-SmbServerConfiguration") {
        try { $smbServer = Get-SmbServerConfiguration -ErrorAction SilentlyContinue } catch {}
    }

    $clientRequire = $null
    $serverRequire = $null

    if ($smbClient) {
        try { $clientRequire = [bool]$smbClient.RequireSecuritySignature } catch {}
    } else {
        try {
            $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
            $clientRequire = ((Get-ItemProperty $reg -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature -eq 1)
        } catch {}
    }

    if ($smbServer) {
        try { $serverRequire = [bool]$smbServer.RequireSecuritySignature } catch {}
    } else {
        try {
            $reg = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
            $serverRequire = ((Get-ItemProperty $reg -Name RequireSecuritySignature -ErrorAction SilentlyContinue).RequireSecuritySignature -eq 1)
        } catch {}
    }

    if ($clientRequire -ne $true) {

        $finds++
        fncPrintMessage "SMB Client signing not required." "warning"

        fncAddFinding `
            -Id "SMB_CLIENT_SIGNING_NOT_REQUIRED" `
            -Category "Credential Security" `
            -Title "SMB Client Signing Not Required" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "SMB client does not require signing." `
            -Recommendation "Require SMB client signing to reduce relay risk where feasible."
    }
    else {
        fncPrintMessage "SMB Client signing required." "success"
    }

    if ($serverRequire -ne $true) {

        $finds++
        fncPrintMessage "SMB Server signing not required." "warning"

        fncAddFinding `
            -Id "SMB_SERVER_SIGNING_NOT_REQUIRED" `
            -Category "Credential Security" `
            -Title "SMB Server Signing Not Required" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message "SMB server does not require signing." `
            -Recommendation "Require SMB server signing to reduce relay risk where feasible."
    }
    else {
        fncPrintMessage "SMB Server signing required." "success"
    }

    # ------------------------------------------------------------
    # LAPS Presence / Configuration (Legacy + Windows LAPS)
    # ------------------------------------------------------------
    $lapsLegacyEnabled = $false
    $lapsNewConfigured = $false

    try {
        $regLegacy = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
        if (Test-Path $regLegacy -ErrorAction SilentlyContinue) {
            $v = (Get-ItemProperty $regLegacy -Name AdmPwdEnabled -ErrorAction SilentlyContinue).AdmPwdEnabled
            if ($v -eq 1) { $lapsLegacyEnabled = $true }
        }
    } catch {}

    try {
        $regNew = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LAPS"
        if (Test-Path $regNew -ErrorAction SilentlyContinue) {
            # Any meaningful config key present implies policy is set
            $p = Get-ItemProperty $regNew -ErrorAction SilentlyContinue
            if ($p) {
                $names = $p.PSObject.Properties.Name
                if ($names -contains "BackupDirectory" -or $names -contains "PasswordComplexity" -or $names -contains "PasswordLength" -or $names -contains "EnablePasswordEncryption") {
                    $lapsNewConfigured = $true
                }
            }
        }
    } catch {}

    if ($lapsLegacyEnabled -or $lapsNewConfigured) {

        $mode = @()
        if ($lapsNewConfigured) { $mode += "WindowsLAPS" }
        if ($lapsLegacyEnabled) { $mode += "LegacyLAPS" }

        fncPrintMessage ("LAPS policy detected ({0})." -f ($mode -join "+")) "success"

        fncAddFinding `
            -Id "LAPS_POLICY_DETECTED" `
            -Category "Credential Security" `
            -Title "LAPS Policy Detected" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message ("LAPS policy detected: {0}" -f ($mode -join "+")) `
            -Recommendation "No action required."
    }
    else {

        $finds++
        fncPrintMessage "LAPS policy not detected (local admin password reuse risk)." "warning"

        fncAddFinding `
            -Id "LAPS_NOT_DETECTED" `
            -Category "Credential Security" `
            -Title "LAPS Not Detected" `
            -Severity "High" `
            -Status "Detected" `
            -Message "No Legacy LAPS or Windows LAPS policy indicators detected." `
            -Recommendation "Implement Windows LAPS (preferred) or Legacy LAPS to randomise local admin passwords and reduce reuse."
    }

    # ------------------------------------------------------------
    # Local Admin Password Reuse Indicator (Heuristic)
    # ------------------------------------------------------------
    # We can't prove reuse locally. We flag a heuristic:
    #   If LAPS not detected AND at least one enabled local admin exists => likely reuse risk.
    $enabledLocalAdmins = @()
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        foreach ($a in (fncSafeArray $admins)) {

            if ($a.ObjectClass -ne "User") { continue }

            $uname = [string]$a.Name
            $localName = $uname
            if ($uname -match "^[^\\]+\\(.+)$") { $localName = $matches[1] }

            $u = $null
            try { $u = Get-LocalUser -Name $localName -ErrorAction SilentlyContinue } catch {}

            if ($u -and $u.Enabled) {
                $enabledLocalAdmins += $u.Name
            }
        }
    } catch {}

    if (-not ($lapsLegacyEnabled -or $lapsNewConfigured) -and (fncSafeCount $enabledLocalAdmins) -gt 0) {

        $finds++
        fncPrintMessage ("Enabled local admin(s) present without LAPS: {0}" -f ($enabledLocalAdmins -join ", ")) "warning"

        fncAddFinding `
            -Id "LOCAL_ADMIN_REUSE_RISK_HEURISTIC" `
            -Category "Credential Security" `
            -Title "Local Admin Password Reuse Risk (Heuristic)" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message ("Enabled local admin(s) detected without LAPS policy: {0}" -f ($enabledLocalAdmins -join ", ")) `
            -Recommendation "Implement LAPS and disable/rename unused local admin accounts. Consider Just Enough Administration / privileged access workstations."
    }

    # ------------------------------------------------------------
    # Domain User Profiles Present (Correlation Signal)
    # ------------------------------------------------------------
    $profiles = @()
    try {
        $profiles = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPath -like "C:\Users\*" -and -not $_.Special }
    } catch {}

    $domainProfiles = @()

    foreach ($p in (fncSafeArray $profiles)) {

        if ($p.LocalPath -match "\\Users\\(.+)$") {

            $username = $matches[1]

            # Simple heuristic: domain-style usernames often contain dot
            if ($username -match "\.") {
                $domainProfiles += $username
            }
        }
    }

    if ($domainProfiles.Count -gt 0) {
        fncPrintMessage ("Domain user profiles present: {0}" -f ($domainProfiles -join ", ")) "info"
    }

    fncPrintMessage "" "plain"
    if ($cachedCount -gt 0 -and $runAsPPL -ne 1 -and $cgStatus -ne "Enabled") {
        fncPrintMessage "Cached credential extraction likely feasible if attacker gains local admin." "warning"
    }
    # ------------------------------------------------------------
    # Good State
    # ------------------------------------------------------------
    if ($finds -eq 0) {

        fncAddFinding `
            -Id "CACHED_CREDENTIALS_NONE" `
            -Category "Credential Security" `
            -Title "Cached Credential Exposure" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No cached credential exposure or tiering posture risks detected." `
            -Recommendation "No action required."
    }
}