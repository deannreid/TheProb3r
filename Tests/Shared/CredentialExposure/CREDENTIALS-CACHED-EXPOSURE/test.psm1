# ================================================================
# Function: fncGetCredentialsCachedExposure
# Purpose : Detect cached credential and plaintext exposure risks
# Notes   : Mapping embedded, unified ID model
# ================================================================
function fncGetCredentialsCachedExposure {

    fncSafeSectionHeader "Cached Credential Exposure"
    fncSafePrintMessage "Checking cached credential exposure and credential theft posture..." "info"
    Write-Host ""

    # ------------------------------------------------------------
    # Require Admin
    # ------------------------------------------------------------
    if (-not (fncIsAdmin)) {

        fncAddFinding `
            -Id ("CRED-CACHED-" + (fncShortHashTag "ADMIN_REQUIRED")) `
            -TestId "CREDENTIALS-CACHED-EXPOSURE" `
            -Category "Credential Exposure" `
            -Title "Cached Credential Exposure Check Skipped" `
            -Severity "Info" `
            -Status "Skipped" `
            -Message "Administrator privileges required to assess cached credentials and SECURITY hive." `
            -Recommendation "Re-run test with elevated privileges."

        return
    }

    # ------------------------------------------------------------
    # Exploitation Narrative
    # ------------------------------------------------------------
    $exploitationText = @"
If cached credentials, WDigest plaintext, or LSASS protections are weak,
an attacker gaining local admin can extract credential material directly
from LSASS memory or registry artifacts.

Combined with SMB relay or lack of signing, this enables rapid lateral movement.
"@

    # ------------------------------------------------------------
    # Remediation Narrative
    # ------------------------------------------------------------
    $remediationText = @"
Disable WDigest plaintext credential caching.
Enable LSASS protection (RunAsPPL).
Enable Credential Guard where supported.
Reduce CachedLogonsCount where operationally feasible.
Enforce SMB signing.
Implement Windows LAPS to prevent local admin reuse.
"@

    $finds = 0

    # ============================================================
    # Example: WDigest Check (Pattern for all findings)
    # ============================================================
    $wdigest = $null
    try {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        $wdigest = (Get-ItemProperty $reg -Name UseLogonCredential -ErrorAction SilentlyContinue).UseLogonCredential
    } catch {}

    if ($wdigest -eq 1) {

        $finds++

        $hashInput = "WDigest|Enabled"
        $findingId = "CRED-CACHED-" + (fncShortHashTag $hashInput)

        $message = "WDigest UseLogonCredential is enabled. LSASS may store plaintext credentials."
        if ($mappingSummary) { $message += "`nMapping: $mappingSummary" }

        fncAddFinding `
            -Id $findingId `
            -TestId "CREDENTIALS-CACHED-EXPOSURE" `
            -Category "Credential Exposure" `
            -Title "WDigest Plaintext Credentials Enabled" `
            -Severity "High" `
            -Status "Detected" `
            -Message $message `
            -Recommendation "Disable WDigest UseLogonCredential." `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

    # ============================================================
    # LSASS Protection
    # ============================================================
    $runAsPPL = $null
    try {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $runAsPPL = (Get-ItemProperty $reg -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    } catch {}

    if ($runAsPPL -ne 1) {

        $finds++

        $hashInput = "LSASS|RunAsPPL|Disabled"
        $findingId = "CRED-CACHED-" + (fncShortHashTag $hashInput)

        $message = "LSASS protection (RunAsPPL) not enabled."
        if ($mappingSummary) { $message += "`nMapping: $mappingSummary" }

        fncAddFinding `
            -Id $findingId `
            -TestId "CREDENTIALS-CACHED-EXPOSURE" `
            -Category "Credential Exposure" `
            -Title "LSASS Protection Not Enabled" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message $message `
            -Recommendation "Enable LSASS protection via GPO." `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }
}