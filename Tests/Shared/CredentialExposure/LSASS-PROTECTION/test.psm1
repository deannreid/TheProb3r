# ================================================================
# Function: fncCheckLsassProtection
# Purpose : Determine whether LSASS Protected Process Light is enabled
# Notes   : Uses structured mapping injection via -TestId
# ================================================================
function fncCheckLsassProtection {

    fncSafeSectionHeader "LSASS Protection Check"
    fncSafePrintMessage "Checking LSASS protection configuration..." "info"

    $testId   = "LSASS-PROTECTION"
    $regPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $valueName = "RunAsPPL"

    # ------------------------------------------------------------
    # Exploitation Narrative
    # ------------------------------------------------------------
    $exploitationText = @"
If LSASS is not protected via RunAsPPL, attackers with administrative privileges
can dump LSASS memory using tools such as Mimikatz or ProcDump.
This allows extraction of cleartext credentials, NTLM hashes, and Kerberos tickets.
"@

    # ------------------------------------------------------------
    # Remediation Narrative
    # ------------------------------------------------------------
    $remediationText = @"
Enable LSASS protection using:
Registry: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1
Or via Group Policy:
Computer Configuration → Administrative Templates → System → Local Security Authority.
Reboot required after enabling.
"@

    try {

        $value = fncTryGetRegistryValue -Path $regPath -Name $valueName -Default 0

        # ------------------------------------------------------------
        # PROTECTED
        # ------------------------------------------------------------
        if ($value -eq 1) {

            fncSafePrintMessage "LSASS protection is enabled (RunAsPPL)." "success"

            $fingerprint = "LSASS|RunAsPPL|Enabled"
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -TestId $testId `
                -Id ("LSASS-PROTECTION-" + $tag) `
                -Category "Credential Exposure" `
                -Title "LSASS Protection Enabled" `
                -Severity "Info" `
                -Status "Protected" `
                -Message "RunAsPPL is enabled. LSASS runs as Protected Process Light." `
                -Recommendation "Maintain current configuration." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }

        # ------------------------------------------------------------
        # UNPROTECTED
        # ------------------------------------------------------------
        else {

            fncSafePrintMessage "LSASS protection is NOT enabled." "warning"

            $fingerprint = "LSASS|RunAsPPL|Disabled"
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -TestId $testId `
                -Id ("LSASS-PROTECTION-" + $tag) `
                -Category "Credential Exposure" `
                -Title "LSASS Protection Not Enabled" `
                -Severity "High" `
                -Status "Unprotected" `
                -Message "RunAsPPL is disabled or missing. LSASS may be vulnerable to credential dumping." `
                -Recommendation "Enable LSASS protection via GPO or registry (RunAsPPL = 1)." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }

    }
    catch {
        fncSafePrintMessage ("Failed checking LSASS protection: {0}" -f $_.Exception.Message) "error"
    }
}

Export-ModuleMember -Function fncCheckLsassProtection