# ================================================================
# Test    : LSASS Protection Check
# Purpose : Determine whether LSASS protection is enabled
# Notes   : Checks RunAsPPL registry setting
# ================================================================

function fncCheckLsassProtection {

    fncPrintMessage "Checking LSASS protection configuration..." "info"
    fncPrintMessage "Preparing to query LSASS protection registry configuration." "debug"

    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $valueName = "RunAsPPL"

    fncPrintMessage ("Registry target: Path='{0}', Value='{1}'" -f $regPath,$valueName) "debug"

    try {

        fncPrintMessage "Attempting to read RunAsPPL value using fncTryGetRegistryValue." "debug"

        $value = fncTryGetRegistryValue -Path $regPath -Name $valueName -Default 0

        fncPrintMessage ("Registry value retrieved: RunAsPPL={0}" -f $value) "debug"

        if ($value -eq 1) {

            fncPrintMessage "LSASS protection is enabled (RunAsPPL)." "success"

            $fingerprint = "LSASS|RunAsPPL|Enabled"
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("LSASS-PROTECTION_$tag") `
                -Category "Credentials" `
                -Title "LSASS Protection Enabled" `
                -Severity "Good" `
                -Status "Protected" `
                -Message "RunAsPPL is enabled. LSASS memory protection is active." `
                -Recommendation "No action required."
        }
        else {

            fncPrintMessage "LSASS protection is NOT enabled." "warning"

            $fingerprint = "LSASS|RunAsPPL|Disabled"
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("LSASS-PROTECTION_$tag") `
                -Category "Credentials" `
                -Title "LSASS Protection Not Enabled" `
                -Severity "High" `
                -Status "Unprotected" `
                -Message "RunAsPPL is disabled or missing. LSASS may be vulnerable to credential dumping." `
                -Recommendation "Enable LSASS protection via GPO or registry (RunAsPPL = 1)."
        }

    }
    catch {

        fncPrintMessage (
            "Exception encountered while checking LSASS protection: {0}" -f $_.Exception.Message
        ) "debug"

        fncPrintMessage ("Failed checking LSASS protection: {0}" -f $_.Exception.Message) "error"
    }
}

Export-ModuleMember -Function fncCheckLsassProtection
