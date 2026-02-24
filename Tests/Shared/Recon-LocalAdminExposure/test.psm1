# ================================================================
# Function: fncGetReconLocalAdminExposure
# Purpose : Enumerate local Administrators group exposure
# Notes   : Also checks built-in RID 500 Administrator rename status
# ================================================================
function fncGetReconLocalAdminExposure {

    fncPrintMessage "Enumerating local Administrators group membership..." "info"
    fncPrintMessage "" "plain"

    $members = @()
    try {
        $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    } catch {}

    if (-not $members -or $members.Count -eq 0) {
        fncPrintMessage "No members retrieved from local Administrators group." "warning"
        return
    }

    # ------------------------------------------------------------
    # Check Built-in Administrator (RID 500)
    # ------------------------------------------------------------
    $rid500 = $null
    try {
        $rid500 = Get-LocalUser | Where-Object {
            $_.SID.Value -match "-500$"
        }
    } catch {}

    if ($rid500) {

        $isRenamed = $rid500.Name -ne "Administrator"
        $isEnabled = $rid500.Enabled

        if (-not $isRenamed) {

            fncPrintMessage "Default RID 500 Administrator account has NOT been renamed." "warning"

            fncAddFinding `
                -Id "LOCALADMIN_DEFAULT_ADMIN_NOT_RENAMED" `
                -Category "Reconnaissance" `
                -Title "Default Administrator Account Not Renamed" `
                -Severity "Medium" `
                -Status "Detected" `
                -Message "Built-in RID 500 account name is still 'Administrator'." `
                -Recommendation "Rename the built-in Administrator account via security policy."
        }
        else {

            fncPrintMessage ("RID 500 Administrator renamed to '{0}'." -f $rid500.Name) "success"

            fncAddFinding `
                -Id "LOCALADMIN_DEFAULT_ADMIN_RENAMED" `
                -Category "Reconnaissance" `
                -Title "Default Administrator Account Renamed" `
                -Severity "Good" `
                -Status "Not Detected" `
                -Message ("Built-in RID 500 account renamed to '{0}'." -f $rid500.Name) `
                -Recommendation "No action required."
        }

        if ($isEnabled) {

            fncPrintMessage "Built-in Administrator account is ENABLED." "warning"

            fncAddFinding `
                -Id "LOCALADMIN_DEFAULT_ADMIN_ENABLED" `
                -Category "Reconnaissance" `
                -Title "Built-in Administrator Account Enabled" `
                -Severity "Medium" `
                -Status "Detected" `
                -Message "Built-in RID 500 account is enabled." `
                -Recommendation "Disable the built-in Administrator account where possible."
        }
    }

    # ------------------------------------------------------------
    # Domain Exposure Check
    # ------------------------------------------------------------
    $exposed = @()

    foreach ($m in $members) {

        $name = [string]$m.Name

        $isDomain = $false
        if ($name -match "\\") { $isDomain = $true }

        $isBuiltInSafe =
            $rid500 -and $name -match $rid500.Name

        if ($isDomain -and -not $isBuiltInSafe) {

            $score = 70
            $severity = "High"
            $confidence = "High"

            $summary = "Domain principal '$name' is member of local Administrators"

            $exposed += [pscustomobject]@{
                Score      = $score
                Severity   = $severity
                Confidence = $confidence
                Summary    = $summary
            }

            fncAddFinding `
                -Id ("LOCALADMIN_DOMAIN_" + ($name -replace '[^A-Za-z0-9]','')) `
                -Category "Reconnaissance" `
                -Title "Domain Principal in Local Administrators" `
                -Severity $severity `
                -Status "Detected" `
                -Message $summary `
                -Recommendation "Review necessity of domain principals in local Administrators. Restrict via GPO and tiering model."
        }
    }

    fncPrintSectionHeader "Local Administrators Group Members"

    foreach ($m in $members) {
        Write-Host ("  -> {0} ({1})" -f $m.Name,$m.ObjectClass)
    }

    fncPrintMessage "" "plain"

    if ($exposed.Count -eq 0) {

        fncPrintMessage "No risky domain principals detected in local Administrators." "success"

        fncAddFinding `
            -Id "LOCALADMIN_EXPOSURE_NONE" `
            -Category "Reconnaissance" `
            -Title "Local Admin Exposure" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No risky domain principals detected in local Administrators group." `
            -Recommendation "No action required."
    }
}