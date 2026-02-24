# ================================================================
# Function: fncGetInterestingServiceAccounts
# Purpose : Enumerate services running as non built-in accounts
# ================================================================
function fncGetInterestingServiceAccounts {

    fncPrintMessage "Enumerating services running as non built-in accounts..." "info"
    fncPrintMessage "Starting service enumeration routine." "debug"
    fncPrintMessage "" "plain"

    $interesting  = @()
    $serviceCount = 0

    $ignoreAccounts = @(
        "LocalSystem",
        "NT AUTHORITY\LocalService",
        "NT AUTHORITY\NetworkService"
    )

    fncPrintMessage ("Ignore list initialised with {0} built-in accounts." -f $ignoreAccounts.Count) "debug"

    # ----------------------------------------------------------
    # Enumerate Services
    # ----------------------------------------------------------
    try {
        fncPrintMessage "Querying Win32_Service via CIM..." "debug"
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        fncPrintMessage ("Successfully retrieved {0} services from CIM." -f ($services.Count)) "debug"
    }
    catch {

        fncPrintMessage "Failed to enumerate services." "warning"
        fncPrintMessage ("Exception during service enumeration: {0}" -f $_.Exception.Message) "debug"

        $fingerprint = "SERVICE_ENUM"
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("SERVICE_ENUM_FAILED_$tag") `
            -Category "Recon" `
            -Title "Service Enumeration Failed" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "Unable to enumerate Windows services." `
            -Recommendation "Verify permissions or WMI availability."

        return
    }

    foreach ($svc in $services) {

        $serviceCount++

        try {

            $account = fncSafeString $svc.StartName
            if (-not $account) {
                fncPrintMessage ("Skipping service '{0}' - no StartName value." -f $svc.Name) "debug"
                continue
            }

            if ($ignoreAccounts -contains $account) {
                fncPrintMessage ("Ignoring service '{0}' running as built-in account '{1}'." -f $svc.Name,$account) "debug"
                continue
            }

            fncPrintMessage ("Interesting service detected: {0} running as {1}" -f $svc.Name,$account) "debug"

            $interesting += [PSCustomObject]@{
                ServiceName = fncSafeString $svc.Name
                DisplayName = fncSafeString $svc.DisplayName
                StartName   = $account
                StartMode   = fncSafeString $svc.StartMode
                State       = fncSafeString $svc.State
            }
        }
        catch {
            fncPrintMessage ("Error processing service '{0}': {1}" -f $svc.Name,$_.Exception.Message) "debug"
            continue
        }
    }

    fncPrintMessage ("Processed {0} services. Interesting services found: {1}" -f $serviceCount,$interesting.Count) "debug"

    # ----------------------------------------------------------
    # No Findings
    # ----------------------------------------------------------
    if ($interesting.Count -eq 0) {

        fncPrintMessage "No services running as non built-in accounts detected." "success"
        fncPrintMessage "All enumerated services used built-in service accounts." "debug"

        $fingerprint = "SERVICE_NO_INTERESTING"
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("SERVICE_NO_INTERESTING_$tag") `
            -Category "Recon" `
            -Title "No Non Built-In Service Accounts Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "All enumerated services run using built-in service accounts." `
            -Recommendation "No action required."

        return
    }

    # ----------------------------------------------------------
    # Display Results
    # ----------------------------------------------------------
    fncPrintSectionHeader "Services Running As Non Built-In Accounts"
    fncPrintMessage "Displaying interesting service accounts to operator." "debug"

    foreach ($svc in $interesting) {

        Write-Host ("Service     : {0} ({1})" -f $svc.ServiceName,$svc.DisplayName)
        Write-Host ("Runs As     : {0}" -f $svc.StartName)
        Write-Host ("Start Mode  : {0}" -f $svc.StartMode)
        Write-Host ("State       : {0}" -f $svc.State)
        Write-Host ("Exploit Note: Target this account for credential theft, token abuse, or service hijacking.")
        Write-Host "-------------------------------------------"
    }

    fncPrintMessage "" "plain"

    # ----------------------------------------------------------
    # Finding Creation
    # ----------------------------------------------------------
    fncPrintMessage ("Found {0} services running as non built-in accounts." -f $interesting.Count) "warning"
    fncPrintMessage "Creating findings for each interesting service." "debug"

    foreach ($svc in $interesting) {

        $fingerprint = "$($svc.ServiceName)|$($svc.StartName)"
        $tag = fncShortHashTag $fingerprint

        fncPrintMessage ("Creating finding for service '{0}' running as '{1}'." -f $svc.ServiceName,$svc.StartName) "debug"

        fncAddFinding `
            -Id ("SERVICE_INTERESTING_$tag") `
            -Category "Recon" `
            -Title "Service Running As Custom Account" `
            -Severity "Info" `
            -Status "Detected" `
            -Message ("Service '{0}' runs as '{1}' (StartMode={2}, State={3})" -f `
                        $svc.ServiceName,$svc.StartName,$svc.StartMode,$svc.State) `
            -Recommendation "Review service permissions, credentials storage, and service binary paths for abuse opportunities."
    }

    fncPrintMessage "Service account enumeration routine completed." "debug"
}

Export-ModuleMember -Function fncGetInterestingServiceAccounts
