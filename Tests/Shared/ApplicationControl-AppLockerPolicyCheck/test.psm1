# ================================================================
# Function: fncCheckAppLockerPolicy
# Purpose : Enumerate AppLocker configuration + enforcement
# ================================================================
function fncCheckAppLockerPolicy {

    fncPrintMessage "Enumerating AppLocker configuration..." "info"
    fncPrintMessage "Starting AppLocker inspection routine." "debug"
    fncPrintMessage "" "plain"

    $appIdSvcRunning = $false

    # ----------------------------------------------------------
    # Check AppIDSvc enforcement service
    # ----------------------------------------------------------
    try {

        fncPrintMessage "Checking Application Identity service (AppIDSvc)." "debug"

        $svc = Get-Service -Name AppIDSvc -ErrorAction Stop
        $appIdSvcRunning = ($svc.Status -eq "Running")

        fncPrintMessage ("AppIDSvc Status='{0}', StartType='{1}'" -f $svc.Status,$svc.StartType) "debug"

        if ($appIdSvcRunning) {
            fncPrintMessage ("Application Identity Service : {0}" -f $svc.Status) "success"
        }
        else {
            fncPrintMessage ("Application Identity Service : {0}" -f $svc.Status) "warning"
        }
    }
    catch {

        fncPrintMessage "Application Identity Service not found." "warning"
        fncPrintMessage ("Exception while querying AppIDSvc: {0}" -f $_.Exception.Message) "debug"
    }

    fncPrintMessage "" "plain"

    # ----------------------------------------------------------
    # Check if AppLocker cmdlet exists
    # ----------------------------------------------------------
    fncPrintMessage "Checking presence of Get-AppLockerPolicy cmdlet." "debug"

    if (-not (Get-Command Get-AppLockerPolicy -ErrorAction SilentlyContinue)) {

        fncPrintMessage "AppLocker cmdlet not available. Performing registry inspection..." "warning"

        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2"

        fncPrintMessage ("Inspecting registry path: {0}" -f $regPath) "debug"

        if (Test-Path $regPath) {

            fncPrintMessage "AppLocker registry configuration detected." "info"

            $tag = fncShortHashTag "APPLOCKER|REGISTRY_PRESENT"

            fncAddFinding `
                -Id ("APPLOCKER_REGISTRY_PRESENT_$tag") `
                -Category "Application Control" `
                -Title "AppLocker Registry Policy Present" `
                -Severity "Info" `
                -Status "Detected" `
                -Message "Registry keys exist but cmdlet unavailable." `
                -Recommendation "Validate AppLocker configuration via GPO or Local Security Policy." `
                -Evidence $regPath
        }
        else {

            fncPrintMessage "No AppLocker configuration detected." "info"

            $tag = fncShortHashTag "APPLOCKER|NOT_PRESENT"

            fncAddFinding `
                -Id ("APPLOCKER_NOT_PRESENT_$tag") `
                -Category "Application Control" `
                -Title "AppLocker Not Configured" `
                -Severity "Low" `
                -Status "Not Detected" `
                -Message "No AppLocker registry or policy detected." `
                -Recommendation "Consider implementing application allow-listing."
        }

        return
    }

    # ----------------------------------------------------------
    # Retrieve Effective Policy
    # ----------------------------------------------------------
    try {

        fncPrintMessage "Retrieving effective AppLocker policy." "debug"

        $policy = Get-AppLockerPolicy -Effective -ErrorAction Stop

        fncPrintMessage "Effective AppLocker policy retrieved successfully." "debug"
    }
    catch {

        fncPrintMessage "Unable to retrieve effective AppLocker policy." "warning"
        fncPrintMessage ("Exception retrieving policy: {0}" -f $_.Exception.Message) "debug"

        $tag = fncShortHashTag "APPLOCKER|POLICY_UNREADABLE"

        fncAddFinding `
            -Id ("APPLOCKER_POLICY_UNREADABLE_$tag") `
            -Category "Application Control" `
            -Title "AppLocker Policy Could Not Be Retrieved" `
            -Severity "Medium" `
            -Status "Unknown" `
            -Message "Unable to retrieve effective AppLocker policy." `
            -Recommendation "Verify AppLocker deployment and permissions." `
            -Evidence $_.Exception.Message

        return
    }

    # ----------------------------------------------------------
    # Extract Collections
    # ----------------------------------------------------------
    $collections = @()
    try {

        $collections = @($policy.RuleCollections)

        fncPrintMessage ("Rule collection count detected: {0}" -f $collections.Count) "debug"

    } catch {}

    if ($collections.Count -eq 0) {

        fncPrintMessage "AppLocker installed but no rule collections exist." "warning"

        $tag = fncShortHashTag "APPLOCKER|NO_COLLECTIONS"

        fncAddFinding `
            -Id ("APPLOCKER_NO_COLLECTIONS_$tag") `
            -Category "Application Control" `
            -Title "AppLocker Installed but No Rule Collections" `
            -Severity "Medium" `
            -Status "Misconfigured" `
            -Message "AppLocker present but rule collections are empty." `
            -Recommendation "Implement rule collections for enforcement."

        return
    }

    # ----------------------------------------------------------
    # Display Rule Summary
    # ----------------------------------------------------------
    fncPrintSectionHeader "AppLocker Rule Summary"

    $ruleCounts = @{}
    $totalRules = 0

    foreach ($rc in $collections) {

        $type  = fncSafeString $rc.CollectionType
        $count = @( $rc.Rules ).Count

        fncPrintMessage ("Processing collection '{0}' with {1} rules." -f $type,$count) "debug"

        $ruleCounts[$type] = $count
        $totalRules += $count

        fncPrintMessage ("{0} Rules : {1}" -f $type,$count) "info"
    }

    fncPrintMessage "" "plain"

    # ----------------------------------------------------------
    # Show Sample Rules
    # ----------------------------------------------------------
    fncPrintSectionHeader "Sample AppLocker Rules"

    $sampleRules = @()

    foreach ($rc in $collections) {
        foreach ($rule in fncSafeArray $rc.Rules) {

            $sampleRules += [PSCustomObject]@{
                Type   = fncSafeString $rc.CollectionType
                Name   = fncSafeString $rule.Name
                Action = fncSafeString $rule.Action
            }
        }
    }

    fncPrintMessage ("Total individual rules enumerated: {0}" -f $sampleRules.Count) "debug"

    if ($sampleRules.Count -gt 0) {
        $sampleRules | Select-Object -First 10 | Format-Table -AutoSize
    }
    else {
        fncPrintMessage "No individual rules found." "warning"
    }

    fncPrintMessage "" "plain"

    # ----------------------------------------------------------
    # Evaluate Policy Strength
    # ----------------------------------------------------------
    if ($totalRules -eq 0) {

        fncPrintMessage "AppLocker policy exists but contains zero rules." "warning"

        $tag = fncShortHashTag "APPLOCKER|EMPTY_POLICY"

        fncAddFinding `
            -Id ("APPLOCKER_EMPTY_POLICY_$tag") `
            -Category "Application Control" `
            -Title "AppLocker Policy Contains No Rules" `
            -Severity "Medium" `
            -Status "Disabled" `
            -Message "AppLocker policy exists but contains zero rules." `
            -Recommendation "Create allow-list rules to enforce execution control."

        return
    }

    if (-not $appIdSvcRunning) {

        fncPrintMessage "AppLocker rules present but enforcement service stopped." "warning"

        $tag = fncShortHashTag "APPLOCKER|SERVICE_STOPPED"

        fncAddFinding `
            -Id ("APPLOCKER_SERVICE_STOPPED_$tag") `
            -Category "Application Control" `
            -Title "AppLocker Service Not Running" `
            -Severity "High" `
            -Status "Not Enforced" `
            -Message "AppLocker rules exist but enforcement service is stopped." `
            -Recommendation "Start and configure Application Identity service." `
            -Evidence "Rules exist but AppIDSvc stopped."

        return
    }

    # ----------------------------------------------------------
    # SUCCESS
    # ----------------------------------------------------------
    $evidence = ($ruleCounts.GetEnumerator() |
        ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ", "

    fncPrintMessage ("Final rule count: {0}" -f $totalRules) "debug"
    fncPrintMessage "AppLocker rules detected and enforcement active." "success"

    $tag = fncShortHashTag "APPLOCKER|ACTIVE"

    fncAddFinding `
        -Id ("APPLOCKER_ACTIVE_$tag") `
        -Category "Application Control" `
        -Title "AppLocker Policy Enforced" `
        -Severity "Good" `
        -Status "Enabled" `
        -Message "AppLocker rules are present and enforcement service is running." `
        -Recommendation "No action required." `
        -Evidence $evidence
}

Export-ModuleMember -Function fncCheckAppLockerPolicy
