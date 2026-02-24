# ================================================================
# Function: fncGetLateralMovementRemoteServiceExposure
# Purpose : Identify lateral movement via service abuse
# ================================================================
function fncGetLateralMovementRemoteServiceExposure {

    fncPrintMessage "Enumerating lateral movement exposure via services..." "info"
    fncPrintMessage "Initialising service enumeration for remote abuse indicators." "debug"
    fncPrintMessage "" "plain"

    $services = $null

    try {
        fncPrintMessage "Querying Win32_Service via CIM." "debug"
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        fncPrintMessage ("Total services retrieved: {0}" -f (fncSafeCount $services)) "debug"
    }
    catch {
        fncPrintMessage ("Service enumeration failed: {0}" -f $_.Exception.Message) "debug"
        fncPrintMessage "Unable to enumerate services." "warning"
        return
    }

    $inspectedCount = 0
    $hitCount = 0

    foreach ($svc in fncSafeArray $services) {

        $inspectedCount++

        try {

            $svcName   = fncSafeString $svc.Name
            $startName = fncSafeString $svc.StartName
            $startMode = fncSafeString $svc.StartMode

            fncPrintMessage (
                "Inspecting service: Name='{0}', StartName='{1}', StartMode='{2}'" -f `
                $svcName,$startName,$startMode
            ) "debug"

            if ($startName -match "LocalSystem" -and $startMode -eq "Auto") {

                fncPrintMessage (
                    "Service '{0}' meets lateral movement heuristic (SYSTEM + Auto)." -f $svcName
                ) "debug"

                $summary = "Service '$svcName' runs as SYSTEM and is auto-started (potential remote service abuse)"

                fncAddFinding `
                    -Id ("LATMOV_SERVICE_" + $svcName) `
                    -Category "Lateral Movement" `
                    -Title "SYSTEM Service Lateral Movement Surface" `
                    -Severity "Low" `
                    -Status "Detected" `
                    -Message $summary `
                    -Recommendation "Ensure service permissions restrict remote creation or modification."

                $hitCount++
            }

        }
        catch {
            fncPrintMessage (
                "Error processing service '{0}': {1}" -f `
                (fncSafeString $svc.Name), $_.Exception.Message
            ) "debug"
            continue
        }
    }

    fncPrintMessage ("Service inspection completed. Services inspected: {0}" -f $inspectedCount) "debug"
    fncPrintMessage ("Potential lateral movement service exposures identified: {0}" -f $hitCount) "debug"

    if ($hitCount -eq 0) {
        fncPrintMessage "No lateral movement service exposure heuristics triggered." "success"
    }

    fncPrintMessage "" "plain"
}

Export-ModuleMember -Function fncGetLateralMovementRemoteServiceExposure
