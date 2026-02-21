# ================================================================
# Function: fncGetExecutionLOLBINSurfaces
# Purpose : Identify LOLBIN execution opportunities
# ================================================================
function fncGetExecutionLOLBINSurfaces {

    fncPrintMessage "Enumerating LOLBIN execution surfaces..." "info"
    fncPrintMessage "Initialising LOLBIN service execution analysis." "debug"
    Write-Host ""

    $lolbins = @(
        "powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
        "wscript.exe","cscript.exe","rundll32.exe",
        "regsvr32.exe","installutil.exe"
    )

    fncPrintMessage ("LOLBIN signatures loaded: {0}" -f ($lolbins -join ", ")) "debug"

    $findings = @()
    $services = $null

    try {
        fncPrintMessage "Querying Win32_Service via CIM." "debug"
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        fncPrintMessage ("Services retrieved: {0}" -f (fncSafeCount $services)) "debug"
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
            $pathName  = fncSafeString $svc.PathName

            fncPrintMessage (
                "Inspecting service: Name='{0}', StartName='{1}', Path='{2}'" -f `
                $svcName,$startName,$pathName
            ) "debug"

            if (-not $pathName) {
                fncPrintMessage ("Service '{0}' has no executable path. Skipping." -f $svcName) "debug"
                continue
            }

            foreach ($bin in $lolbins) {

                try {

                    if ($pathName -match [regex]::Escape($bin)) {

                        fncPrintMessage (
                            "LOLBIN match detected: Service '{0}' contains '{1}'" -f $svcName,$bin
                        ) "debug"

                        $summary = "Service '$svcName' executes LOLBIN '$bin' (StartName='$startName')"

                        $findings += $summary
                        $hitCount++

                        $fingerprint = "$svcName|$bin|$startName"
                        $tag = fncShortHashTag $fingerprint

                        fncAddFinding `
                            -Id ("EXEC_LOLBIN_$tag") `
                            -Category "Execution" `
                            -Title "LOLBIN Execution Surface Detected" `
                            -Severity "Medium" `
                            -Status "Detected" `
                            -Message $summary `
                            -Recommendation "Review necessity of LOLBIN execution. Prefer signed binaries with constrained arguments."
                    }

                }
                catch {
                    fncPrintMessage (
                        "Error evaluating LOLBIN '{0}' for service '{1}': {2}" -f `
                        $bin,$svcName,$_.Exception.Message
                    ) "debug"
                    continue
                }
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
    fncPrintMessage ("LOLBIN execution surfaces identified: {0}" -f $hitCount) "debug"

    if (-not $findings -or $findings.Count -eq 0) {
        fncPrintMessage "No LOLBIN execution surfaces detected." "success"
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetExecutionLOLBINSurfaces
