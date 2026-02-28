# ================================================================
# Function: fncGetExecutionLOLBINSurfaces
# Purpose : Identify LOLBIN execution opportunities
# Notes   : SchemaVersion 5 mapping injection via -TestId
# ================================================================
function fncGetExecutionLOLBINSurfaces {

    fncSafeSectionHeader "LOLBIN Execution Surface Check"
    fncSafePrintMessage "Enumerating LOLBIN execution surfaces..." "info"
    Write-Host ""

    $testId = "EXEC-LOLBIN-EXECUTION"

    $lolbins = @(
        "powershell.exe","pwsh.exe","cmd.exe","mshta.exe",
        "wscript.exe","cscript.exe","rundll32.exe",
        "regsvr32.exe","installutil.exe"
    )

    $services = $null

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
    }
    catch {
        fncSafePrintMessage "Unable to enumerate services." "warning"
        return
    }

    $inspectedCount = 0
    $hitCount = 0

    $exploitationText = @"
LOLBINs (Living-Off-The-Land Binaries) allow attackers to execute payloads
using trusted Microsoft-signed binaries. When referenced by services,
these binaries can enable stealthy execution and defense evasion.
"@

    $remediationText = @"
Review service configurations that reference scripting engines or proxy
execution binaries. Restrict usage where possible and enforce
application allow-listing policies.
"@

    foreach ($svc in fncSafeArray $services) {

        $inspectedCount++

        try {

            $svcName   = fncSafeString $svc.Name
            $startName = fncSafeString $svc.StartName
            $pathName  = fncSafeString $svc.PathName

            if (-not $pathName) { continue }

            foreach ($bin in $lolbins) {

                if ($pathName -match [regex]::Escape($bin)) {

                    $hitCount++

                    $summary = "Service '$svcName' executes LOLBIN '$bin' (StartName='$startName')."

                    $fingerprint = "$svcName|$bin|$startName"
                    $tag = fncShortHashTag $fingerprint

                    fncAddFinding `
                        -TestId $testId `
                        -Id ("EXEC-LOLBIN-" + $tag) `
                        -Category "Execution" `
                        -Title "LOLBIN Execution Surface Detected" `
                        -Severity "Medium" `
                        -Status "Detected" `
                        -Message $summary `
                        -Recommendation "Review necessity of LOLBIN execution within this service context." `
                        -Exploitation $exploitationText `
                        -Remediation $remediationText
                }
            }

        }
        catch {
            continue
        }
    }
    Write-Host ""
}

Export-ModuleMember -Function fncGetExecutionLOLBINSurfaces