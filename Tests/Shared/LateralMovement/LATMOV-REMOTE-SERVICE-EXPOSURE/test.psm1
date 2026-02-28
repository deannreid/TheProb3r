# ================================================================
# Function: fncGetLateralMovementRemoteServiceExposure
# Purpose : Identify lateral movement via service abuse
# Notes   : Heuristic detection of SYSTEM auto-start services
# ================================================================
function fncGetLateralMovementRemoteServiceExposure {

    fncPrintMessage "Enumerating lateral movement exposure via services..." "info"
    fncPrintMessage "Initialising service enumeration for remote abuse indicators." "debug"
    Write-Host ""

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
    }
    catch {
        fncPrintMessage ("Service enumeration failed: {0}" -f $_.Exception.Message) "warning"
        return
    }

    $hitCount = 0

    foreach ($svc in $services) {

        try {

            $svcName   = [string]$svc.Name
            $startName = [string]$svc.StartName
            $startMode = [string]$svc.StartMode

            # Heuristic: SYSTEM + Auto start
            if ($startName -match "LocalSystem" -and $startMode -eq "Auto") {

                # Risk scoring
                $score = 40

                if ($svcName -match "SQL|Backup|Remote|Admin|Update") { $score += 20 }
                if ($svc.PathName -match "ProgramData|Users|Temp") { $score += 20 }

                if ($score -gt 100) { $score = 100 }

                # Severity mapping
                if ($score -ge 80) { $severity="High" }
                elseif ($score -ge 60) { $severity="Medium" }
                else { $severity="Low" }

                $summary = "Service '$svcName' runs as SYSTEM and auto-starts (potential remote service abuse surface)"

                $title = switch ($severity) {
                    "High"   { "High-Risk SYSTEM Service Lateral Movement Surface" }
                    "Medium" { "SYSTEM Service Exposure (Moderate Risk)" }
                    default  { "SYSTEM Service Lateral Movement Surface" }
                }

$exploitation = @"
Services running as LocalSystem with automatic start provide privileged
execution context.

If an attacker gains the ability to create, modify, or reconfigure
services remotely (e.g., via SCM, WMI, PsExec, or RPC),
they may achieve privilege escalation or lateral movement.
"@

$remediation = @"
Review the following:

- Restrict Service Control Manager (SCM) permissions.
- Audit who can create or modify services remotely.
- Ensure no unnecessary SYSTEM services are auto-started.
- Apply least privilege service accounts where possible.
- Monitor for suspicious service creation events (Event ID 7045).
"@

                fncAddFinding `
                    -Id ("LATMOV_SERVICE_" + ($svcName -replace '[^A-Za-z0-9]','')) `
                    -TestId "LATMOV-REMOTE-SERVICE-EXPOSURE" `
                    -Category "Lateral Movement" `
                    -Title $title `
                    -Severity $severity `
                    -Status "Detected" `
                    -Message ("{0}`nScore={1}/100" -f $summary,$score) `
                    -Exploitation $exploitation `
                    -Remediation $remediation `
                    -Recommendation "Restrict remote service control permissions and audit service configuration."

                $hitCount++
            }
        }
        catch {
            fncPrintMessage ("Error processing service '{0}': {1}" -f $svc.Name,$_.Exception.Message) "debug"
            continue
        }
    }
    Write-Host ""
}

Export-ModuleMember -Function fncGetLateralMovementRemoteServiceExposure