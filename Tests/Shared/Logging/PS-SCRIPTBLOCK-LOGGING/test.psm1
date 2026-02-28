# ================================================================
# Function: fncCheckPSScriptBlockLogging
# Purpose : Check if PowerShell Script Block Logging is enabled
# Notes   : Registry-based inspection (low-priv compatible)
# ================================================================
function fncCheckPSScriptBlockLogging {

    fncPrintMessage "Checking PowerShell Script Block Logging configuration..." "info"
    fncPrintMessage "Initialising Script Block Logging registry inspection." "debug"

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    $score = 0
    $status = "Unknown"
    $severity = "Info"

    try {

        if (-not (Test-Path $regPath)) {

            $score = 70
            $status = "Not Configured"
            $severity = "High"

            $message = "Script Block Logging registry key not found."

        }
        else {

            $value = Get-ItemProperty -Path $regPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue

            if ($null -eq $value -or $value.EnableScriptBlockLogging -ne 1) {

                $score = 80
                $status = "Disabled"
                $severity = "High"

                $message = "Script Block Logging is not enabled."

            }
        }

        $title = switch ($severity) {
            "High"  { "PowerShell Script Block Logging Disabled" }
           # "Info"  { "PowerShell Script Block Logging Enabled" }
            default { "PowerShell Script Block Logging Configuration" }
        }

$exploitation = @"
PowerShell Script Block Logging records executed PowerShell code in detail.

When disabled, attackers can execute obfuscated or fileless PowerShell payloads
without full forensic visibility, significantly reducing detection capability.

This technique is frequently leveraged in fileless malware and lateral movement.
"@

$remediation = @"
Enable Script Block Logging via Group Policy:

Computer Configuration ->
Administrative Templates ->
Windows Components ->
Windows PowerShell ->
Turn on PowerShell Script Block Logging

Alternatively set registry value:

HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1 (DWORD)

Ensure centralized log collection (SIEM) captures Event ID 4104.
"@

        fncAddFinding `
            -Id "PS-SCRIPTBLOCK-LOGGING" `
            -TestId "PS-SCRIPTBLOCK-LOGGING" `
            -Category "Logging & Monitoring" `
            -Title $title `
            -Severity $severity `
            -Status $status `
            -Message ("{0}`nScore={1}/100" -f $message,$score) `
            -Exploitation $exploitation `
            -Remediation $remediation `
            -Recommendation "Enable and centrally collect Script Block Logging events."
    }
    catch {
        fncPrintMessage ("Exception encountered: {0}" -f $_.Exception.Message) "error"
    }

    fncPrintMessage "Script Block Logging inspection complete." "debug"
}

Export-ModuleMember -Function fncCheckPSScriptBlockLogging