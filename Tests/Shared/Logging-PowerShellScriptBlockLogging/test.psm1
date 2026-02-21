# ================================================================
# Function: fncCheckPSScriptBlockLogging
# Purpose : Check if PowerShell Script Block Logging is enabled
# ================================================================
function fncCheckPSScriptBlockLogging {

    fncPrintMessage "Checking PowerShell Script Block Logging configuration..." "info"
    fncPrintMessage "Initialising Script Block Logging registry inspection." "debug"

    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    fncPrintMessage ("Target registry path: {0}" -f $regPath) "debug"

    try {

        if (Test-Path $regPath) {

            fncPrintMessage "ScriptBlockLogging registry key exists." "debug"

            $value = Get-ItemProperty -Path $regPath -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue

            if ($null -eq $value) {

                fncPrintMessage "EnableScriptBlockLogging value missing under registry key." "debug"

                fncAddFinding `
                    -Id "PS-SCRIPTBLOCK-LOGGING" `
                    -Category "Logging & Monitoring" `
                    -Title "PowerShell Script Block Logging" `
                    -Severity "Medium" `
                    -Status "Not Configured" `
                    -Message "Script Block Logging registry key exists but EnableScriptBlockLogging value is missing." `
                    -Recommendation "Configure EnableScriptBlockLogging via GPO or registry."

                fncPrintMessage "Script Block Logging registry key present but value missing." "warning"
                return
            }

            fncPrintMessage ("Registry value EnableScriptBlockLogging = {0}" -f $value.EnableScriptBlockLogging) "debug"

            if ($value.EnableScriptBlockLogging -eq 1) {

                fncPrintMessage "Script Block Logging evaluated as ENABLED." "debug"

                fncAddFinding `
                    -Id "PS-SCRIPTBLOCK-LOGGING" `
                    -Category "Logging & Monitoring" `
                    -Title "PowerShell Script Block Logging" `
                    -Severity "Good" `
                    -Status "Enabled" `
                    -Message "Script Block Logging is enabled." `
                    -Recommendation "No action required."

                fncPrintMessage "Script Block Logging is enabled." "success"

            }
            else {

                fncPrintMessage "Script Block Logging evaluated as DISABLED." "debug"

                fncAddFinding `
                    -Id "PS-SCRIPTBLOCK-LOGGING" `
                    -Category "Logging & Monitoring" `
                    -Title "PowerShell Script Block Logging" `
                    -Severity "Medium" `
                    -Status "Disabled" `
                    -Message "Script Block Logging is NOT enabled." `
                    -Recommendation "Enable via GPO or registry."

                fncPrintMessage "Script Block Logging is NOT enabled." "warning"
            }
        }
        else {

            fncPrintMessage "ScriptBlockLogging registry key not found." "debug"

            fncAddFinding `
                -Id "PS-SCRIPTBLOCK-LOGGING" `
                -Category "Logging & Monitoring" `
                -Title "PowerShell Script Block Logging" `
                -Severity "Medium" `
                -Status "Not Configured" `
                -Message "Script Block Logging registry key not found." `
                -Recommendation "Enable via GPO."

            fncPrintMessage "Script Block Logging not configured." "warning"
        }
    }
    catch {

        fncPrintMessage ("Exception encountered while checking Script Block Logging: {0}" -f $_.Exception.Message) "debug"
        fncPrintMessage "Failed to check Script Block Logging." "error"
    }

    fncPrintMessage "Script Block Logging inspection complete." "debug"
}

Export-ModuleMember -Function fncCheckPSScriptBlockLogging
