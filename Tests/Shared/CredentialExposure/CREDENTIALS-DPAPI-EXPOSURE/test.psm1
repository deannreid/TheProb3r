# ================================================================
# Function: fncGetCredentialsDpapiExposure
# Purpose : Detect insecure ACL exposure on DPAPI masterkey paths
# Notes   : Mapping embedded directly into finding
# ================================================================
function fncGetCredentialsDpapiExposure {

    fncSafeSectionHeader "DPAPI Exposure Analysis"
    fncSafePrintMessage "Checking DPAPI masterkey and machine blob exposure..." "info"
    Write-Host ""

    $verboseMode = $false
    if ($global:config -and $global:config.DEBUG) { $verboseMode = $true }

    # ------------------------------------------------------------
    # Exploitation Narrative
    # ------------------------------------------------------------
    $exploitationText = @"
If low-privileged users can write to DPAPI masterkey directories,
they may replace or manipulate DPAPI blobs.
Combined with local privilege escalation, this may allow credential recovery
or compromise of encrypted secrets tied to the machine or user context.
"@

    # ------------------------------------------------------------
    # Remediation Narrative
    # ------------------------------------------------------------
    $remediationText = @"
Restrict write permissions on DPAPI directories.
Ensure only SYSTEM and the owning user have Modify access.
Remove inherited permissions for 'Users' or 'Everyone'.
Audit ACL inheritance on ProgramData\Microsoft\Protect.
"@

    $targets = @(
        "$env:APPDATA\Microsoft\Protect",
        "$env:LOCALAPPDATA\Microsoft\Protect",
        "$env:ProgramData\Microsoft\Protect"
    )

    foreach ($path in $targets) {

        if (-not (Test-Path -LiteralPath $path -ErrorAction SilentlyContinue)) {
            if ($verboseMode) {
                fncSafePrintMessage "Path not found: $path" "debug"
            }
            continue
        }

        fncSafePrintMessage "Evaluating: $path" "info"

        try {

            $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
            $risk = $false
            $riskyEntries = @()

            foreach ($ace in $acl.Access) {

                if ($ace.AccessControlType -ne "Allow") { continue }

                $id     = fncSafeString $ace.IdentityReference
                $rights = fncSafeString $ace.FileSystemRights

                if (
                    ($id -match "Everyone" -or $id -match "Users") -and
                    ($rights -match "Write" -or
                     $rights -match "Modify" -or
                     $rights -match "FullControl")
                ) {
                    $risk = $true
                    $riskyEntries += "$id ($rights)"
                }
            }

            if ($risk) {

                $findingId = "CRED-DPAPI-" + (fncShortHashTag $path)

                $message = ("Low-priv write exposure detected in {0} | Risky ACE(s): {1}" -f $path,($riskyEntries -join ", "))

                if (-not [string]::IsNullOrWhiteSpace($mappingSummary)) {
                    $message += "`nMapping: $mappingSummary"
                }

                fncAddFinding `
                    -Id $findingId `
                    -TestId "CREDENTIALS-DPAPI-EXPOSURE" `
                    -Category "Credential Exposure" `
                    -Title "DPAPI Masterkey Directory Writable by Low Privilege" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message $message `
                    -Recommendation "Restrict write permissions on DPAPI directories to SYSTEM and the owning user only." `
                    -Exploitation $exploitationText `
                    -Remediation $remediationText

                $symbol = fncGetSeveritySymbol "High"
                $colour = fncGetSeverityColour "High"

                if (fncCommandExists "fncWriteColour") {
                    fncWriteColour "$symbol [High] DPAPI exposure detected: $path" $colour
                    fncWriteColour "      Risky ACE(s): $($riskyEntries -join ', ')" ([System.ConsoleColor]::DarkGray)
                }
            }
            else {
                fncSafePrintMessage "No low-privilege write exposure detected." "success"
            }

        }
        catch {
            if ($verboseMode) {
                fncSafePrintMessage ("Failed ACL evaluation: {0}" -f $path) "debug"
            }
        }

        Write-Host ""
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetCredentialsDpapiExposure