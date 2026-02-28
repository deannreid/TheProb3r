# ================================================================
# Function: fncGetCredentialsPlaintextConfigSecrets
# Purpose : Identify potential plaintext secrets in config files
# ================================================================
function fncGetCredentialsPlaintextConfigSecrets {

    fncSafeSectionHeader "Plaintext Secret Exposure"

    fncSafePrintMessage "Scanning common local config locations for hardcoded secrets..." "info"
    fncSafePrintMessage "Limited local scan only. Use APMAC for deep/remote scanning." "warning"
    Write-Host ""

    # ------------------------------------------------------------
    # Exploitation Narrative
    # ------------------------------------------------------------
    $exploitationText = @"
Attackers search application configuration files for hardcoded credentials.
Recovered passwords, API keys, and tokens allow lateral movement, database access,
or cloud compromise without triggering authentication brute-force alerts.
"@

    # ------------------------------------------------------------
    # Remediation Narrative
    # ------------------------------------------------------------
    $remediationText = @"
Remove hardcoded credentials from configuration files.
Store secrets in a secure vault (Azure Key Vault, HashiCorp Vault, DPAPI, etc.).
Use environment variables or managed identities.
Rotate exposed credentials immediately.
"@

    $patterns = @(
        "(?i)password\s*=",
        "(?i)pwd\s*=",
        "(?i)connectionstring",
        "(?i)secret\s*=",
        "(?i)apikey\s*=",
        "(?i)token\s*="
    )

    $roots = @(
        "C:\inetpub\wwwroot",
        "C:\ProgramData"
    )

    foreach ($root in $roots) {

        if (-not (Test-Path $root)) { continue }

        fncSafePrintMessage "Scanning root: $root" "info"

        $matchCount = 0

        try {

            $allItems = Get-ChildItem -Path $root -Recurse -Depth 4 -ErrorAction SilentlyContinue

            $candidateFiles = $allItems | Where-Object {
                -not $_.PSIsContainer -and
                $_.Extension -match '\.(config|json|xml|env|ini)$'
            }

            foreach ($file in $candidateFiles) {

                try {

                    $lines = Get-Content $file.FullName -ErrorAction Stop
                    $lineNumber = 0

                    foreach ($line in $lines) {

                        $lineNumber++

                        foreach ($pattern in $patterns) {

                            if ($line -match $pattern) {

                                $matchCount++
                                $matchedKeyword = $matches[0]

                                $snippet = $line.Trim()
                                if ($snippet.Length -gt 140) {
                                    $snippet = $snippet.Substring(0, 140) + "..."
                                }

                                if ($snippet -match "=") {
                                    $parts = $snippet.Split("=",2)
                                    $snippet = $parts[0] + "= ***REDACTED***"
                                }

                                $findingId = "CRED-PLAINTEXT-" + (fncShortHashTag ($file.FullName + $lineNumber))

                                $fullMessage = ("Match '{0}' at line {1} in {2}" -f $matchedKeyword,$lineNumber,$file.FullName)

                                fncAddFinding `
                                    -Id $findingId `
                                    -TestId "CREDENTIALS-PLAINTEXT-CONFIG" `
                                    -Category "Credential Exposure" `
                                    -Title "Potential Hardcoded Secret in Configuration File" `
                                    -Severity "High" `
                                    -Status "Detected" `
                                    -Message $fullMessage `
                                    -Recommendation "Remove hardcoded secrets and migrate to secure secret storage." `
                                    -Exploitation $exploitationText `
                                    -Remediation $remediationText

                                if (fncCommandExists "fncWriteColour") {
                                    $symbol = fncGetSeveritySymbol "High"
                                    $colour = fncGetSeverityColour "High"

                                    fncWriteColour "$symbol [High] $($file.FullName) (line $lineNumber)" $colour
                                    fncWriteColour "      -> $snippet" ([System.ConsoleColor]::DarkGray)
                                }

                                break
                            }
                        }
                    }

                }
                catch { }
            }

        }
        catch { }

        if ($matchCount -gt 0) {
            fncSafePrintMessage ("Detected {0} potential secret(s) in $root" -f $matchCount) "warning"
        }
        else {
            fncSafePrintMessage ("No plaintext secrets detected in $root") "success"
        }

        Write-Host ""
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetCredentialsPlaintextConfigSecrets