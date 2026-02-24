# ================================================================
# Function: fncGetCredentialsPlaintextConfigSecrets
# Purpose : Identify potential plaintext secrets in config files
# Notes   : Line-aware detection + bounded recursion
#           Limited local scan only. For deep/DFS/SMB scans use APMAC.
# ================================================================
function fncGetCredentialsPlaintextConfigSecrets {

    fncSafeSectionHeader "Plaintext Secret Exposure"

    fncSafePrintMessage "Scanning common local config locations for hardcoded secrets..." "info"
    fncSafePrintMessage "Note: This module performs LIMITED local scanning only." "warning"
    fncSafePrintMessage "For deep scanning (DFS shares, SMB paths, remote hosts, verbose secret hunting)," "warning"
    fncSafePrintMessage "use APMAC: https://github.com/deannreid/APMAC" "warning"
    fncPrintMessage "" "plain"
    fncSafePrintMessage "Run as Administrator for comprehensive results. Limited access may yield false negatives." "info"
    fncPrintMessage "" "plain"

    $verboseMode = $false
    if ($global:config -and $global:config.DEBUG) { $verboseMode = $true }

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

        if (-not (Test-Path $root)) {
            if ($verboseMode) {
                fncSafePrintMessage "Root not found: $root" "debug"
            }
            continue
        }

        fncSafePrintMessage "Scanning root: $root" "info"

        $matchCount = 0

        try {

            $allItems = Get-ChildItem -Path $root -Recurse -Depth 4 -ErrorAction SilentlyContinue

            $candidateFiles = @(
                $allItems | Where-Object {
                    -not $_.PSIsContainer -and
                    $_.Extension -match '\.(config|json|xml|env|ini)$'
                }
            )

            if ($verboseMode) {
                fncSafePrintMessage ("  Candidate config files: {0}" -f $candidateFiles.Count) "debug"
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

                                # Redact potential secret values after "="
                                $snippet = $line.Trim()
                                if ($snippet.Length -gt 140) {
                                    $snippet = $snippet.Substring(0, 140) + "..."
                                }

                                # Basic redaction (anything after '=' replaced)
                                if ($snippet -match "=") {
                                    $parts = $snippet.Split("=",2)
                                    $snippet = $parts[0] + "= ***REDACTED***"
                                }

                                $findingId = "CRED-PLAINTEXT-" + (fncShortHashTag ($file.FullName + $lineNumber))

                                fncAddFinding `
                                    -Id $findingId `
                                    -Category "Credential Access" `
                                    -Title "Potential Hardcoded Secret in Configuration File" `
                                    -Severity "High" `
                                    -Status "Detected" `
                                    -Message ("Match '{0}' at line {1} in {2}" -f $matchedKeyword,$lineNumber,$file.FullName) `
                                    -Recommendation "Move secrets to secure vaults or environment variables; remove hardcoded credentials."

                                # Immediate console feedback
                                $symbol = fncGetSeveritySymbol "High"
                                $colour = fncGetSeverityColour "High"

                                if (fncCommandExists "fncWriteColour") {
                                    fncWriteColour "$symbol [High] $($file.FullName) (line $lineNumber)" $colour
                                    fncWriteColour "      → $snippet" ([System.ConsoleColor]::DarkGray)
                                }
                                else {
                                    Write-Host "$symbol [High] $($file.FullName) (line $lineNumber)" -ForegroundColor Red
                                    Write-Host "      → $snippet"
                                }

                                break
                            }
                        }
                    }

                } catch {
                    if ($verboseMode) {
                        fncSafePrintMessage ("  Failed reading file: {0}" -f $file.FullName) "debug"
                    }
                }
            }

        } catch {
            if ($verboseMode) {
                fncSafePrintMessage ("Error scanning root: {0}" -f $root) "debug"
            }
        }

        if ($matchCount -gt 0) {
            fncSafePrintMessage ("Detected {0} potential secret(s) in $root" -f $matchCount) "warning"
        }
        else {
            fncSafePrintMessage ("No plaintext secrets detected in $root" -f $matchCount) "success"
        }

        fncPrintMessage "" "plain"
    }

    fncPrintMessage "" "plain"
}

Export-ModuleMember -Function fncGetCredentialsPlaintextConfigSecrets