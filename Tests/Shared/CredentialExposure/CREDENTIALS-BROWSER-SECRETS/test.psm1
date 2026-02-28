# ================================================================
# Function: fncGetCredentialsBrowserSecretsExposure
# Purpose : Detect readable browser credential stores
# Notes   : Enriches findings with MITRE/NIST/CWE mapping metadata
#           Mapping is embedded in the SAME finding (no -MAP finding)
#           Finding Id = fncShortHashTag($Path) as requested
# ================================================================
function fncGetCredentialsBrowserSecretsExposure {

    fncSafeSectionHeader "Browser Credential Store Exposure"
    fncSafePrintMessage "Scanning for readable browser credential databases..." "info"
    Write-Host ""

    $verboseMode = $false
    if ($global:config -and $global:config.DEBUG) { $verboseMode = $true }

    # ------------------------------------------------------------
    # Retrieve this test's metadata (for mappings)
    # ------------------------------------------------------------
    $thisTest = $null
    try {
        $thisTest = $global:ProberState.Tests | Where-Object { (fncSafeString $_.Id) -eq "CREDENTIALS-BROWSER-SECRETS" } | Select-Object -First 1
    } catch {}

    $mappingSummary = ""
    if ($thisTest -and $thisTest.Mappings) {

        $parts = @()

        foreach ($m in (fncSafeArray $thisTest.Mappings.MitreAttack)) {
            $tech = fncSafeString $m.Technique
            $sub  = fncSafeString $m.SubTechnique
            $name = fncSafeString $m.Name

            if (-not [string]::IsNullOrWhiteSpace($sub)) {
                $parts += "MITRE $tech.$sub - $name"
            }
            else {
                $parts += "MITRE $tech - $name"
            }
        }

        foreach ($c in (fncSafeArray $thisTest.Mappings.CWE)) {
            $parts += ("CWE {0} - {1}" -f (fncSafeString $c.Id),(fncSafeString $c.Name))
        }

        foreach ($n in (fncSafeArray $thisTest.Mappings.Nist)) {
            $parts += ("NIST {0} - {1}" -f (fncSafeString $n.Control),(fncSafeString $n.Name))
        }

        if ($parts.Count -gt 0) {
            $mappingSummary = ($parts -join " | ")
        }
    }

    # ------------------------------------------------------------
    # Exploitation description (constant for this test)
    # ------------------------------------------------------------
    $exploitationText = @"
Low-privileged users may directly copy browser credential databases.
If the Local State key file is readable, DPAPI-protected secrets can be decrypted offline.
Attackers commonly extract Chrome/Edge 'Login Data' and decrypt passwords to pivot laterally.
"@

    # ------------------------------------------------------------
    # Remediation description (constant for this test)
    # ------------------------------------------------------------
    $remediationText = @"
Restrict profile directory ACLs to the owning user only.
Remove inherited permissions for 'Users' or 'Everyone'.
Enforce full disk encryption (BitLocker).
Harden endpoint configuration baselines.
"@

    function fncTestBrowserFile {
        param(
            [string]$Path,
            [string]$BrowserName,
            [string]$Severity = "High"
        )

        if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            if ($verboseMode) { fncSafePrintMessage "Not found: $Path" "debug" }
            return
        }

        fncSafePrintMessage "Evaluating: $Path" "info"

        try {

            $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
            $risky = @()

            foreach ($ace in $acl.Access) {

                if ($ace.AccessControlType -ne "Allow") { continue }

                $id     = fncSafeString $ace.IdentityReference
                $rights = fncSafeString $ace.FileSystemRights

                if (
                    ($id -match "Everyone" -or $id -match "Users") -and
                    ($rights -match "Read" -or $rights -match "ReadAndExecute" -or $rights -match "FullControl" -or $rights -match "Modify")
                ) {
                    $risky += "$id ($rights)"
                }
            }

            if ((fncSafeCount $risky) -gt 0) {

                # As requested: finding id uses fncShortHashTag($Path)
                $findingId = "CRED-BROWSER-" + (fncShortHashTag $Path)

                $msg = ("Credential store exposure in {0} | Risky ACE(s): {1}" -f $Path,($risky -join ", "))

                if (-not [string]::IsNullOrWhiteSpace($mappingSummary)) {
                    $msg += "`nMapping: $mappingSummary"
                }

                fncAddFinding `
                    -Id $findingId `
                    -TestId "CREDENTIALS-BROWSER-SECRETS" `
                    -Category "Credential Exposure" `
                    -Title "$BrowserName Credential Store Readable by Low Privilege" `
                    -Severity $Severity `
                    -Status "Detected" `
                    -Message $msg `
                    -Recommendation "Restrict browser profile ACLs to the owning user." `
                    -Exploitation $exploitationText `
                    -Remediation $remediationText

                $symbol = fncGetSeveritySymbol $Severity
                $colour = fncGetSeverityColour $Severity

                if (fncCommandExists "fncWriteColour") {
                    fncWriteColour "$symbol [$Severity] $BrowserName exposure detected: $Path" $colour
                    fncWriteColour "      Risky ACE(s): $($risky -join ', ')" ([System.ConsoleColor]::DarkGray)
                }
                else {
                    Write-Host "$symbol [$Severity] $BrowserName exposure detected: $Path" -ForegroundColor Red
                    Write-Host "      Risky ACE(s): $($risky -join ', ')"
                }
            }
            else {
                fncSafePrintMessage "No low-privilege read exposure detected." "success"
            }

        }
        catch {
            if ($verboseMode) {
                fncSafePrintMessage ("Failed ACL evaluation: {0}" -f $Path) "debug"
            }
        }

        Write-Host ""
    }

    # ------------------------------------------------------------
    # Browser scanning logic (unchanged)
    # ------------------------------------------------------------
    $chromiumRoots = @(
        @{ Name="Chrome"; Path="$env:LOCALAPPDATA\Google\Chrome\User Data" },
        @{ Name="Edge";   Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data" },
        @{ Name="Brave";  Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data" },
        @{ Name="Opera";  Path="$env:APPDATA\Opera Software\Opera Stable" }
    )

    foreach ($browser in $chromiumRoots) {

        if (-not (Test-Path $browser.Path -ErrorAction SilentlyContinue)) { continue }

        fncSafePrintMessage "Detected browser: $($browser.Name)" "info"

        if ($browser.Name -eq "Opera") {
            fncTestBrowserFile -Path (Join-Path $browser.Path "Login Data") -BrowserName $browser.Name -Severity "High"
            continue
        }

        Get-ChildItem $browser.Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {

            $profilePath = $_.FullName
            $loginDb     = Join-Path $profilePath "Login Data"
            $localState  = Join-Path $browser.Path "Local State"

            fncTestBrowserFile -Path $loginDb    -BrowserName $browser.Name -Severity "High"
            fncTestBrowserFile -Path $localState -BrowserName $browser.Name -Severity "Medium"
        }

        Write-Host ""
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetCredentialsBrowserSecretsExposure