# ================================================================
# Function: fncGetCredentialsBrowserSecretsExposure
# ================================================================
function fncGetCredentialsBrowserSecretsExposure {

    fncSafeSectionHeader "Browser Credential Store Exposure"
    fncSafePrintMessage "Scanning for readable browser credential databases..." "info"
    Write-Host ""

    $verboseMode = $false
    if ($global:config -and $global:config.DEBUG) { $verboseMode = $true }

    function fncTestBrowserFile {
        param(
            [string]$Path,
            [string]$BrowserName,
            [string]$Severity = "High"
        )

        if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) {
            if ($verboseMode) {
                fncSafePrintMessage "Not found: $Path" "debug"
            }
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

                if ($verboseMode) {
                    fncSafePrintMessage ("  ACE -> {0} : {1}" -f $id,$rights) "debug"
                }

                if (
                    ($id -match "Everyone" -or $id -match "Users") -and
                    ($rights -match "Read" -or
                     $rights -match "FullControl" -or
                     $rights -match "Modify")
                ) {
                    $risky += "$id ($rights)"
                }
            }

            if ($risky.Count -gt 0) {

                $findingId = "CRED-BROWSER-" + (fncShortHashTag $Path)

                fncAddFinding `
                    -Id $findingId `
                    -Category "Credential Access" `
                    -Title "$BrowserName Credential Store Readable by Low Privilege" `
                    -Severity $Severity `
                    -Status "Detected" `
                    -Message ("Credential store exposure in {0} | Risky ACE(s): {1}" -f $Path,($risky -join ", ")) `
                    -Recommendation "Restrict browser profile ACLs to the owning user; enforce full disk encryption."

                $symbol = fncGetSeveritySymbol $Severity
                $colour = fncGetSeverityColour $Severity

                if (fncCommandExists "fncWriteColour") {
                    fncWriteColour "$symbol [$Severity] $BrowserName exposure detected: $Path" $colour
                    fncWriteColour "      Risky ACE(s): $($risky -join ', ')" ([System.ConsoleColor]::DarkGray)
                }
                else {
                    Write-Host "$symbol [$Severity] $BrowserName exposure detected: $Path" -ForegroundColor Red
                }
            }
            else {
                fncSafePrintMessage "No low-privilege read exposure detected." "success"
            }

        } catch {
            if ($verboseMode) {
                fncSafePrintMessage ("Failed ACL evaluation: {0}" -f $Path) "debug"
            }
        }

        Write-Host ""
    }

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
            fncTestBrowserFile -Path (Join-Path $browser.Path "Login Data") -BrowserName $browser.Name
            continue
        }

        Get-ChildItem $browser.Path -Directory -ErrorAction SilentlyContinue | ForEach-Object {

            $profilePath = $_.FullName
            $loginDb     = Join-Path $profilePath "Login Data"
            $localState  = Join-Path $browser.Path "Local State"

            if ($verboseMode) {
                fncSafePrintMessage ("  Profile detected: {0}" -f $_.Name) "debug"
            }

            fncTestBrowserFile -Path $loginDb    -BrowserName $browser.Name -Severity "High"
            fncTestBrowserFile -Path $localState -BrowserName $browser.Name -Severity "Medium"
        }

        Write-Host ""
    }

    $firefoxRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"

    if (Test-Path $firefoxRoot) {

        fncSafePrintMessage "Detected browser: Firefox" "info"

        Get-ChildItem $firefoxRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {

            $modProfile = $_.FullName

            if ($verboseMode) {
                fncSafePrintMessage ("  Firefox profile: {0}" -f $_.Name) "debug"
            }

            fncTestBrowserFile -Path $modProfile -BrowserName "Firefox" -Severity "Medium"
        }

        Write-Host ""
    }

    $safariRoot = "$env:LOCALAPPDATA\Apple Computer\Safari"

    if (Test-Path $safariRoot) {

        fncSafePrintMessage "Detected browser: Safari (Windows)" "warning"
        fncSafePrintMessage "Safari for Windows is END-OF-LIFE and unsupported." "warning"

        fncAddFinding `
            -Id ("CRED-SAFARI-EOL-" + (fncShortHashTag $safariRoot)) `
            -Category "Credential Access" `
            -Title "Safari for Windows Installed (End-of-Life Software)" `
            -Severity "High" `
            -Status "Detected" `
            -Message "Safari for Windows detected. Product is unsupported and no longer receives security updates." `
            -Recommendation "Remove Safari for Windows immediately. Replace with a supported browser."

        $symbol = fncGetSeveritySymbol "High"
        $colour = fncGetSeverityColour "High"

        if (fncCommandExists "fncWriteColour") {

            fncWriteColour "============================================================" ([System.ConsoleColor]::Red)
            fncWriteColour "  $symbol  SAFARI FOR WINDOWS DETECTED (END-OF-LIFE)" ([System.ConsoleColor]::Red)
            fncWriteColour "  This browser is unsupported and receives NO security updates." ([System.ConsoleColor]::Red)
            fncWriteColour "  Immediate removal is strongly recommended." ([System.ConsoleColor]::Red)
            fncWriteColour "============================================================" ([System.ConsoleColor]::Red)

        }
        else {
            Write-Host "============================================================" -ForegroundColor Red
            Write-Host "  SAFARI FOR WINDOWS DETECTED (END-OF-LIFE)" -ForegroundColor Red
            Write-Host "  This browser is unsupported and receives NO security updates." -ForegroundColor Red
            Write-Host "  Immediate removal is strongly recommended." -ForegroundColor Red
            Write-Host "============================================================" -ForegroundColor Red
        }

        $safariTargets = @(
            (Join-Path $safariRoot "WebKit"),
            (Join-Path $safariRoot "LocalStorage"),
            (Join-Path $safariRoot "Databases")
        )

        foreach ($path in $safariTargets) {
            fncTestBrowserFile -Path $path -BrowserName "Safari" -Severity "High"
        }

        Write-Host ""
    }

    Write-Host ""
}

Export-ModuleMember -Function fncGetCredentialsBrowserSecretsExposure