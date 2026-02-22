# ================================================================
# Function: fncGetCredentialsDpapiExposure
# ================================================================
function fncGetCredentialsDpapiExposure {

    fncSafeSectionHeader "DPAPI Exposure Analysis"
    fncSafePrintMessage "Checking DPAPI masterkey and machine blob exposure..." "info"
    fncSafePrintMessage "Evaluating ACL exposure beyond expected user context." "info"
    Write-Host ""

    $verboseMode = $false
    if ($global:config -and $global:config.DEBUG) { $verboseMode = $true }

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
            $owner = fncSafeString $acl.Owner

            if ($verboseMode) {
                fncSafePrintMessage ("  Owner: {0}" -f $owner) "debug"
            }

            $risk = $false
            $riskyEntries = @()

            foreach ($ace in $acl.Access) {

                if ($ace.AccessControlType -ne "Allow") { continue }

                $id = fncSafeString $ace.IdentityReference
                $rights = fncSafeString $ace.FileSystemRights

                if ($verboseMode) {
                    fncSafePrintMessage ("  ACE -> {0} : {1}" -f $id,$rights) "debug"
                }

                if (
                    ($id -match "Everyone" -or
                     $id -match "Users") -and
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

                fncAddFinding `
                    -Id $findingId `
                    -Category "Credential Access" `
                    -Title "DPAPI Masterkey Directory Writable by Low Privilege" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("Low-priv write exposure detected in {0} | Risky ACE(s): {1}" -f $path,($riskyEntries -join ", ")) `
                    -Recommendation "Restrict write permissions on DPAPI directories to the owning user or SYSTEM only."

                $symbol = fncGetSeveritySymbol "High"
                $colour = fncGetSeverityColour "High"

                if (fncCommandExists "fncWriteColour") {
                    fncWriteColour "$symbol [High] DPAPI exposure detected: $path" $colour
                    fncWriteColour "      Risky ACE(s): $($riskyEntries -join ', ')" ([System.ConsoleColor]::DarkGray)
                }
                else {
                    Write-Host "$symbol [High] DPAPI exposure detected: $path" -ForegroundColor Red
                    Write-Host "      Risky ACE(s): $($riskyEntries -join ', ')"
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