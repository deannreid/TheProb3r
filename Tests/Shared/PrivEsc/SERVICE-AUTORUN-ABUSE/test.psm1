# ================================================================
# Function: fncServiceAndAutorunAbuse
# Purpose : Detect privilege escalation surfaces via services,
#           autoruns, and writable high-priv binaries.
# Notes   : Lean V5 version using Core enrichment via fncAddFinding
# ================================================================
function fncServiceAndAutorunAbuse {

    fncSafeSectionHeader "Service and Autorun Abuse"
    fncSafePrintMessage "Enumerating privilege escalation surfaces..." "info"
    Write-Host ""

    $testId = "SERVICE-AUTORUN-ABUSE"

# ================================================================
# Narratives
# ================================================================
$exploitationText = @"
Writable service binaries, unquoted service paths, writable autoruns,
and dangerous token privileges can be chained to achieve SYSTEM-level execution.
"@

$remediationText = @"
Harden ACLs on service binaries and directories.
Quote all service paths containing spaces.
Remove write permissions from broad principals.
Review autorun entries and restrict write access.
Audit token privileges and dangerous group membership.
"@

# ================================================================
# Helper Functions
# ================================================================
function fncLocal_NormalisePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim() -replace '"',''
    if ($p -match '^(.*?\.(exe|dll|sys|bat|cmd|ps1))') { return $Matches[1] }
    return $p.Split(" ")[0]
}

function fncLocal_IsWritableByBroadPrincipal {
    param([string]$Path)

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        foreach ($ace in $acl.Access) {
            if ($ace.IdentityReference -match "Everyone|Users|Authenticated Users") {
                if ($ace.FileSystemRights -match "Write|Modify|FullControl") {
                    return $true
                }
            }
        }
    } catch {}
    return $false
}

# ================================================================
# TOKEN POSTURE
# ================================================================
fncSafeSectionHeader "Token Posture Signals"

try {
    $identity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $groups    = @()

    foreach ($sid in $identity.Groups) {
        try { $groups += $sid.Translate([System.Security.Principal.NTAccount]).Value }
        catch { $groups += $sid.Value }
    }

    $dangerGroups = @(
        "Administrators",
        "Backup Operators",
        "Print Operators",
        "Server Operators",
        "Hyper-V Administrators"
    )

    foreach ($dg in $dangerGroups) {
        if ($groups -match $dg) {
            fncAddFinding `
                -TestId $testId `
                -Id ("GROUP_" + ($dg -replace " ","_")) `
                -Category "Privilege Escalation" `
                -Title ("Dangerous Group Membership: {0}" -f $dg) `
                -Severity "High" `
                -Status "Detected" `
                -Message ("User is member of {0}" -f $dg) `
                -Recommendation "Review necessity of membership." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }
    }

    $privOutput = whoami /priv
    if ($privOutput -match "SeImpersonatePrivilege\s+Enabled") {
        fncAddFinding `
            -TestId $testId `
            -Id "PRIV_SeImpersonatePrivilege" `
            -Category "Privilege Escalation" `
            -Title "Privilege Enabled: SeImpersonatePrivilege" `
            -Severity "High" `
            -Status "Detected" `
            -Message "SeImpersonatePrivilege is enabled." `
            -Recommendation "Remove if not required." `
            -Exploitation $exploitationText `
            -Remediation $remediationText
    }

} catch {}

# ================================================================
# SERVICE ANALYSIS
# ================================================================
fncSafeSectionHeader "Service Abuse Surfaces"

try {
    $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue

    foreach ($svc in $services) {

        $exePath = fncLocal_NormalisePath $svc.PathName
        if (-not (Test-Path $exePath)) { continue }

        # --- Unquoted Path
        if ($svc.PathName -match "\s" -and -not $svc.PathName.StartsWith('"')) {

            fncAddFinding `
                -TestId $testId `
                -Id ("SERVICE_UNQUOTED_" + $svc.Name) `
                -Category "Privilege Escalation" `
                -Title "Unquoted Service Path" `
                -Severity "High" `
                -Status "Detected" `
                -Message ("Service {0} has unquoted path: {1}" -f $svc.Name,$svc.PathName) `
                -Recommendation "Quote service binary path." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }

        # --- Writable Binary
        if (fncLocal_IsWritableByBroadPrincipal $exePath) {

            fncAddFinding `
                -TestId $testId `
                -Id ("SERVICE_WRITABLE_BIN_" + $svc.Name) `
                -Category "Privilege Escalation" `
                -Title "Writable Service Binary" `
                -Severity "High" `
                -Status "Detected" `
                -Message ("Writable service binary: {0}" -f $exePath) `
                -Recommendation "Remove write permissions from broad principals." `
                -Exploitation $exploitationText `
                -Remediation $remediationText
        }
    }

} catch {}

# ================================================================
# AUTORUN ANALYSIS
# ================================================================
fncSafeSectionHeader "Autorun Abuse Surfaces"

$autorunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $autorunKeys) {

    try {
        $values = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
        foreach ($prop in $values.PSObject.Properties) {

            if ($prop.Name -match "^PS") { continue }

            $target = fncLocal_NormalisePath $prop.Value
            if (-not (Test-Path $target)) { continue }

            if (fncLocal_IsWritableByBroadPrincipal $target) {

                fncAddFinding `
                    -TestId $testId `
                    -Id ("AUTORUN_WRITABLE_" + ($prop.Name -replace '[^A-Za-z0-9]','_')) `
                    -Category "Privilege Escalation" `
                    -Title "Writable Autorun Target" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("Writable autorun target: {0}" -f $target) `
                    -Recommendation "Restrict write permissions." `
                    -Exploitation $exploitationText `
                    -Remediation $remediationText
            }
        }
    } catch {}
}

# ================================================================
# HIGH-PRIV WRITABLE BINARIES
# ================================================================
fncSafeSectionHeader "High-Priv Writable Binary Hunt"

$roots = @($env:ProgramFiles,$env:ProgramData) | Where-Object { $_ -and (Test-Path $_) }

foreach ($root in $roots) {

    Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -match "\.(exe|dll|sys)$" } |
    ForEach-Object {

        try {
            $acl = Get-Acl $_.FullName
            if ($acl.Owner -match "SYSTEM|Administrators") {

                if (fncLocal_IsWritableByBroadPrincipal $_.FullName) {

                    fncAddFinding `
                        -TestId $testId `
                        -Id ("HIGHPRIV_WRITABLE_" + (fncShortHashTag $_.FullName)) `
                        -Category "Privilege Escalation" `
                        -Title "High-Priv Binary Writable By Broad Principal" `
                        -Severity "Medium" `
                        -Status "Detected" `
                        -Message ("Writable high-priv binary: {0}" -f $_.FullName) `
                        -Recommendation "Fix ACLs and validate invocation path." `
                        -Exploitation $exploitationText `
                        -Remediation $remediationText
                }
            }
        } catch {}
    }
}

Write-Host ""
fncSafePrintMessage "Service and Autorun abuse enumeration complete." "debug"

}

Export-ModuleMember -Function fncServiceAndAutorunAbuse