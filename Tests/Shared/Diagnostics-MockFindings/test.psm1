# ================================================================
# Test    : Mock Findings Generator
# Purpose : Inject synthetic findings for framework validation
# ================================================================

function fncGenerateMockFindings {

    if ($null -eq $global:ProberState) {
        Write-Host "ProberState not initialised."
        return
    }

    if ($null -eq $global:ProberState.Findings) {
        $global:ProberState.Findings = @()
    }

    $now = Get-Date

    $mockFindings = @(
        @{ Sev="Critical"; Cat="Credentials";  Title="LSASS Protection Disabled" },
        @{ Sev="High";     Cat="Logging";      Title="Script Block Logging Disabled" },
        @{ Sev="Medium";   Cat="Hardening";    Title="UAC Weak Configuration" },
        @{ Sev="Low";      Cat="Network";      Title="LLMNR Enabled" },
        @{ Sev="Info";     Cat="Telemetry";    Title="PowerShell Version Collected" },
        @{ Sev="Good";     Cat="Protection";   Title="Credential Guard Enabled" }
    )

    foreach ($m in $mockFindings) {

        $global:ProberState.Findings += [pscustomobject]@{

            Id = "MOCK-$($m.Sev.ToUpper())-$([guid]::NewGuid().ToString().Substring(0,8))"

            Category = $m.Cat
            Title    = $m.Title
            Severity = $m.Sev
            Status   = "Detected"

            Message = "Synthetic finding generated for testing."
            Recommendation = "No remediation required."

            Timestamp = $now
        }
    }

    try {
        fncPrintMessage "Mock findings injected successfully." "success"
    }
    catch {
        Write-Host "Mock findings injected."
    }
}

Export-ModuleMember -Function fncGenerateMockFindings
