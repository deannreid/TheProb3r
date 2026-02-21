# ================================================================
# Module  : UI.Framework.psm1
# ================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncGetRegistryStats {

    $tests = @()

    try {
        if ($global:ProberState -and $global:ProberState.Tests) {
            $tests = fncSafeArray $global:ProberState.Tests
        }
    } catch {}

    return [pscustomobject]@{
        TotalRegistered = fncSafeCount $tests
    }
}

function fncGetModuleLoadSummary {

    $modules = @()

    try {
        $modules = @(Get-Module -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -like "UI.*" -or $_.Name -like "*Prober*"
            })
    } catch {}

    $names = @($modules | Select-Object -ExpandProperty Name -Unique -ErrorAction SilentlyContinue)

    return [pscustomobject]@{
        UniqueModules = fncSafeCount $names
    }
}

function fncGetEnvironmentContext {

    $envProfile = "Unknown"
    $domainJoined = $false

    try {
        if ($global:ProberState -and $global:ProberState.EnvProfile) {
            $envProfile = fncSafeString $global:ProberState.EnvProfile
        }
    } catch {}

    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $domainJoined = [bool]$cs.PartOfDomain
    } catch {}

    return [pscustomobject]@{
        Profile      = $envProfile
        DomainJoined = $domainJoined
    }
}

function fncShowFrameworkStatus {

    $ctx = fncGetEnvironmentContext
    $reg = fncGetRegistryStats
    $mod = fncGetModuleLoadSummary

    if (fncCommandExists "fncPrintMessage") {
        fncPrintMessage "===== THE Pr0b3r Status =====" "info"
    }
    else {
        Write-Host "===== THE Pr0b3r Status ====="
    }

    function fncSafePrintStatus {
        param($label,$value)

        if (fncCommandExists "fncPrintStatus") {
            fncPrintStatus $label $value
        }
        else {
            Write-Host ("  {0,-20}: {1}" -f $label,$value)
        }
    }

    try {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    } catch { $user = "Unknown" }

    fncSafePrintStatus "User" $user
    fncSafePrintStatus "Hostname" $env:COMPUTERNAME
    fncSafePrintStatus "EnvProfile" $ctx.Profile
    fncSafePrintStatus "Modules Loaded" $mod.UniqueModules
    fncSafePrintStatus "Tests Registered" $reg.TotalRegistered

    if (fncCommandExists "fncPrintOperatorRiskBanner") {
        fncPrintOperatorRiskBanner
    }
}

Export-ModuleMember -Function @(
    "fncGetRegistryStats",
    "fncGetModuleLoadSummary",
    "fncGetEnvironmentContext",
    "fncShowFrameworkStatus"
)
