# ================================================================
# Module  : Core.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Ensure ProberState Exists
# ------------------------------------------------------------
if (-not (Get-Variable ProberState -Scope Global -ErrorAction SilentlyContinue)) {

    fncLog "DEBUG" "Core bootstrap creating minimal ProberState"

    $global:ProberState = [pscustomobject]@{
        Config = [pscustomobject]@{
            DEBUG         = $false
            ADVANCED_MODE = $false
        }

        Tests             = @()
        Findings          = @()
        TempDir           = $null
        EnvProfile        = "Unknown"
        OperatorTelemetry = $null
        _LoadedTestIds = @()


        RunContext = [pscustomobject]@{
            RunId     = [guid]::NewGuid()
            StartTime = Get-Date
            Host      = $env:COMPUTERNAME
            User      = $env:USERNAME
        }
    }

    fncLog "INFO" "Core created minimal ProberState container"
}

# ------------------------------------------------------------
# Ensure Required Properties Exist
# ------------------------------------------------------------
$requiredProps = @(
    @{ Name="Tests";             Value=@() },
    @{ Name="Findings";          Value=@() },
    @{ Name="TempDir";           Value=$null },
    @{ Name="EnvProfile";        Value="Unknown" },
    @{ Name="OperatorTelemetry"; Value=$null },
    @{ Name="_LoadedTestIds"; Value=@() }

)

foreach ($p in $requiredProps) {
    if ($global:ProberState.PSObject.Properties.Name -notcontains $p.Name) {

        fncLog "DEBUG" ("Core adding missing ProberState property: {0}" -f $p.Name)

        $global:ProberState | Add-Member -MemberType NoteProperty -Name $p.Name -Value $p.Value
    }
}

# ------------------------------------------------------------
# Config alias
# ------------------------------------------------------------
if (-not (Get-Variable config -Scope Global -ErrorAction SilentlyContinue)) {

    $global:config = $global:ProberState.Config
    fncLog "DEBUG" "Core initialised global config alias"
}

# Cosmetic globals
if (-not (Get-Variable CurrentBlurb -Scope Global -ErrorAction SilentlyContinue)) {

    $global:CurrentBlurb = "Enumerating wisdom"
    fncLog "DEBUG" "Core initialised default blurb"
}

function fncGetScriptDirectory {

    fncLog "DEBUG" "fncGetScriptDirectory invoked"

    try {
        if ($PSScriptRoot) { return $PSScriptRoot }
        return (Split-Path -Parent $MyInvocation.MyCommand.Path)
    }
    catch {
        fncLogException $_.Exception "fncGetScriptDirectory"
        return (Get-Location).Path
    }
}

function fncInitProberState {

    fncLog "DEBUG" "fncInitProberState invoked"

    if (Get-Variable ProberState -Scope Global -ErrorAction SilentlyContinue) {
        fncLog "DEBUG" "ProberState already exists - skipping full init"
        return
    }

    $global:ProberState = [pscustomobject]@{
        Config = [pscustomobject]@{
            DEBUG         = $false
            ADVANCED_MODE = $false
        }

        Tests             = @()
        Findings          = @()
        TempDir           = $null
        EnvProfile        = "Unknown"
        OperatorTelemetry = $null
        _LoadedTestIds = @()


        RunContext = [pscustomobject]@{
            RunId     = [guid]::NewGuid()
            StartTime = Get-Date
            Host      = $env:COMPUTERNAME
            User      = $env:USERNAME
        }
    }

    fncLog "INFO" "ProberState fully initialised via fncInitProberState"
}

function fncIsAdmin {

    fncLog "DEBUG" "Checking administrative privileges"

    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        fncLogException $_.Exception "fncIsAdmin"
        return $false
    }
}

function fncCreateTempDir {

    fncLog "DEBUG" "fncCreateTempDir invoked"

    try {
        if ($global:ProberState.TempDir -and (Test-Path $global:ProberState.TempDir)) {
            fncLog "DEBUG" ("Reusing existing temp directory: {0}" -f $global:ProberState.TempDir)
            return $global:ProberState.TempDir
        }
    }
    catch {
        fncLogException $_.Exception "fncCreateTempDir existing temp check"
    }

    if (-not $global:RunLogDir) {
        throw "RunLogDir not initialised by runner."
    }

    $path = Join-Path $global:RunLogDir "Temp"

    try {
        New-Item -ItemType Directory -Path $path -Force | Out-Null
        $global:ProberState.TempDir = $path

        fncLog "INFO" ("Created temp directory: {0}" -f $path)

        return $path
    }
    catch {
        fncLogException $_.Exception "fncCreateTempDir directory creation"
        return $null
    }
}

function fncCleanupTempDir {

    fncLog "DEBUG" "fncCleanupTempDir invoked"

    try {
        if ($global:ProberState.TempDir -and (Test-Path $global:ProberState.TempDir)) {

            fncLog "DEBUG" ("Removing temp directory: {0}" -f $global:ProberState.TempDir)

            Remove-Item $global:ProberState.TempDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        fncLogException $_.Exception "fncCleanupTempDir"
    }

    $global:ProberState.TempDir = $null
}

function fncGetEnvProfile {

    fncLog "DEBUG" "fncGetEnvProfile invoked"

    try {

        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

        $isServer = $false
        if ($os -and $os.Caption -match "(?i)\bserver\b") { $isServer = $true }

        $isDC = $false
        if ($cs -and $cs.DomainRole -ge 4) { $isDC = $true }

        if ($isDC) {
            fncLog "DEBUG" "Environment profile detected as Domain Controller"
            return "Domain"
        }

        if ($isServer) {
            fncLog "DEBUG" "Environment profile detected as Server"
            return "Server"
        }

        fncLog "DEBUG" "Environment profile detected as Workstation"
        return "Workstation"
    }
    catch {
        fncLogException $_.Exception "fncGetEnvProfile"
        return "Unknown"
    }
}

# ------------------------------------------------------------
# Function: fncAskYesNo
# ------------------------------------------------------------
function fncAskYesNo {
    param(
        [Parameter(Mandatory=$true)][string]$Question,
        [ValidateSet("Y","N")][string]$Default = "N"
    )

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" ("Prompt issued: {0}" -f $Question) } } catch {}

    $defTxt = if ($Default -eq "Y") { "Y/n" } else { "y/N" }

    while ($true) {
        $ans = Read-Host ("{0} ({1})" -f $Question, $defTxt)

        if ([string]::IsNullOrWhiteSpace($ans)) {
            return ($Default -eq "Y")
        }

        switch ($ans.Trim().ToLower()) {
            "y"   { return $true }
            "yes" { return $true }
            "n"   { return $false }
            "no"  { return $false }
            default { fncPrintMessage "Please enter Y or N." "warning" }
        }
    }
}

# ------------------------------------------------------------
# Function: fncPause
# ------------------------------------------------------------
function fncPause {
    param([string]$Message = "Press Enter to continue")

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" "Pause invoked" } } catch {}

    Read-Host $Message | Out-Null
}

function fncTryGetRegistryValue {

    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Name,
        $Default = $null
    )

    fncLog "DEBUG" ("Registry lookup requested: {0} -> {1}" -f $Path,$Name)

    try {

        if (-not (Test-Path $Path)) { return $Default }

        $item = Get-ItemProperty $Path -ErrorAction Stop
        if ($null -eq $item) { return $Default }

        if ($item.PSObject.Properties.Name -notcontains $Name) {
            return $Default
        }

        return $item.$Name
    }
    catch {
        fncLogException $_.Exception "fncTryGetRegistryValue"
        return $Default
    }
}

function fncInitFindings {

    fncLog "DEBUG" "Initialising findings container"
    $global:ProberState.Findings = @()
}

function fncAddFinding {

    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [string]$Category = "Uncategorised",
        [string]$Title = "",
        [ValidateSet("Good","Info","Low","Medium","High","Critical")]
        [string]$Severity = "Info",
        [string]$Status = "",
        [string]$Message = "",
        [string]$Recommendation = ""
    )

    fncLog "DEBUG" ("Adding finding: {0} ({1})" -f $Id,$Severity)

    if (-not $global:ProberState.Findings) {
        $global:ProberState.Findings = @()
    }

    $keep = @()
    foreach ($f in $global:ProberState.Findings) {
        if ($f.Id -ne $Id) { $keep += $f }
    }

    $global:ProberState.Findings = $keep

    $global:ProberState.Findings += [pscustomobject]@{
        Id             = $Id
        Category       = $Category
        Title          = $Title
        Severity       = $Severity
        Status         = $Status
        Message        = $Message
        Recommendation = $Recommendation
        Timestamp      = Get-Date
    }
}

function fncRegisterConsoleBreakHandler {

    param([scriptblock]$OnBreak = {})

    fncLog "DEBUG" "Registering console break handler"

    try {
        Unregister-Event ConsoleBreak -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    try {
        Register-EngineEvent ConsoleBreak -SupportEvent -Action {
            try { & $using:OnBreak } catch {}
            try { $event.Sender.Cancel = $true } catch {}
        } | Out-Null
    } catch {
        fncLogException $_.Exception "fncRegisterConsoleBreakHandler"
    }
}

function fncSafeArray {
    param($Value)

    if ($null -eq $Value) { return @() }

    return @($Value)
}

function fncSafeCount {

    param($Value)

    if ($null -eq $Value) { return 0 }

    try {
        return @($Value | Where-Object { $_ -ne $null }).Count
    }
    catch {
        return 0
    }
}

function fncSafeString { 
    param($Value) 
    if ($null -eq $Value) { 
        return "" 
    } return [string]$Value 
}

function fncCommandExists {
    param([Parameter(Mandatory=$true)][string]$Name)
    return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function fncSafePrintMessage {
    param([string]$Msg,[string]$Level="info")

    if (fncCommandExists "fncPrintMessage") {
        fncPrintMessage $Msg $Level
        return
    }
    Write-Host $Msg
}

function fncSafePause {
    if (fncCommandExists "fncRenderPause") { fncRenderPause; return }
    Write-Host ""
    Read-Host "Press Enter to continue" | Out-Null
}

function fncSafeRenderHeader {
    if (fncCommandExists "fncRenderHeader") { fncRenderHeader; return }
    #Clear-Host
    Write-Host ""
}

function fncSafeSectionHeader {
    param([string]$Title)

    if (fncCommandExists "fncRenderSectionHeader") {
        fncRenderSectionHeader -Title $Title
        return
    }

    Write-Host ("==== {0} ====" -f $Title)
}

function fncSafeDivider {
    if (fncCommandExists "fncRenderDivider") { fncRenderDivider; return }
    Write-Host "==========================================="
}

function fncSafeMenuOption {
    param([string]$Key,[string]$Label)

    if (fncCommandExists "fncRenderMenuOption") {
        fncRenderMenuOption -Key $Key -Label $Label
        return
    }

    Write-Host ("[{0}] {1}" -f $Key,$Label)
}

function fncSafeBackQuit {
    if (fncCommandExists "fncRenderBackQuit") {
        fncRenderBackQuit
        return
    }

    Write-Host "[B] Back"
    Write-Host "[Q] Quit"
}

Export-ModuleMember -Function @(
    "fncGetScriptDirectory",
    "fncInitProberState",
    "fncIsAdmin",
    "fncCreateTempDir",
    "fncCleanupTempDir",
    "fncGetEnvProfile",
    "fncAskYesNo",
    "fncPause",
    "fncTryGetRegistryValue",
    "fncInitFindings",
    "fncAddFinding",
    "fncRegisterConsoleBreakHandler",
    "fncSafeCount",
    "fncSafeArray",
    "fncSafeString",
    "fncCommandExists",
    "fncSafePrintMessage",
    "fncSafePause",
    "fncSafeRenderHeader",
    "fncSafeSectionHeader",
    "fncSafeDivider",
    "fncSafeMenuOption",
    "fncSafeBackQuit"
)
