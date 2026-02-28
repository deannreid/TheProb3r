# ================================================================
# Script: thePr0b3r.ps1
# Purpose: Runner / entry point for THE Pr0b3r framework
# ================================================================

param(
    [switch]$ShowHelp,
    [switch]$ShowVersion,
    [ValidateSet("silent","info","debug","file")]
    [string]$logger = "info"
)

$global:LoggerMode = $logger.ToLower()
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Resolve Script Root
# ------------------------------------------------------------
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) {
    $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$global:ScriptRoot = $scriptRoot

# ------------------------------------------------------------
# Early Logging Bootstrap
# ------------------------------------------------------------
try {

    $loggingModule = Join-Path $scriptRoot "modules\Logging.psm1"

    if (Test-Path $loggingModule) {
        Import-Module $loggingModule -Force -ErrorAction Stop | Out-Null
    }

} catch {
    Write-Host "CRITICAL: Unable to load Logging module." -ForegroundColor Red
}


# ------------------------------------------------------------
# Bootstrap Runtime State
# ------------------------------------------------------------
function fncBootstrapProberState {

    fncLog "DEBUG" "Entering fncBootstrapProberState"

    if (-not (Get-Variable ProberState -Scope Global -ErrorAction SilentlyContinue)) {

        $global:ProberState = [pscustomobject]@{

            Config = [pscustomobject]@{
                DEBUG         = $false
                ADVANCED_MODE = $false
            }

            Tests      = @()
            Findings   = @()
            TempDir    = $null
            EnvProfile = "Unknown"
            OperatorTelemetry = $null
            _LoadedTestIds = @()

            RunContext = [pscustomobject]@{
                RunId     = [guid]::NewGuid()
                StartTime = Get-Date
                Host      = $env:COMPUTERNAME
                User      = $env:USERNAME
            }
        }

        fncLog "INFO" "Initialised ProberState runtime container"
    }
}

# ------------------------------------------------------------
# Module Loader
# ------------------------------------------------------------
function fncImportLocalModules {

    param([string]$ModulesRoot = "")

    fncLog "INFO" "Starting module import routine"

    if ([string]::IsNullOrWhiteSpace($ModulesRoot)) {
        $ModulesRoot = Join-Path $scriptRoot "modules"
    }

    fncLog "DEBUG" ("Module root resolved to: {0}" -f $ModulesRoot)

    if (-not (Test-Path $ModulesRoot)) {
        fncLog "ERROR" ("Modules folder missing: {0}" -f $ModulesRoot)
        throw "Modules folder not found: $ModulesRoot"
    }

    $required = @(
        "Core.psm1",
        "Output.psm1",
        "Logging.psm1",
        "Findings.psm1",
        "Registry.psm1",
        "UI.Render.psm1",
        "UI.Operator.psm1",
        "UI.Framework.psm1",
        "UI.Browser.psm1",
        "UI.Findings.psm1",
        "Menu.psm1"
    )

    $optional = @(
        "Integrations.NIST.psm1",
        "Integrations.KEV.psm1",
        "Export.HTML.psm1"
    )

    switch ($global:LoggerMode) {
        "silent" { $global:OutputDebug = $false; $global:ConsoleLogLevel = "NONE" }
        "file"   { $global:OutputDebug = $false; $global:ConsoleLogLevel = "ERROR" }
        "info"   { $global:OutputDebug = $false; $global:ConsoleLogLevel = "INFO" }
        "debug"  { $global:OutputDebug = $true;  $global:ConsoleLogLevel = "DEBUG" }
    }

    foreach ($m in $required) {

        $path = Join-Path $ModulesRoot $m

        if (-not (Test-Path $path)) {
            fncLog "ERROR" ("Required module missing: {0}" -f $path)
            throw "Missing required module file: $path"
        }

        fncLog "DEBUG" ("Importing required module: {0}" -f $m)
        Import-Module $path -Force -ErrorAction Stop | Out-Null
        fncLog "INFO" ("Loaded required module: {0}" -f $m)

        if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {
            fncPrintMessage ("Loaded module: {0}" -f $m) "debug"
        }
    }

    foreach ($m in $optional) {

        $path = Join-Path $ModulesRoot $m

        if (-not (Test-Path $path)) {

            fncLog "WARN" ("Optional module not present: {0}" -f $m)

            if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {
                fncPrintMessage ("Optional module not found (skipped): {0}" -f $m) "debug"
            }

            continue
        }

        Import-Module $path -Force -ErrorAction Stop | Out-Null
        fncLog "DEBUG" ("Loaded optional module: {0}" -f $m)

        if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {
            fncPrintMessage ("Loaded optional module: {0}" -f $m) "debug"
        }
    }
}

# ------------------------------------------------------------
# Main Wrapper
# ------------------------------------------------------------
function fncRunMenu {

    param(
        [switch]$ShowHelp,
        [switch]$ShowVersion
    )

    try {

        fncBootstrapProberState
        $runId = $global:ProberState.RunContext.RunId
        $global:LogRoot   = Join-Path $global:ScriptRoot "Logs"
        $global:RunLogDir = Join-Path $global:LogRoot $runId

        New-Item -ItemType Directory -Path $global:RunLogDir -Force | Out-Null

        $global:LogFile = Join-Path $global:RunLogDir "thePr0b3r.log"
        fncImportLocalModules
        
        fncLogBanner "THE Pr0b3r Execution"
        fncLog "INFO" "Runner initialisation starting"
        fncLog "DEBUG" ("RunId: {0}" -f $global:ProberState.RunContext.RunId)

        if (Get-Command fncCheckPowerShellVersion -ErrorAction SilentlyContinue) {
            fncCheckPowerShellVersion
            fncLog "DEBUG" "PowerShell version check executed"
        }

        if (Get-Command fncAdminCheck -ErrorAction SilentlyContinue) {
            fncAdminCheck
            fncLog "DEBUG" "Admin privilege check executed"
        }

        if ($ShowHelp) {

            if (Get-Command fncShowHelp -ErrorAction SilentlyContinue) {
                fncShowHelp
                fncLog "INFO" "Help menu displayed"
                return
            }

            fncLog "ERROR" "ShowHelp requested but fncShowHelp missing"
            throw "ShowHelp requested but fncShowHelp not found."
        }

        if ($ShowVersion) {

            if (Get-Command fncPrintVersion -ErrorAction SilentlyContinue) {
                fncPrintVersion
                fncLog "INFO" "Version information displayed"
                return
            }

            fncLog "ERROR" "ShowVersion requested but fncPrintVersion missing"
            throw "ShowVersion requested but fncPrintVersion not found."
        }

        if (-not (Get-Command fncMain -ErrorAction SilentlyContinue)) {
            fncLog "ERROR" "fncMain entry point not found"
            throw "fncMain not found. Ensure Menu.psm1 exports fncMain."
        }

        fncLog "INFO" "Launching main framework execution"
        fncMain
        fncLog "INFO" "Main framework execution completed"
    }
    catch {

        fncLogException $_.Exception "Runner"

        if (Get-Command fncPrintMessage -ErrorAction SilentlyContinue) {

            fncPrintMessage ("Runner error: {0}" -f $_.Exception.Message) "error"
            fncPrintMessage ("Exception: {0}" -f $_.Exception.ToString()) "debug"
        }
        else {

            Write-Host ("Runner error: {0}" -f $_.Exception.Message) -ForegroundColor Red
            Write-Host $_.Exception.ToString()
        }

        exit 1
    }
}

fncLog "DEBUG" "Script entry point reached"
fncRunMenu -ShowHelp:$ShowHelp -ShowVersion:$ShowVersion
