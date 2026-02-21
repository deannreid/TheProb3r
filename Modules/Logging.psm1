# ================================================================
# Module  : Logging.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Variable LogFile -Scope Global -ErrorAction SilentlyContinue)) {
    # Caller should set this; we fall back to a temp location.
    $global:LogFile = Join-Path $env:TEMP "thePr0b3r.log"
}

if (-not (Get-Variable OutputDebug -Scope Global -ErrorAction SilentlyContinue)) {
    $global:OutputDebug = $false
}

function fncInitLogging {
    param(
        [string]$Path = $global:LogFile
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        $Path = Join-Path $env:TEMP "thePr0b3r.log"
        $global:LogFile = $Path
    }

    try {
        $dir = Split-Path -Parent $Path
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType File -Path $Path -Force | Out-Null
        }
    } catch {
        $fallback = Join-Path $env:TEMP "thePr0b3r.log"
        $global:LogFile = $fallback
        try {
            if (-not (Test-Path -LiteralPath $fallback)) {
                New-Item -ItemType File -Path $fallback -Force | Out-Null
            }
        } catch { }
    }
}

function fncLog {
    param(
        [Parameter(Mandatory=$true)][ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level,

        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message
    )

    # Honour DEBUG toggles
    if ($Level -eq "DEBUG") {
        $debugOn = $false
        try {
            if ($global:OutputDebug -eq $true) { $debugOn = $true }
            elseif ($null -ne $global:config -and $null -ne $global:config.DEBUG -and $global:config.DEBUG -eq $true) { $debugOn = $true }
        } catch { $debugOn = $false }

        if (-not $debugOn) { return }
    }

    try { fncInitLogging | Out-Null } catch { }

    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss.fff")
    $line = "{0} [{1}] {2}" -f $ts, $Level, $Message

    try {
        Add-Content -LiteralPath $global:LogFile -Value $line -Encoding UTF8
    } catch {
    }
}

function fncLogException {
    param(
        [Parameter(Mandatory=$true)][System.Exception]$Exception,
        [string]$Context = ""
    )

    $ctx = ""
    if (-not [string]::IsNullOrWhiteSpace($Context)) { $ctx = " | Context: $Context" }

    fncLog "ERROR" ("Exception: {0}{1}" -f $Exception.Message, $ctx)

    try {
        if ($Exception.StackTrace) {
            fncLog "DEBUG" ("StackTrace: {0}" -f ($Exception.StackTrace -replace "\r?\n"," | "))
        }
    } catch { }
}

function fncLogBanner {
    param([string]$Title = "Run Start")

    try { fncInitLogging | Out-Null } catch { }

    fncLog "INFO" "============================================================"
    fncLog "INFO" ("{0} - {1}" -f $Title, (Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))
    fncLog "INFO" "============================================================"
}

function fncShouldConsoleLog {
    param(
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level
    )

    switch ($global:ConsoleLogLevel) {

        "NONE"  { return $false }

        "ERROR" {
            if ($Level -in @("ERROR","WARN")) { return $true }
            return $false
        }

        "INFO" {
            if ($Level -in @("INFO","WARN","ERROR")) { return $true }
            return $false
        }

        "DEBUG" { return $true }
    }

    return $true
}

Export-ModuleMember -Function @(
    "fncInitLogging",
    "fncLog",
    "fncLogException",
    "fncLogBanner",
    "fncShouldConsoleLog"
)