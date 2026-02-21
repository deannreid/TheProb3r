# ================================================================
# Module  : Output.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Variable Banner -Scope Global -ErrorAction SilentlyContinue)) {
$global:Banner = @'
 ________  __                        _______              ______   __         ______            
|        \|  \                      |       \            /      \ |  \       /      \           
 \$$$$$$$$| $$____    ______        | $$$$$$$\  ______  |  $$$$$$\| $$____  |  $$$$$$\  ______  
   | $$   | $$    \  /      \       | $$__/ $$ /      \ | $$$\| $$| $$    \  \$$__| $$ /      \ 
   | $$   | $$$$$$$\|  $$$$$$\      | $$    $$|  $$$$$$\| $$$$\ $$| $$$$$$$\  |     $$|  $$$$$$\
   | $$   | $$  | $$| $$    $$      | $$$$$$$ | $$   \$$| $$\$$\$$| $$  | $$ __\$$$$$\| $$   \$$             2
   | $$   | $$  | $$| $$$$$$$$      | $$      | $$      | $$_\$$$$| $$__/ $$|  \__| $$| $$      
   | $$   | $$  | $$ \$$     \      | $$      | $$       \$$  \$$$| $$    $$ \$$    $$| $$      
    \$$    \$$   \$$  \$$$$$$$       \$$       \$$        \$$$$$$  \$$$$$$$   \$$$$$$  \$$      

                        THE Pr0b3r  ::  {0}
                ----------------------------------------------------------------
                ::          https://github.com/deannreid/The-Prober           ::
                ----------------------------------------------------------------
'@
}

if (-not (Get-Variable CurrentBlurb -Scope Global -ErrorAction SilentlyContinue)) {
    $global:CurrentBlurb = "Operationalising bad decisions... safely."
}

if (-not (Get-Variable OutputDebug -Scope Global -ErrorAction SilentlyContinue)) {
    $global:OutputDebug = $false
}

if (-not (Get-Variable ConsoleLogLevel -Scope Global -ErrorAction SilentlyContinue)) {
    $global:ConsoleLogLevel = "INFO"
}

function fncWriteColour {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Text,
        [Parameter(Mandatory=$true)][System.ConsoleColor]$Colour,
        [switch]$NoNewLine
    )

    try {
        if ($NoNewLine) { Write-Host $Text -ForegroundColor $Colour -NoNewline }
        else { Write-Host $Text -ForegroundColor $Colour }
    } catch {
        if ($NoNewLine) { Write-Host $Text -NoNewline }
        else { Write-Host $Text }
    }
}

function fncColourLine {

    param(
        [string]$Name,
        [string]$Value,
        [bool]$IsRisk
    )

    if (fncCommandExists "fncWriteColour") {

        fncWriteColour ("  - {0,-20}: " -f $Name) ([System.ConsoleColor]::White) -NoNewLine

        if ($IsRisk) {
            fncWriteColour $Value ([System.ConsoleColor]::Red)
        }
        else {
            fncWriteColour $Value ([System.ConsoleColor]::Green)
        }

    }
    else {
        Write-Host ("  - {0,-20}: {1}" -f $Name,$Value)
    }
}

function fncPrintSectionHeader {
    param(
        [Parameter(Mandatory=$true)][string]$Title
    )

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" ("Rendering section header: {0}" -f $Title) } } catch {}

    $safeTitle = ""
    try { $safeTitle = fncSafeString $Title } catch { $safeTitle = "$Title" }

    Write-Host ""

    if (Get-Command fncWriteColour -ErrorAction SilentlyContinue) {

        try {
            fncWriteColour "=========|| " ([System.ConsoleColor]::Blue) -NoNewLine
            fncWriteColour $safeTitle ([System.ConsoleColor]::Red) -NoNewLine
            fncWriteColour " ||=========" ([System.ConsoleColor]::Blue)
        }
        catch {
            Write-Host "=========|| $safeTitle ||========="
        }

    }
    else {
        Write-Host "=========|| $safeTitle ||========="
    }

    Write-Host ""
}

function fncPrintMessage {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyString()][string]$Message,
        [Parameter(Mandatory=$false)][ValidateSet("success","info","warning","error","debug","plain")]
        [string]$Level = "info"
    )

    $logLevelMap = @{
        "success" = "INFO"
        "info"    = "INFO"
        "warning" = "WARN"
        "error"   = "ERROR"
        "debug"   = "DEBUG"
        "plain"   = "INFO"
    }

    $mappedLevel = $logLevelMap[$Level]

    try {
        if (Get-Command fncLog -ErrorAction SilentlyContinue) {
            fncLog $mappedLevel $Message
        }
    } catch {}

    if (-not (fncShouldConsoleLog $mappedLevel)) {
        return
    }

    $prefix = ""
    $colour = [System.ConsoleColor]::White

    switch ($Level) {
        "success" { $prefix = "[+]"; $colour = [System.ConsoleColor]::Green }
        "info"    { $prefix = "[i]"; $colour = [System.ConsoleColor]::Cyan }
        "warning" { $prefix = "[!]"; $colour = [System.ConsoleColor]::Yellow }
        "error"   { $prefix = "[-]"; $colour = [System.ConsoleColor]::Red }
        "debug"   {
            $prefix = "[d]"
            $colour = [System.ConsoleColor]::DarkGray

            $debugOn = $false
            try {
                if ($global:OutputDebug -eq $true) { $debugOn = $true }
                elseif ($null -ne $global:config -and $null -ne $global:config.DEBUG -and $global:config.DEBUG -eq $true) { $debugOn = $true }
            } catch { $debugOn = $false }

            if (-not $debugOn) { return }
        }
        "plain"  { $prefix = ""; $colour = [System.ConsoleColor]::White }
    }

    if ([string]::IsNullOrWhiteSpace($prefix)) {
        fncWriteColour $Message $colour
    } else {
        fncWriteColour ("{0} {1}" -f $prefix, $Message) $colour
    }
}

function fncPrintKey {

    try { if (Get-Command fncLog -ErrorAction SilentlyContinue) { fncLog "DEBUG" "Rendering output key legend" } } catch {}

    try {
        $isAdmin = $false
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        $isAdmin = $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if ($isAdmin) { fncWriteColour "                                  Running as: Administrator" ([System.ConsoleColor]::Green) }
        else { fncWriteColour "                                  Running as: Standard User" ([System.ConsoleColor]::Yellow) }
    } catch {
        fncWriteColour "                                  Running as: Unknown" ([System.ConsoleColor]::DarkGray)
    }

    Write-Host ""
    Write-Host "==================== Output Key ====================" -ForegroundColor Blue

    Write-Host "[!]" -NoNewline -ForegroundColor Red;      Write-Host " Special privilege or misconfiguration"
    Write-Host "[+]" -NoNewline -ForegroundColor Green;    Write-Host " Protection enabled / well configured"
    Write-Host "[~]" -NoNewline -ForegroundColor Cyan;     Write-Host " Active user or object"
    Write-Host "[X]" -NoNewline -ForegroundColor DarkGray; Write-Host " Disabled user or object"
    Write-Host "[>]" -NoNewline -ForegroundColor Yellow;   Write-Host " Link or reference"
    Write-Host "[#]" -NoNewline -ForegroundColor Blue;     Write-Host " Section or title header"

    Write-Host "===================================================="
}

Export-ModuleMember -Function @(
    "fncWriteColour",
    "fncColourLine",
    "fncPrintSectionHeader",
    "fncPrintMessage",
    "fncPrintKey"
)