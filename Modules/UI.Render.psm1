# ================================================================
# Module  : UI.Render.psm1
# ================================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"


function fncRenderHeader {
   # Clear-Host

    try {

        if ($global:Banner) {
            if (fncCommandExists "fncWriteColour") {
                fncWriteColour ($global:Banner -f (fncSafeString $global:CurrentBlurb)) ([System.ConsoleColor]::DarkRed)
            }
            else {
                Write-Host ($global:Banner -f (fncSafeString $global:CurrentBlurb))
            }
        }

        if (fncCommandExists "fncPrintKey") {
            fncPrintKey
        }

    }
    catch {
        Write-Host "Header rendering failed."
    }

    fncPrintMessage "" "plain"
}

function fncPrintStatus {

    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter()][object]$Value
    )

    $Value = fncSafeString $Value

    if (fncCommandExists "fncWriteColour") {
        fncWriteColour ("  {0,-20}: " -f $Label) ([System.ConsoleColor]::White) -NoNewLine
        fncWriteColour $Value ([System.ConsoleColor]::Cyan)
    }
    else {
        Write-Host ("  {0,-20}: {1}" -f $Label, $Value)
    }
}

function fncRenderSectionHeader {
    param([Parameter(Mandatory)][string]$Title)

    if (fncCommandExists "fncWriteColour") {
        fncWriteColour ("==================== {0} ====================" -f $Title) ([System.ConsoleColor]::Cyan)
    }
    else {
        Write-Host ("==================== {0} ====================" -f $Title)
    }
}

function fncRenderEnvironmentLine {

    $envProfile = "Unknown"

    try {
        if ($global:ProberState -and $global:ProberState.EnvProfile) {
            $envProfile = fncSafeString $global:ProberState.EnvProfile
        }
    }
    catch {}

    if (fncCommandExists "fncPrintMessage") {
        fncPrintMessage ("Environment Profile: {0}" -f $envProfile) "info"
    }
    else {
        Write-Host ("Environment Profile: {0}" -f $envProfile)
    }
}

function fncRenderDivider {
    Write-Host "==========================================="
}

function fncRenderMenuOption {
    param(
        [string]$Key,
        [string]$Label
    )

    Write-Host ("[{0}] {1}" -f (fncSafeString $Key), (fncSafeString $Label))
}

function fncRenderBackQuit {

    Write-Host "[B] Back"
    Write-Host "[Q] Quit"
}

function fncRenderPause {

    fncPrintMessage "" "plain"
    try { Read-Host "Press Enter to continue" | Out-Null }
    catch {}
}

function fncRenderTestCategoryHeader {
    param([string]$Category)

    $Category = fncSafeString $Category

    if (fncCommandExists "fncWriteColour") {
        fncWriteColour ("--- {0} ---" -f $Category) ([System.ConsoleColor]::Blue)
    }
    else {
        Write-Host ("--- {0} ---" -f $Category)
    }
}

function fncRenderTestEntry {

    param(
        [int]$Index,
        [object]$Test
    )

    $name = ""
    $requiresAdmin = $false

    try {

        $name = "{0}" -f $Test.Name

        if ($Test -and $Test.PSObject.Properties.Name -contains "RequiresAdmin") {
            $requiresAdmin = [bool]$Test.RequiresAdmin
        }

    }
    catch {}

    if ($requiresAdmin) {

        fncWriteColour ("[{0}] {1} " -f $Index, $name) White -NoNewLine
        fncWriteColour "[!]" Red

    }
    else {

        Write-Host ("[{0}] {1}" -f $Index, $name)

    }
}

Export-ModuleMember -Function @(
    "fncRenderHeader",
    "fncPrintStatus",
    "fncRenderSectionHeader",
    "fncRenderEnvironmentLine",
    "fncRenderDivider",
    "fncRenderMenuOption",
    "fncRenderBackQuit",
    "fncRenderPause",
    "fncRenderTestCategoryHeader",
    "fncRenderTestEntry"
)
