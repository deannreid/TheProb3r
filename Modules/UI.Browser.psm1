# ================================================================
# Module  : UI.Browser.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncGetAllTestsSafe {
    try {
        if ($global:ProberState -and $global:ProberState.Tests) {
            return @(fncSafeArray $global:ProberState.Tests)
        }
    } catch {}
    return @()
}

function fncSafeInvokeTestById {
    param([string]$Id)

    if (fncCommandExists "fncInvokeTestById") {
        fncInvokeTestById -TestId $Id
        return
    }

    fncSafePrintMessage ("Invoke missing: fncInvokeTestById (wanted {0})" -f $Id) "warning"
}

function fncSafeEnvLine {

    if (fncCommandExists "fncRenderEnvironmentLine") {
        fncRenderEnvironmentLine
        return
    }

    $p = "Unknown"
    try { $p = fncSafeString $global:ProberState.EnvProfile } catch {}
    Write-Host ("EnvProfile: {0}" -f $p)
}

function fncSafeFindingsSummary {
    if (fncCommandExists "fncPrintFindingsSummary") {
        fncPrintFindingsSummary
    }
}

function fncSafeRenderTestEntry {

    param(
        [int]$Index,
        [object]$Test
    )

    if (fncCommandExists "fncRenderTestEntry") {
        fncRenderTestEntry -Index $Index -Test $Test
        return
    }

    Write-Host ("[{0}] {1}" -f $Index, (fncSafeString $Test.Name))
}

function fncShowTestsForCategory {

    param(
        [Parameter(Mandatory=$true)][string]$Category,
        [ValidateSet('All','Workstation','Server','Domain','DMZ','Cloud','SaaS','Container','Network','WebApp')]
        [string]$Scope = "All"
    )

    if (-not (fncCommandExists "fncGetTestsByScope")) {
        fncSafePrintMessage "Missing required function: fncGetTestsByScope" "error"
        fncSafePause
        return
    }

    $tests = @()
    try {
        $tests = @(fncSafeArray (fncGetTestsByScope -Scope $Scope -Category $Category))
    }
    catch {
        fncSafePrintMessage ("Failed retrieving tests: {0}" -f $_.Exception.Message) "error"
        fncSafePause
        return
    }

    if ((fncSafeCount $tests) -eq 0) {
        fncSafePrintMessage "No tests in this category." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader (fncSafeString $Category)
        fncSafeEnvLine
        fncSafeFindingsSummary
        fncSafeDivider

        $indexMap = @()
        $i = 1

        foreach ($t in $tests) {
            fncSafeRenderTestEntry $i $t
            $indexMap += $t
            $i++
        }

        Write-Host ""
        fncSafeMenuOption "B" "Back"
        fncSafeMenuOption "Q" "Quit"

        $choice = Read-Host "Select test"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "B" { return }
            "Q" { return "QUIT" }

            default {
                if ($choice -match '^\d+$') {

                    $index = [int]$choice - 1

                    if ($index -ge 0 -and $index -lt (fncSafeCount $indexMap)) {

                        $picked = $indexMap[$index]
                        $id = fncSafeString $picked.Id

                        if (-not [string]::IsNullOrWhiteSpace($id)) {
                            fncSafeInvokeTestById $id
                            fncSafePause
                        }
                    }
                }
            }
        }
    }
}

function fncShowCategoryMenu {

    param(
        [ValidateSet('All','Workstation','Server','Domain','DMZ','Cloud','SaaS','Container','Network','WebApp')]
        [string]$Scope = "All"
    )

    $cats = @()

    if (fncCommandExists "fncGetUniqueCategories") {
        try { $cats = @(fncSafeArray (fncGetUniqueCategories -Scope $Scope)) } catch { $cats = @() }
    }

    if ((fncSafeCount $cats) -eq 0) {

        $tests = fncGetAllTestsSafe

        $cats = @(
            $tests |
            Where-Object {
                $_.Enabled -eq $true -and
                (
                    $Scope -eq "All" -or
                    $_.Scopes -contains "All" -or
                    @(fncSafeArray $_.Scopes) -contains $Scope
                )
            } |
            ForEach-Object {
                $c = fncSafeString $_.Category
                if ([string]::IsNullOrWhiteSpace($c)) { "Uncategorised" }
                else { $c }
            } |
            Sort-Object -Unique
        )
        
    }

    $cats = @($cats | ForEach-Object { fncSafeString $_ })

    if ((fncSafeCount $cats) -eq 0) {
        fncSafePrintMessage "No categories loaded." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Test Categories"
        fncSafeEnvLine
        fncSafeFindingsSummary
        fncSafeDivider

        for ($i = 0; $i -lt (fncSafeCount $cats); $i++) {
            fncSafeMenuOption (fncSafeString ($i + 1)) (fncSafeString $cats[$i])
        }

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select category"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "B" { return }
            "Q" { return "QUIT" }

            default {
                if ($choice -match '^\d+$') {

                    $index = [int]$choice - 1

                    if ($index -ge 0 -and $index -lt (fncSafeCount $cats)) {

                        $r = fncShowTestsForCategory `
                            -Category (fncSafeString $cats[$index]) `
                            -Scope $Scope

                        if ($r -eq "QUIT") { return "QUIT" }
                    }
                }
            }
        }
    }
}

function fncSelectEnvironmentScope {

    while ($true) {

        Write-Host ""
        Write-Host "Select Environment Scope:"
        Write-Host ""
        Write-Host "[1] DMZ"
        Write-Host "[2] Workstation"
        Write-Host "[3] Server"
        Write-Host "[4] Domain"
        Write-Host "[5] Cloud"
        Write-Host "[6] SaaS"
        Write-Host "[7] Container"
        Write-Host "[8] Network"
        Write-Host "[9] WebApp"
        Write-Host "[A] All"
        Write-Host "[Q] Back"
        Write-Host ""

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {
        "1" { return "DMZ" }
        "2" { return "Workstation" }
        "3" { return "Server" }
        "4" { return "Domain" }
        "5" { return "Cloud" }
        "6" { return "SaaS" }
        "7" { return "Container" }
        "8" { return "Network" }
        "9" { return "WebApp" }
        "A" { return "All" }
        "Q" { return $null }
        default { fncSafePrintMessage "Invalid selection." "warning" }
        }
    }
}

function fncSearchAndRunTest {

    $search = Read-Host "Enter test name or ID"
    if ([string]::IsNullOrWhiteSpace($search)) { return }

    $all = fncGetAllTestsSafe

    $tests = @(
        $all | Where-Object {
            (fncSafeString $_.Name -like "*$search*") -or
            (fncSafeString $_.Id   -like "*$search*")
        }
    )

    if ((fncSafeCount $tests) -eq 0) {
        fncSafePrintMessage "No matching tests found." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Search Results"
        fncSafeDivider

        for ($i = 0; $i -lt (fncSafeCount $tests); $i++) {
            fncSafeRenderTestEntry ($i + 1) $tests[$i]
        }

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select test"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        if ($choice.ToUpper() -eq "B") { return }
        if ($choice.ToUpper() -eq "Q") { return }

        if ($choice -match '^\d+$') {

            $index = [int]$choice - 1

            if ($index -ge 0 -and $index -lt (fncSafeCount $tests)) {

                $id = fncSafeString $tests[$index].Id

                if (-not [string]::IsNullOrWhiteSpace($id)) {
                    fncSafeInvokeTestById $id
                    fncSafePause
                }
            }
        }
    }
}

Export-ModuleMember -Function @(
    "fncShowCategoryMenu",
    "fncShowTestsForCategory",
    "fncSearchAndRunTest",
    "fncSelectEnvironmentScope"
)
