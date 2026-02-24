# ================================================================
# Module  : Menu.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncShowMainMenu {

    try { if (fncCommandExists "fncLog") { fncLog "DEBUG" "Entering fncShowMainMenu loop" } } catch {}

    while ($true) {

        if (fncCommandExists "fncRenderHeader") {
            fncRenderHeader
        }

        try { if (fncCommandExists "fncLog") { fncLog "INFO" ("Environment detected: {0}" -f $global:ProberState.EnvProfile) } } catch {}

        fncSafePrintMessage ("Environment detected: {0}" -f $global:ProberState.EnvProfile) "success"    
        fncSafePrintMessage ("RunId: {0}" -f $global:ProberState.RunContext.RunId) "success"

        if (fncCommandExists "fncShowFrameworkStatus") {
            fncShowFrameworkStatus
        }

        if (fncCommandExists "fncRenderDivider") {
            fncRenderDivider
        }

        if (fncCommandExists "fncRenderMenuOption") {

            fncRenderMenuOption "1" ("Browse Tests For Current Environment ({0})" -f $global:ProberState.EnvProfile)
            fncRenderMenuOption "2" "Browse Tests By Environment Type"
            fncRenderMenuOption "3" "Browse All Test Categories"
            fncRenderMenuOption "4" "Search Test"
            fncRenderMenuOption "5" "Show Framework Status"
            fncRenderMenuOption "6" "Show Findings"

            fncPrintMessage "" "plain"
            fncSafeSectionHeader "AD & Cloud Tools"
            fncRenderMenuOption "7" "Active Directory Console"
            fncRenderMenuOption "8" "Azure Console"
            fncPrintMessage "" "plain"
            fncRenderMenuOption "R" "Rescan Tests"
            fncRenderMenuOption "Q" "Quit"

        }
        else {

            Write-Host ("[1] Browse Tests For Current Environment ({0})" -f $global:ProberState.EnvProfile)
            Write-Host "[2] Browse Tests By Environment Type"
            Write-Host "[3] Browse All Test Categories"
            Write-Host "[4] Search Test"
            Write-Host "[5] Show Framework Status"
            Write-Host "[6] Show Findings"
            Write-Host "[7] Active Directory Console"
            Write-Host ""
            Write-Host "[R] Rescan Tests"
            Write-Host "[Q] Quit"
        }

        fncPrintMessage "" "plain"

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        try { if (fncCommandExists "fncLog") { fncLog "INFO" ("Menu selection: {0}" -f $choice) } } catch {}

        switch ($choice.ToUpper()) {

            "1" {
                if (-not (fncCommandExists "fncShowCategoryMenu")) {
                    fncSafePrintMessage "Category browser module missing." "warning"
                    fncSafePause
                    continue
                }

                $scope = $global:ProberState.EnvProfile
                if (-not $scope) { $scope = "All" }

                try { if (fncCommandExists "fncLog") { fncLog "DEBUG" ("Browsing categories with scope: {0}" -f $scope) } } catch {}

                $r = fncShowCategoryMenu -Scope $scope
                if ($r -eq "QUIT") { return }
            }

            "2" {
                if (-not (fncCommandExists "fncSelectEnvironmentScope")) {
                    fncSafePrintMessage "Environment selector module missing." "warning"
                    fncSafePause
                    continue
                }

                $scope = fncSelectEnvironmentScope

                if (-not $scope) {
                    fncSafePrintMessage "No environment selected." "warning"
                    fncSafePause
                    continue
                }

                try { if (fncCommandExists "fncLog") { fncLog "DEBUG" ("Browsing categories with manual scope: {0}" -f $scope) } } catch {}

                $r = fncShowCategoryMenu -Scope $scope
                if ($r -eq "QUIT") { return }
            }

            "3" {
                if (-not (fncCommandExists "fncShowCategoryMenu")) {
                    fncSafePrintMessage "Category browser module missing." "warning"
                    fncSafePause
                    continue
                }

                $r = fncShowCategoryMenu -Scope "All"
                if ($r -eq "QUIT") { return }
            }

            "4" {
                if (-not (fncCommandExists "fncSearchAndRunTest")) {
                    fncSafePrintMessage "Search module missing." "warning"
                    fncSafePause
                    continue
                }

                fncSearchAndRunTest
            }

            "5" {
                if (fncCommandExists "fncShowFrameworkStatus") {
                    fncShowFrameworkStatus
                }
                fncSafePause
            }

            "6" {
                if (fncCommandExists "fncShowFindingsMenu") {
                    fncShowFindingsMenu
                }
                else {
                    fncSafePrintMessage "Findings module missing." "warning"
                    fncSafePause
                }
            }

            "7" {
                if (-not (fncCommandExists "fncShowADContextMenu")) {
                    fncSafePrintMessage "AD Console module missing." "warning"
                    fncSafePause
                    continue
                }

                $r = fncShowADContextMenu
                if ($r -eq "QUIT") { return }
            }

            "R" {
                fncRescanTestModules
                fncSafePause
            }

            "Q" {
                fncSafePrintMessage "Exiting THE Pr0b3r..." "warning"
                try { if (fncCommandExists "fncLog") { fncLog "INFO" "User selected Quit from main menu" } } catch {}
                return
            }

            default {
                fncSafePrintMessage "Invalid menu selection." "warning"
                fncSafePause
            }
        }
    }
}

function fncMain {

    try {

        if (fncCommandExists "fncLog") {
            fncLog "INFO" "Prober start"
            fncLog "DEBUG" ("RunId: {0}" -f $global:ProberState.RunContext.RunId)
        }

        if (fncCommandExists "fncCreateTempDir") {
            try {
                $global:ProberState.TempDir = fncCreateTempDir
                if (fncCommandExists "fncLog") { fncLog "INFO" ("Temp directory set: {0}" -f $global:ProberState.TempDir) }
            } catch {
                try { if (fncCommandExists "fncLog") { fncLogException $_.Exception "Temp directory creation" } } catch {}
            }
        }

        if (fncCommandExists "fncInitFindings") {
            fncInitFindings
            try { if (fncCommandExists "fncLog") { fncLog "DEBUG" "Findings initialised" } } catch {}
        }
        else {
            $global:ProberState.Findings = @()
            try { if (fncCommandExists "fncLog") { fncLog "WARN" "fncInitFindings missing; initialised empty findings array" } } catch {}
        }

        if (fncCommandExists "fncGetEnvProfile") {
            try {
                $global:ProberState.EnvProfile = fncGetEnvProfile
            } catch {
                try { if (fncCommandExists "fncLog") { fncLogException $_.Exception "Environment profile detection" } } catch {}
                $global:ProberState.EnvProfile = "Unknown"
            }
        }

        if (-not (fncCommandExists "fncRegisterTests")) {
            try { if (fncCommandExists "fncLog") { fncLog "ERROR" "fncRegisterTests missing" } } catch {}
            throw "fncRegisterTests missing"
        }

        try { if (fncCommandExists "fncLog") { fncLog "DEBUG" "Registering tests" } } catch {}
        fncRegisterTests
        try { if (fncCommandExists "fncLog") { fncLog "INFO" "Test registration complete" } } catch {}

        fncShowMainMenu
   
        if (fncCommandExists "fncLog") {
            fncLog "INFO" "Prober exit"
        }

    }
    catch {

        fncSafePrintMessage ("Unhandled error: {0}" -f $_.Exception.Message) "error"

        if (fncCommandExists "fncLog") {
            try { fncLogException $_.Exception "fncMain unhandled" } catch {}
        }

        throw
    }
    finally {

        if (fncCommandExists "fncCleanupTempDir") {
            try { if (fncCommandExists "fncLog") { fncLog "DEBUG" "Running temp directory cleanup" } } catch {}
            fncCleanupTempDir
        }
    }
}

Export-ModuleMember -Function @(
    "fncMain",
    "fncShowMainMenu"
)
