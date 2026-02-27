# ================================================================
# Module  : UI.Findings.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncShowFindings {

    $findings = fncSafeArray $global:ProberState.Findings

    if ((fncSafeCount $findings) -eq 0) {
        fncSafePrintMessage "No findings recorded." "warning"
        fncSafePause
        return
    }

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Findings Viewer"
        fncSafeDivider

        fncSafeMenuOption "1" "All"
        fncSafeMenuOption "2" "Critical"
        fncSafeMenuOption "3" "High"
        fncSafeMenuOption "4" "Medium"
        fncSafeMenuOption "5" "Low"
        fncSafeMenuOption "6" "Info"

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select filter"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "1" { fncPrintFindings -SeverityFilter "All" }
            "2" { fncPrintFindings -SeverityFilter "Critical" }
            "3" { fncPrintFindings -SeverityFilter "High" }
            "4" { fncPrintFindings -SeverityFilter "Medium" }
            "5" { fncPrintFindings -SeverityFilter "Low" }
            "6" { fncPrintFindings -SeverityFilter "Info" }

            "B" { return }
            "Q" { return }
        }

        fncSafePause
    }
}

function fncExportFindings {

    $rows = fncSafeArray $global:ProberState.Findings

    if ((fncSafeCount $rows) -eq 0) {
        fncSafePrintMessage "No findings to export." "warning"
        fncSafePause
        return
    }

    try {

        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $Path = Join-Path $PWD ("Prober_Findings_{0}.csv" -f $timestamp)

        $rows |
            Select-Object Id,Category,Title,Severity,Status,Message,Recommendation,Timestamp |
            Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8

        fncSafePrintMessage ("Exported findings to: {0}" -f $Path) "success"

        try { fncLog "INFO" ("Exported findings to CSV: {0} (count: {1})" -f $Path, (fncSafeCount $rows)) } catch {}

    }
    catch {
        fncSafePrintMessage ("Export failed: {0}" -f $_.Exception.Message) "error"
    }

    fncSafePause
}

function fncShowFindingsMenu {

    while ($true) {

        fncSafeRenderHeader
        fncSafeSectionHeader "Findings"
        fncSafeDivider

        fncSafeMenuOption "1" "View Findings"
        fncSafeMenuOption "2" "Export Findings"

        Write-Host ""
        fncSafeBackQuit

        $choice = Read-Host "Select option"
        if ([string]::IsNullOrWhiteSpace($choice)) { continue }

        switch ($choice.ToUpper()) {

            "1" { fncShowFindings }
            "2" { fncExportFindings }
            "B" { return }
            "Q" { return }
        }
    }
}

Export-ModuleMember -Function @(
    "fncShowFindings",
    "fncExportFindings",
    "fncShowFindingsMenu"
)
