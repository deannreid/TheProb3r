# ================================================================
# Module  : Export.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncNormaliseCsvField {
    param(
        [AllowNull()][object]$Value,
        [int]$MaxLen = 4000
    )

    try { fncLog "DEBUG" "fncNormaliseCsvField invoked" } catch {}

    if ($null -eq $Value) { return "" }

    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return "" }

    $s = $s -replace "`r`n|`n|`r", " "
    $s = $s -replace "`t", " "
    $s = $s -replace "\s{2,}", " "
    $s = $s.Trim()

    if ($s.Length -gt $MaxLen) {
        try { fncLog "DEBUG" ("CSV field truncated to {0} chars" -f $MaxLen) } catch {}
        $s = $s.Substring(0, $MaxLen) + "..."
    }

    return $s
}

function fncExportFindingsToCsv {
    param(
        [string]$Path = "",
        [switch]$Force
    )

    try { fncLog "INFO" "fncExportFindingsToCsv invoked" } catch {}

    if ((fncSafeCount $global:ProberState.Findings) -eq 0) {

        try { fncLog "WARN" "CSV export requested but no findings present" } catch {}

        fncPrintMessage "No findings to export." "warning"
        return
    }

    if ([string]::IsNullOrWhiteSpace($Path)) {

        try { fncLog "DEBUG" "No CSV path supplied, generating default export path" } catch {}

        $dir = ""
        try {
            if (Get-Command -Name fncGetScriptDirectory -ErrorAction SilentlyContinue) {
                $dir = fncGetScriptDirectory
            }
        } catch {
            try { fncLogException $_.Exception "fncExportFindingsToCsv directory resolution" } catch {}
            $dir = ""
        }

        if ([string]::IsNullOrWhiteSpace($dir)) { $dir = $PWD.Path }

        $stamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        $Path = Join-Path $dir ("Findings_{0}.csv" -f $stamp)

        try { fncLog "DEBUG" ("Default CSV export path resolved: {0}" -f $Path) } catch {}
    }

    if ((Test-Path -LiteralPath $Path) -and -not $Force) {

        try { fncLog "WARN" ("CSV export prevented due to existing file: {0}" -f $Path) } catch {}

        fncPrintMessage ("CSV already exists: {0}" -f $Path) "warning"
        fncPrintMessage "Provide -Force or choose a different path." "info"
        return
    }

    try { fncLog "DEBUG" ("Building CSV rows from findings (count: {0})" -f (fncSafeCount $global:ProberState.Findings)) } catch {}

    $rows = @()
    foreach ($f in @($global:ProberState.Findings)) {

        $rows += [pscustomobject]@{
            ExportedAt     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Id             = fncNormaliseCsvField ($f.Id)
            Category       = fncNormaliseCsvField ($f.Category)
            Title          = fncNormaliseCsvField ($f.Title)
            Severity       = fncNormaliseCsvField ($f.Severity)
            Status         = fncNormaliseCsvField ($f.Status)
            Message        = fncNormaliseCsvField ($f.Message) 8000
            Recommendation = fncNormaliseCsvField ($f.Recommendation) 8000
            Evidence       = fncNormaliseCsvField ($f.Evidence) 8000
        }
    }

    try {

        fncLog "DEBUG" ("Writing CSV export to disk: {0}" -f $Path)

        $rows | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -Force

        fncPrintMessage ("Findings exported to CSV: {0}" -f $Path) "success"

        try {
            fncLog "INFO" ("Exported findings to CSV: {0} (count: {1})" -f $Path, (fncSafeCount $rows))
        } catch {}

    } catch {

        fncPrintMessage ("Failed to export CSV: {0}" -f $_.Exception.Message) "error"

        try { fncLogException $_.Exception "CSV export" } catch {}
    }
}

Export-ModuleMember -Function @(
    "fncExportFindingsToCsv"
)