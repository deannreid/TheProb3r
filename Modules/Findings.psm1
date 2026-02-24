# ================================================================
# Module  : Findings.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncShortHashTag {

    param(
        [Parameter(Mandatory=$true)]
        [string]$Input
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [Text.Encoding]::UTF8.GetBytes($Input)
    $hash = $sha.ComputeHash($bytes)

    $hex = [BitConverter]::ToString($hash).Replace("-","")

    return $hex.Substring(0,5)
}

function fncRemoveFindingsById {
    param([Parameter(Mandatory=$true)][string[]]$Ids)

    try { fncLog "DEBUG" ("Removing findings by Id(s): {0}" -f ($Ids -join ",")) } catch {}

    $findings = fncSafeArray $global:ProberState.Findings
    if ((fncSafeCount $findings) -eq 0) { return }

    $keep = @()

    foreach ($f in $findings) {
        if ($Ids -notcontains (fncSafeString $f.Id)) {
            $keep += $f
        }
    }

    $global:ProberState.Findings = $keep
}

function fncGetSeverityRank {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return 6 }
        "High"     { return 5 }
        "Medium"   { return 4 }
        "Low"      { return 3 }
        "Info"     { return 2 }
        "Good"     { return 1 }
        default    { return 0 }
    }
}

function fncGetSeverityColour {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return "DarkRed" }
        "High"     { return "Red" }
        "Medium"   { return "Yellow" }
        "Low"      { return "Cyan" }
        "Info"     { return "DarkGray" }
        "Good"     { return "Green" }
        default    { return "White" }
    }
}

function fncGetSeveritySymbol {
    param([string]$Severity)

    switch ($Severity) {
        "Critical" { return "[-]" }
        "High"     { return "[!]" }
        "Medium"   { return "[!]" }
        "Low"      { return "[i]" }
        "Info"     { return "[i]" }
        "Good"     { return "[+]" }
        default    { return "[?]" }
    }
}

function fncPrintFindingsSummary {

    try { fncLog "DEBUG" "Printing findings summary" } catch {}

    $all = fncSafeArray $global:ProberState.Findings

    if ((fncSafeCount $all) -eq 0) {

        try { fncPrintMessage "Findings: none yet." "success" }
        catch { Write-Host "Findings: none yet." }

        try { fncLog "INFO" "Findings summary displayed: none present" } catch {}
        return
    }

    $counts = @{
        Critical = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Critical"))
        High     = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "High"))
        Medium   = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Medium"))
        Low      = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Low"))
        Info     = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Info"))
        Good     = fncSafeCount (fncSafeArray ($all | Where-Object Severity -eq "Good"))
    }

    try {

        if (fncCommandExists "fncWriteColour") {

            # Banner colour logic
            $bannerColour = [System.ConsoleColor]::Green
            if ($counts.Critical -gt 0) { $bannerColour = [System.ConsoleColor]::Red }
            elseif ($counts.High -gt 0) { $bannerColour = [System.ConsoleColor]::DarkRed }
            elseif ($counts.Medium -gt 0) { $bannerColour = [System.ConsoleColor]::Yellow }

            fncWriteColour "[!] Findings => " $bannerColour -NoNewLine

            # --- Critical ---
            $cColour = if ($counts.Critical -gt 0) { [System.ConsoleColor]::Red } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Critical:{0} | " -f $counts.Critical) $cColour -NoNewLine

            # --- High ---
            $hColour = if ($counts.High -gt 0) { [System.ConsoleColor]::DarkRed } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("High:{0} | " -f $counts.High) $hColour -NoNewLine

            # --- Medium ---
            $mColour = if ($counts.Medium -gt 0) { [System.ConsoleColor]::Yellow } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Medium:{0} | " -f $counts.Medium) $mColour -NoNewLine

            # --- Low ---
            $lColour = if ($counts.Low -gt 0) { [System.ConsoleColor]::Cyan } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Low:{0} | " -f $counts.Low) $lColour -NoNewLine
            # --- Info ---
            $iColour = if ($counts.Info -gt 0) { [System.ConsoleColor]::White } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Info:{0} |" -f $counts.Info) $iColour -NoNewLine

            # --- Good ---
            $gColour = if ($counts.Good -gt 0) { [System.ConsoleColor]::Green } else { [System.ConsoleColor]::DarkGray }
            fncWriteColour ("Good:{0}" -f $counts.Good) $gColour
        }
        else {

            Write-Host ("Findings => Critical:{0} | High:{1} | Medium:{2} | Low:{3} | Info:{4} | Good:{5}" -f `
                $counts.Critical,$counts.High,$counts.Medium,$counts.Low,$counts.Info,$counts.Good)
        }

        fncLog "INFO" ("Findings summary => C:{0} H:{1} M:{2} L:{3} I:{4} G:{5}" -f `
            $counts.Critical,$counts.High,$counts.Medium,$counts.Low,$counts.Info,$counts.Good)

    }
    catch {
        Write-Host "Findings summary display failed."
    }
}

function fncFormatFinding {
    param([Parameter(Mandatory)][pscustomobject]$Finding)

    try { fncLog "DEBUG" ("Formatting finding: {0}" -f (fncSafeString $Finding.Id)) } catch {}

    $id    = fncSafeString $Finding.Id
    $cat   = fncSafeString $Finding.Category
    $title = fncSafeString $Finding.Title
    $sev   = fncSafeString $Finding.Severity
    $stat  = fncSafeString $Finding.Status
    $msg   = fncSafeString $Finding.Message
    $rec   = fncSafeString $Finding.Recommendation
    $time  = fncSafeString $Finding.Timestamp

    $evid = ""
    if ($Finding.PSObject.Properties.Name -contains "Evidence") {
        $evid = fncSafeString $Finding.Evidence
    }

    if (-not $time) {
        $time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    }

    $lines = @()
    $lines += ("[{0}] {1} | {2} | {3}" -f $sev,$id,$cat,$title)

    if ($stat) { $lines += "Status: $stat" }
    if ($msg)  { $lines += "Message: $msg" }
    if ($rec)  { $lines += "Recommendation: $rec" }
    if ($evid) { $lines += "Evidence: $evid" }

    $lines += "Timestamp: $time"

    return ($lines -join "`n")
}

function fncPrintFindings {

    param(
        [ValidateSet("All","Critical","High","Medium","Low","Info","Good")]
        [string]$SeverityFilter = "All"
    )

    try { fncLog "DEBUG" ("Printing findings with filter: {0}" -f $SeverityFilter) } catch {}

    fncPrintMessage "" "plain"

    $items = fncSafeArray $global:ProberState.Findings
    if ((fncSafeCount $items) -eq 0) {

        try { fncLog "INFO" "No findings available for display" } catch {}

        fncPrintMessage "No findings to display." "info"
        return
    }

    if ($SeverityFilter -ne "All") {
        $items = fncSafeArray ($items | Where-Object Severity -eq $SeverityFilter)
    }

    if ((fncSafeCount $items) -eq 0) {

        try { fncLog "INFO" ("No findings matched filter: {0}" -f $SeverityFilter) } catch {}

        fncPrintMessage ("No findings matched filter: {0}" -f $SeverityFilter) "info"
        return
    }

    $items = fncSafeArray (
        $items | Sort-Object `
            @{ Expression = { fncGetSeverityRank $_.Severity }; Descending = $true },
            Category,
            Title
    )

    try {
        fncPrintSectionHeader ("FINDINGS ({0})" -f $SeverityFilter.ToUpperInvariant())
    }
    catch {
        Write-Host "FINDINGS ($SeverityFilter)"
    }

    foreach ($f in $items) {

        try { fncLog "DEBUG" ("Rendering finding: {0}" -f (fncSafeString $f.Id)) } catch {}

        $severity = fncSafeString $f.Severity
        $colour   = fncGetSeverityColour $severity
        $symbol   = fncGetSeveritySymbol $severity

        $header = "$symbol [$severity] $($f.Id) | $($f.Category) | $($f.Title)"

        if (fncCommandExists "fncWriteColour") {

            fncWriteColour $header $colour
            fncWriteColour ("Status: $($f.Status)") White
            fncWriteColour ("Message: $($f.Message)") White
            fncWriteColour ("Recommendation: $($f.Recommendation)") White

            if ($f.PSObject.Properties.Name -contains "Evidence" -and $f.Evidence) {
                fncWriteColour ("Evidence: $($f.Evidence)") DarkGray
            }

            fncWriteColour ("Timestamp: $($f.Timestamp)") DarkGray
        }
        else {

            Write-Host $header
            Write-Host "Status: $($f.Status)"
            Write-Host "Message: $($f.Message)"
            Write-Host "Recommendation: $($f.Recommendation)"
            Write-Host "Timestamp: $($f.Timestamp)"
        }

        if (fncCommandExists "fncRenderDivider") {
            fncRenderDivider
        }

        fncPrintMessage "" "plain"
    }
}

# ------------------------------------------------------------
# Exported Members
# ------------------------------------------------------------
Export-ModuleMember -Function @(
    "fncRemoveFindingsById",
    "fncPrintFindingsSummary",
    "fncPrintFindings",
    "fncGetSeverityColour",
    "fncGetSeveritySymbol",
    "fncShortHashTag"
)
