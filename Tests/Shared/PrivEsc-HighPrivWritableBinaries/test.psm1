function fncInvokeParallel {

    param(
        [Parameter(Mandatory)]
        [array]$InputObject,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [int]$Throttle = 4
    )

    fncPrintMessage ("Initialising parallel runspace pool (Throttle={0}, Items={1})" -f $Throttle,($InputObject.Count)) "debug"

    $pool = [runspacefactory]::CreateRunspacePool(1, $Throttle)
    $pool.Open()

    $jobs = @()

    foreach ($item in $InputObject) {

        fncPrintMessage ("Queueing parallel job for root: {0}" -f $item) "debug"

        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool

        $ps.AddScript($ScriptBlock).AddArgument($item) | Out-Null

        $jobs += [pscustomobject]@{
            Pipe   = $ps
            Handle = $ps.BeginInvoke()
        }
    }

    $results = @()

    foreach ($job in $jobs) {
        $results += $job.Pipe.EndInvoke($job.Handle)
        $job.Pipe.Dispose()
    }

    $pool.Close()
    $pool.Dispose()

    fncPrintMessage "Parallel execution complete." "debug"

    return $results
}


# ================================================================
# Function: fncGetHighPrivWritableBinaries
# Purpose : Find high-priv owned binaries writable by current user
# Notes   : PS5 compatible threaded scanner using runspace pool
# ================================================================
function fncGetHighPrivWritableBinaries {

    fncPrintMessage "Scanning filesystem for SYSTEM/Administrators-owned binaries writable by current user..." "info"
    fncPrintMessage "Initialising high-priv writable binary scan." "debug"
    Write-Host ""

    $currentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $currentIdentity) {
        fncPrintMessage "Unable to obtain current identity." "warning"
        fncPrintMessage "WindowsIdentity::GetCurrent() returned null." "debug"
        return
    }

    $currentUser = $currentIdentity.Name
    fncPrintMessage ("Current identity: {0}" -f $currentUser) "debug"

    # ----------------------------------------------------------
    # Interesting roots
    # ----------------------------------------------------------
    $interestingRoots = @(
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData,
        (Join-Path $env:USERPROFILE "AppData")
    ) | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) }

    fncPrintMessage ("Resolved interesting roots: {0}" -f ($interestingRoots -join "; ")) "debug"

    if (-not $interestingRoots) {

        fncPrintMessage "No interesting root paths found." "warning"
        fncPrintMessage "Root resolution returned empty set." "debug"

        fncAddFinding `
            -Id "HIGHPRIV_WRITABLE_NO_ROOTS" `
            -Category "Privilege Escalation" `
            -Title "No Filesystem Roots Available To Scan" `
            -Severity "Low" `
            -Status "Unknown" `
            -Message "No valid Program Files / ProgramData / AppData roots were found." `
            -Recommendation "Verify environment variables and filesystem access."

        return
    }

    $interestingExtensions = @(".exe",".dll",".sys",".bat",".cmd",".ps1")

    fncPrintMessage ("Scanning roots (threaded): {0}" -f ($interestingRoots -join "; ")) "info"
    fncPrintMessage ("Interesting extensions: {0}" -f ($interestingExtensions -join ", ")) "debug"
    Write-Host ""

    # ----------------------------------------------------------
    # Parallel Root Scan
    # ----------------------------------------------------------
    $allResults = fncInvokeParallel -InputObject $interestingRoots -Throttle 4 -ScriptBlock {

        param($root)

        $localHits = @()
        $localCount = 0
        $interestingExtensions = @(".exe",".dll",".sys",".bat",".cmd",".ps1")

        function Test-Modify {
            param($Path)
            try {
                $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
                $current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = New-Object System.Security.Principal.WindowsPrincipal($current)

                foreach ($ace in $acl.Access) {

                    if ($principal.IsInRole($ace.IdentityReference)) {

                        if ($ace.FileSystemRights.ToString() -match "Write|Modify|FullControl") {
                            return $true
                        }
                    }
                }
            } catch {}

            return $false
        }

        try {

            Get-ChildItem -Path $root -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {

                $file = $_
                $localCount++

                try {

                    $ext = [System.IO.Path]::GetExtension($file.FullName)
                    if (-not $ext) { return }

                    if ($interestingExtensions -notcontains $ext.ToLowerInvariant()) { return }

                    $acl = Get-Acl -LiteralPath $file.FullName -ErrorAction SilentlyContinue
                    if (-not $acl) { return }

                    $owner = $acl.Owner
                    if ($owner -notmatch "SYSTEM|Administrators") { return }

                    $fileWritable = Test-Modify $file.FullName

                    if (-not $fileWritable) {

                        $dirPath = Split-Path $file.FullName -Parent
                        if (-not (Test-Modify $dirPath)) { return }

                        $writableWhere = "directory"
                    }
                    else {
                        $writableWhere = "file"
                    }

                    $localHits += [PSCustomObject]@{
                        Path        = $file.FullName
                        Owner       = $owner
                        WritableVia = $writableWhere
                        RootScanned = $root
                    }

                } catch {}
            }

        } catch {}

        return [PSCustomObject]@{
            Hits  = $localHits
            Count = $localCount
        }
    }

    # ----------------------------------------------------------
    # Aggregate Results
    # ----------------------------------------------------------
    $hits = @()
    $scannedCount = 0

    foreach ($r in $allResults) {

        if ($r.Hits) {
            $hits += $r.Hits
        }

        $scannedCount += $r.Count
    }

    Write-Host ""
    fncPrintMessage ("Filesystem scan completed. Files inspected: $scannedCount") "info"
    fncPrintMessage ("Total high-priv writable hits: {0}" -f $hits.Count) "debug"

    # ----------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------
    if (-not $hits) {

        fncPrintMessage "No high-priv writable binaries detected." "success"

        fncAddFinding `
            -Id "HIGHPRIV_WRITABLE_NONE" `
            -Category "Privilege Escalation" `
            -Title "No High-Priv Writable Binaries Found" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No high-priv owned binaries writable by current user." `
            -Recommendation "No action required."

        return
    }

    fncPrintSectionHeader "High-Priv Writable Binaries"

    foreach ($h in $hits) {

        $msg = "High-priv binary '$($h.Path)' (Owner=$($h.Owner)) writable by $currentUser via $($h.WritableVia)."

        Write-Host ("[!] Potential priv-esc surface: $msg") -ForegroundColor Red

        $findingId = "HIGHPRIV_WRITABLE_" + (
            [Convert]::ToBase64String(
                [Text.Encoding]::UTF8.GetBytes($h.Path)
            ) -replace '[^A-Za-z0-9]',''
        )

        fncAddFinding `
            -Id $findingId `
            -Category "Privilege Escalation" `
            -Title "High-Priv Binary Writable By Current User" `
            -Severity "Medium" `
            -Status "Detected" `
            -Message $msg `
            -Recommendation "Fix ACLs and understand what loads this binary."

        Write-Host ("Path       : $($h.Path)")
        Write-Host ("Owner      : $($h.Owner)")
        Write-Host ("WritableVia: $($h.WritableVia)")
        Write-Host ("Root       : $($h.RootScanned)")
        Write-Host "-----------------------------------------"
    }

    fncPrintMessage ("Found $($hits.Count) potential privilege escalation surfaces.") "warning"
    fncPrintMessage "High-priv writable binary scan complete." "debug"
}

Export-ModuleMember -Function fncGetHighPrivWritableBinaries
