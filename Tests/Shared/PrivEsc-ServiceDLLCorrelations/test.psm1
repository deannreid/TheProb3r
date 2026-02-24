# ================================================================
# Function: fncGetPrivEscServiceAndDllCorrelations
# Purpose : Correlate service dirs, PATH search order, and ServiceDll
# Notes   : Token-aware ACL evaluation + heuristic scoring + ratings
# ================================================================
function fncGetPrivEscServiceAndDllCorrelations {

    fncPrintMessage "Correlating service directories, PATH search-order, and ServiceDll loads for priv-esc hints..." "info"
    fncPrintMessage "" "plain"

    # ==========================================================
    # Helpers
    # ==========================================================
    function fncGetTokenSids {
        try {
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $sids = New-Object System.Collections.Generic.HashSet[string]
            if ($id.User) { [void]$sids.Add($id.User.Value) }
            foreach ($g in $id.Groups) {
                try { [void]$sids.Add($g.Value) } catch {}
            }
            return $sids
        } catch { return $null }
    }

    function fncGetOwnerString {
        param([string]$Path)
        try {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
            if ($acl -and $acl.Owner) { return [string]$acl.Owner }
        } catch {}
        return ""
    }

    function fncIsHighPrivOwner {
        param([string]$OwnerString)
        if (-not $OwnerString) { return $false }

        return (
            $OwnerString -match "SYSTEM" -or
            $OwnerString -match "TrustedInstaller" -or
            $OwnerString -match "Administrators" -or
            $OwnerString -match "NT SERVICE\\TrustedInstaller"
        )
    }

    function fncIsSuspiciousPath {
        param([string]$Path)

        if (-not $Path) { return $false }
        $p = $Path.ToLowerInvariant()

        return (
            $p -like "*\appdata\*" -or
            $p -like "*\temp\*" -or
            $p -like "*\tmp\*" -or
            $p -like "*\programdata\*" -or
            $p -like "*\users\public\*" -or
            $p -like "*\downloads\*"
        )
    }

    function fncIsLOLBINChain {
        param([string]$CmdLine)

        if (-not $CmdLine) { return $false }
        $c = $CmdLine.ToLowerInvariant()

        return (
            $c -match "\bpowershell(\.exe)?\b" -or
            $c -match "\bpwsh(\.exe)?\b" -or
            $c -match "\bcmd(\.exe)?\b\s*/c" -or
            $c -match "\bwscript(\.exe)?\b" -or
            $c -match "\bcscript(\.exe)?\b" -or
            $c -match "\bmshta(\.exe)?\b" -or
            $c -match "\brundll32(\.exe)?\b" -or
            $c -match "\bregsvr32(\.exe)?\b" -or
            $c -match "\binstallutil(\.exe)?\b"
        )
    }

    function fncGetExecutableFromCommandLine {
        param([string]$CommandLine)

        if (-not $CommandLine) { return $null }
        $cmd = $CommandLine.Trim()

        if ($cmd -match '^\s*"(.*?)"') { return $matches[1] }
        $first = $cmd.Split(" ")[0]
        return $first
    }

    function fncResolvePathSafe {
        param([string]$RawPath)

        if (-not $RawPath) { return $null }

        try {
            $p = $RawPath.Trim()
            $p = $p.Trim('"')
            $p = [Environment]::ExpandEnvironmentVariables($p)

            # Normalise trailing slashes
            try { $p = $p.TrimEnd("\") } catch {}

            if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
                return (Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).FullName
            }
        } catch {}

        return $null
    }

    function fncTokenCanWritePath {
        param(
            [string]$Path,
            [System.Collections.Generic.HashSet[string]]$TokenSids
        )

        if (-not $Path -or -not $TokenSids) { return $false }

        try {
            $acl = Get-Acl -LiteralPath $Path -ErrorAction SilentlyContinue
            if (-not $acl) { return $false }

            foreach ($ace in $acl.Access) {

                if (-not $ace) { continue }
                if ($ace.AccessControlType -ne "Allow") { continue }

                $sid = $null
                try {
                    $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                } catch { continue }

                if (-not $TokenSids.Contains($sid)) { continue }

                $rights = [string]$ace.FileSystemRights

                if ($rights -match "FullControl" -or $rights -match "Modify" -or $rights -match "Write") {
                    return $true
                }

                if ($rights -match "WriteData" -or $rights -match "CreateFiles" -or $rights -match "AppendData") {
                    return $true
                }
            }
        } catch {}

        return $false
    }

    function fncGetOffsecContext {

        param(
            [string]$SurfaceType,
            [string]$StartName,
            [bool]$BeforeSystem32
        )
    
        $trigger = "Manual Trigger"
        $impact  = "User Context"
        $effort  = "Medium"
        $stealth = "Moderate"
    
        switch ($SurfaceType) {
    
            "ServiceBinary" {
                $trigger = "Restart Service"
    
                if ($StartName -match "LocalSystem") {
                    $impact = "Instant SYSTEM"
                    $effort = "Low"
                    $stealth = "Low"
                }
                elseif ($StartName -match "LocalService|NetworkService") {
                    $impact = "Service Account Privilege"
                    $effort = "Low"
                    $stealth = "Low"
                }
            }
    
            "ServiceDir" {
                $trigger = "DLL Load via Service Restart"
                $impact  = "Service Context"
                $effort  = "Medium"
                $stealth = "High"
            }
    
            "ServiceDll" {
                $trigger = "Service Restart"
                $impact  = "Service Context"
                $effort  = "Low"
                $stealth = "Low"
            }
    
            "PathDir" {
                $trigger = "Binary Execution via PATH"
    
                if ($BeforeSystem32) {
                    $impact  = "Binary Hijack Potential"
                    $effort  = "Low"
                    $stealth = "Very High"
                }
            }
        }
    
        return @{
            Trigger = $trigger
            Impact  = $impact
            Effort  = $effort
            Stealth = $stealth
        }
    }
    
    function fncScoreSurface {
        param(
            [string]$SurfaceType,         # ServiceDir | ServiceBinary | PathDir | ServiceDll
            [bool]$IsWritableFile,
            [bool]$IsWritableDir,
            [bool]$IsHighPrivOwner,
            [bool]$IsSuspiciousPath,
            [bool]$IsBeforeSystem32,
            [string]$ServiceStartName,
            [bool]$IsLOLBIN
        )

        $score = 0

        if ($IsWritableFile) { $score += 60 }
        if ($IsWritableDir)  { $score += 40 }
        if ($IsHighPrivOwner) { $score += 15 }
        if ($IsSuspiciousPath) { $score += 20 }
        if ($IsBeforeSystem32) { $score += 25 }
        if ($IsLOLBIN) { $score += 15 }

        if ($ServiceStartName) {
            if ($ServiceStartName -match "LocalSystem") { $score += 25 }
            elseif ($ServiceStartName -match "LocalService|NetworkService") { $score += 10 }
        }

        switch ($SurfaceType) {
            "ServiceBinary" { $score += 10 }
            "ServiceDir"    { $score += 5 }
            "ServiceDll"    { $score += 10 }
            "PathDir"       { $score += 0 }
        }

        if ($score -gt 100) { $score = 100 }
        return $score
    }

    function fncScoreToSeverityAndConfidence {
        param([int]$Score)

        $severity = "Low"
        $confidence = "Low"

        if ($Score -ge 85) { $severity = "Critical"; $confidence = "High" }
        elseif ($Score -ge 70) { $severity = "High"; $confidence = "High" }
        elseif ($Score -ge 50) { $severity = "Medium"; $confidence = "Medium" }
        elseif ($Score -ge 30) { $severity = "Low"; $confidence = "Medium" }
        else { $severity = "Info"; $confidence = "Low" }

        return @{ Severity = $severity; Confidence = $confidence }
    }

    function fncPrintSurface {
        param(
            [string]$Header,
            [array]$Items
        )
    
        fncPrintSectionHeader $Header
    
        if (-not $Items -or $Items.Count -eq 0) {
            fncPrintMessage "None detected." "success"
            fncPrintMessage "" "plain"
            return
        }
    
        foreach ($i in $Items) {
    
            $colour = fncGetSeverityColour $i.Severity
    
            # Make before-System32 stand out
            $prefix = "  ->"
            if ($i.BeforeSys) { $prefix = " [!]" }
    
            Write-Host ("$prefix [{0}/100 | {1} | {2}] {3}" -f `
                $i.Score, $i.Severity, $i.Confidence, $i.Summary) `
                -ForegroundColor $colour
    
            # 🔥 Red team context
            if ($i.SurfaceType) {
    
                $rt = fncGetOffsecContext `
                    -SurfaceType $i.SurfaceType `
                    -StartName $i.StartName `
                    -BeforeSystem32 $i.BeforeSys
    
                Write-Host ("       Offsec: Impact={0} `n       Trigger={1} `n       Effort={2}  `n       Stealth={3}" -f `
                    $rt.Impact, $rt.Trigger, $rt.Effort, $rt.Stealth) `
                    -ForegroundColor DarkGray
            }
        }
    
        fncPrintMessage "" "plain"
    }
    

    # ==========================================================
    # Precompute PATH search order (fast + accurate)
    #   FIXES:
    #     - Expand env vars BEFORE Test-Path
    #     - Do NOT Select-Object -Unique (keeps true ordering/index)
    #     - Derive extra subdirs (e.g. \Scripts) as additional candidates
    # ==========================================================
    $tokenSids = fncGetTokenSids
    if (-not $tokenSids) {
        fncPrintMessage "Failed to build token SID set; ACL checks may be unreliable." "warning"
    }

    $pathEntries = @()
    try {
        $pathEntries = ($env:PATH -split ";") | Where-Object { $_ } | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    } catch { $pathEntries = @() }

    # Build ordered PATH list (1-based index preserved)
    $pathResolvedByIndex = @()
    for ($i = 0; $i -lt $pathEntries.Count; $i++) {

        $raw = $pathEntries[$i]
        $resolved = fncResolvePathSafe $raw

        $pathResolvedByIndex += [PSCustomObject]@{
            Index1   = ($i + 1)
            Raw      = $raw
            Resolved = $resolved
            Derived  = $false
            Parent   = $null
        }

        # Derive common subdirs (python-style) as additional candidates
        if ($resolved) {
            $scripts = Join-Path $resolved "Scripts"
            if (Test-Path -LiteralPath $scripts -PathType Container -ErrorAction SilentlyContinue) {
                $pathResolvedByIndex += [PSCustomObject]@{
                    Index1   = ($i + 1)    # inherit parent's PATH position
                    Raw      = ($raw + "\Scripts (derived)")
                    Resolved = (Get-Item -LiteralPath $scripts -ErrorAction SilentlyContinue).FullName
                    Derived  = $true
                    Parent   = $resolved
                }
            }
        }
    }

    # Compute System32 position using the TRUE ordered list (first match wins)
    $system32 = $null
    try { $system32 = (Get-Item -LiteralPath (Join-Path $env:WINDIR "System32") -ErrorAction SilentlyContinue).FullName } catch {}
    $system32Index1 = -1

    if ($system32) {
        foreach ($e in $pathResolvedByIndex) {
            if ($e.Resolved -and ($e.Resolved -ieq $system32)) { $system32Index1 = $e.Index1; break }
        }
    }

    $pathSurfaces = @()
    for ($i = 0; $i -lt $pathResolvedByIndex.Count; $i++) {

        $e = $pathResolvedByIndex[$i]
        $dir = $e.Resolved
        if (-not $dir) { continue }

        try {
            if (-not (Test-Path -LiteralPath $dir -PathType Container -ErrorAction SilentlyContinue)) { continue }
        } catch { continue }

        $beforeSystem32 = $false
        if ($system32Index1 -gt 0 -and $e.Index1 -lt $system32Index1) { $beforeSystem32 = $true }

        $owner = fncGetOwnerString $dir
        $isHighPrivOwner = fncIsHighPrivOwner $owner

        $isWritable = $false
        if ($tokenSids) { $isWritable = fncTokenCanWritePath -Path $dir -TokenSids $tokenSids }

        if (-not $isWritable) { continue }
        if (-not $isHighPrivOwner) { continue }

        $isSuspicious = fncIsSuspiciousPath $dir
        $score = fncScoreSurface -SurfaceType "PathDir" -IsWritableFile:$false -IsWritableDir:$true -IsHighPrivOwner:$isHighPrivOwner -IsSuspiciousPath:$isSuspicious -IsBeforeSystem32:$beforeSystem32 -ServiceStartName "" -IsLOLBIN:$false
        $sc = fncScoreToSeverityAndConfidence $score

        $derivedNote = ""
        if ($e.Derived -and $e.Parent) { $derivedNote = " (derived from '$($e.Parent)')" }

        $summary = "PATH dir (index $($e.Index1)) '$dir'$derivedNote Owner='$owner' (before System32: $beforeSystem32)"

        $pathSurfaces += [PSCustomObject]@{
            SurfaceType = "PathDir"        
            Score      = $score
            Severity   = $sc.Severity
            Confidence = $sc.Confidence
            Summary    = $summary
            Directory  = $dir
            Owner      = $owner
            BeforeSys  = $beforeSystem32
        }

        fncAddFinding `
            -Id ("PRIVESC_PATHDIR_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($dir)) -replace '[^A-Za-z0-9]','')) `
            -Category "Privilege Escalation" `
            -Title "Writable High-Priv PATH Directory" `
            -Severity $sc.Severity `
            -Status "Detected" `
            -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
            -Recommendation "Remove write access for low-priv groups from PATH directories; ensure PATH does not include writable privileged locations."
    }

    # ==========================================================
    # Services: correlate service binary + service directory (DLL search order #1)
    # ==========================================================
    $svcDirSurfaces = @()
    $svcBinSurfaces = @()

    $services = @()
    try { $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue } catch { $services = @() }

    $svcTotal = ($services | Measure-Object).Count
    $svcIdx = 0

    foreach ($svc in $services) {

        $svcIdx++
        if (($svcIdx % 25) -eq 0) {
            Write-Progress -Id 21 `
                -Activity "Correlating services (binary + directory)" `
                -Status ("{0}/{1} services" -f $svcIdx,$svcTotal) `
                -PercentComplete ([int](($svcIdx / [Math]::Max($svcTotal,1)) * 100))
        }

        try {
            $pathName = [string]$svc.PathName
            if (-not $pathName) { continue }

            $exeRaw = fncGetExecutableFromCommandLine $pathName
            $exe    = fncResolvePathSafe $exeRaw
            if (-not $exe) { continue }

            $dir = $null
            try { $dir = [System.IO.Path]::GetDirectoryName($exe) } catch { $dir = $null }
            if (-not $dir) { continue }

            $ownerDir = fncGetOwnerString $dir
            $ownerExe = fncGetOwnerString $exe

            $isHighPrivOwnerDir = fncIsHighPrivOwner $ownerDir
            $isHighPrivOwnerExe = fncIsHighPrivOwner $ownerExe

            $dirWritable = $false
            $fileWritable = $false
            if ($tokenSids) {
                $dirWritable  = fncTokenCanWritePath -Path $dir -TokenSids $tokenSids
                $fileWritable = fncTokenCanWritePath -Path $exe -TokenSids $tokenSids
            }

            $isSuspiciousDir = fncIsSuspiciousPath $dir
            $isSuspiciousExe = fncIsSuspiciousPath $exe
            $lolbin = fncIsLOLBINChain $pathName

            if ($dirWritable -and $isHighPrivOwnerDir) {

                $score = fncScoreSurface -SurfaceType "ServiceDir" -IsWritableFile:$false -IsWritableDir:$true -IsHighPrivOwner:$true -IsSuspiciousPath:$isSuspiciousDir -IsBeforeSystem32:$false -ServiceStartName ([string]$svc.StartName) -IsLOLBIN:$lolbin
                $sc = fncScoreToSeverityAndConfidence $score

                $summary = "ServiceDir '$dir' for service '$($svc.Name)' (StartName='$($svc.StartName)') Owner='$ownerDir'"

                $svcDirSurfaces += [PSCustomObject]@{
                    Score      = $score
                    Severity   = $sc.Severity
                    Confidence = $sc.Confidence
                    Summary    = $summary
                    Service    = $svc.Name
                    Directory  = $dir
                    StartName  = $svc.StartName
                    Owner      = $ownerDir
                }

                fncAddFinding `
                    -Id ("PRIVESC_SVCDIR_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($svc.Name + "|" + $dir)) -replace '[^A-Za-z0-9]','')) `
                    -Category "Privilege Escalation" `
                    -Title "Writable High-Priv Service Directory (DLL Search-Order #1)" `
                    -Severity $sc.Severity `
                    -Status "Detected" `
                    -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
                    -Recommendation "Remove write access for low-priv groups from service directories; review DLL load behaviour (Procmon/PE imports) to confirm hijack feasibility."
            }

            if ($fileWritable -and $isHighPrivOwnerExe) {

                $score = fncScoreSurface -SurfaceType "ServiceBinary" -IsWritableFile:$true -IsWritableDir:$false -IsHighPrivOwner:$true -IsSuspiciousPath:$isSuspiciousExe -IsBeforeSystem32:$false -ServiceStartName ([string]$svc.StartName) -IsLOLBIN:$lolbin
                $sc = fncScoreToSeverityAndConfidence $score

                $summary = "ServiceBinary '$exe' for service '$($svc.Name)' (StartName='$($svc.StartName)') Owner='$ownerExe'"

                $svcBinSurfaces += [PSCustomObject]@{
                    Score      = $score
                    Severity   = $sc.Severity
                    Confidence = $sc.Confidence
                    Summary    = $summary
                    Service    = $svc.Name
                    Binary     = $exe
                    StartName  = $svc.StartName
                    Owner      = $ownerExe
                }

                fncAddFinding `
                    -Id ("PRIVESC_SVCBIN_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($svc.Name + "|" + $exe)) -replace '[^A-Za-z0-9]','')) `
                    -Category "Privilege Escalation" `
                    -Title "Writable High-Priv Service Binary" `
                    -Severity $sc.Severity `
                    -Status "Detected" `
                    -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
                    -Recommendation "Fix ACLs on the service binary; validate service restart controls and change management."
            }

        } catch { continue }
    }

    Write-Progress -Id 21 -Activity "Correlating services (binary + directory)" -Completed -Status "Done"

    # ==========================================================
    # ServiceDll runtime loads (registry correlation)
    # ==========================================================
    $serviceDllSurfaces = @()

    $svcRegRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
    if (Test-Path $svcRegRoot -ErrorAction SilentlyContinue) {

        $svcKeys = @()
        try { $svcKeys = Get-ChildItem -Path $svcRegRoot -ErrorAction SilentlyContinue } catch { $svcKeys = @() }

        $total = ($svcKeys | Measure-Object).Count
        $idx = 0

        foreach ($k in $svcKeys) {

            $idx++
            if (($idx % 100) -eq 0) {
                Write-Progress -Id 22 `
                    -Activity "Correlating ServiceDll runtime loads" `
                    -Status ("{0}/{1} services" -f $idx,$total) `
                    -PercentComplete ([int](($idx / [Math]::Max($total,1)) * 100))
            }

            try {
                $params = Join-Path $k.PSPath "Parameters"
                if (-not (Test-Path $params -ErrorAction SilentlyContinue)) { continue }

                $ip = Get-ItemProperty -Path $params -ErrorAction SilentlyContinue
                if (-not $ip) { continue }

                $raw = $null
                try { $raw = [string]$ip.ServiceDll } catch { $raw = $null }
                if (-not $raw) { continue }

                $dll = fncResolvePathSafe $raw
                if (-not $dll) { continue }

                $dllDir = $null
                try { $dllDir = [System.IO.Path]::GetDirectoryName($dll) } catch { $dllDir = $null }
                if (-not $dllDir) { continue }

                $ownerDir = fncGetOwnerString $dllDir
                $isHighPrivOwnerDir = fncIsHighPrivOwner $ownerDir

                $dirWritable = $false
                $fileWritable = $false
                if ($tokenSids) {
                    $dirWritable  = fncTokenCanWritePath -Path $dllDir -TokenSids $tokenSids
                    $fileWritable = fncTokenCanWritePath -Path $dll -TokenSids $tokenSids
                }

                if (-not $dirWritable -or -not $isHighPrivOwnerDir) { continue }

                $isSuspicious = (fncIsSuspiciousPath $dll) -or (fncIsSuspiciousPath $dllDir)

                $score = fncScoreSurface -SurfaceType "ServiceDll" -IsWritableFile:$fileWritable -IsWritableDir:$dirWritable -IsHighPrivOwner:$true -IsSuspiciousPath:$isSuspicious -IsBeforeSystem32:$false -ServiceStartName "" -IsLOLBIN:$false
                $sc = fncScoreToSeverityAndConfidence $score

                $svcName = $k.PSChildName
                $summary = "ServiceDll '$dll' (service '$svcName') Dir='$dllDir' Owner='$ownerDir'"

                $serviceDllSurfaces += [PSCustomObject]@{
                    Score      = $score
                    Severity   = $sc.Severity
                    Confidence = $sc.Confidence
                    Summary    = $summary
                    Service    = $svcName
                    Dll        = $dll
                    Directory  = $dllDir
                    Owner      = $ownerDir
                }

                fncAddFinding `
                    -Id ("PRIVESC_SERVICEDLL_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($svcName + "|" + $dll)) -replace '[^A-Za-z0-9]','')) `
                    -Category "Privilege Escalation" `
                    -Title "Writable High-Priv ServiceDll Runtime Load" `
                    -Severity $sc.Severity `
                    -Status "Detected" `
                    -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
                    -Recommendation "Remove low-priv write access from the ServiceDll directory/file; validate service configuration and DLL integrity."

            } catch { continue }
        }

        Write-Progress -Id 22 -Activity "Correlating ServiceDll runtime loads" -Completed -Status "Done"
    }

    # ==========================================================
    # Output (sorted by highest score)
    # ==========================================================
    $svcDirSurfaces     = $svcDirSurfaces     | Sort-Object Score -Descending
    $svcBinSurfaces     = $svcBinSurfaces     | Sort-Object Score -Descending
    $pathSurfaces       = $pathSurfaces       | Sort-Object Score -Descending
    $serviceDllSurfaces = $serviceDllSurfaces | Sort-Object Score -Descending

    fncPrintSurface "Service Binary Direct Overwrite (High-Priv + Writable)" $svcBinSurfaces
    fncPrintSurface "Service Binary Directories (DLL Search-Order #1) (High-Priv + Writable)" $svcDirSurfaces
    fncPrintSurface "PATH Search-Order Directories (High-Priv + Writable)" $pathSurfaces
    fncPrintSurface "ServiceDll Runtime Loads (High-Priv + Writable Directory)" $serviceDllSurfaces

    $totalFinds = 0
    $totalFinds += ($svcBinSurfaces | Measure-Object).Count
    $totalFinds += ($svcDirSurfaces | Measure-Object).Count
    $totalFinds += ($pathSurfaces | Measure-Object).Count
    $totalFinds += ($serviceDllSurfaces | Measure-Object).Count

    if ($totalFinds -eq 0) {
        fncPrintMessage "No high-priv owned, user-writable search-order directories or runtime DLL loads detected." "success"
        fncAddFinding `
            -Id "PRIVESC_SVCDLLCORR_NONE" `
            -Category "Privilege Escalation" `
            -Title "No Service/PATH/DLL Correlation Findings" `
            -Severity "Good" `
            -Status "Not Detected" `
            -Message "No high-priv owned and user-writable service/PATH search-order directories or ServiceDll runtime loads were detected." `
            -Recommendation "No action required."
    } else {
        fncPrintMessage ("Detected {0} correlated priv-esc surface(s)." -f $totalFinds) "warning"
    }

    fncPrintMessage "" "plain"
}

Export-ModuleMember -Function fncGetPrivEscServiceAndDllCorrelations
