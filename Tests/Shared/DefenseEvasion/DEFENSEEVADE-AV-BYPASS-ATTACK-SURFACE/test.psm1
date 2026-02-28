# ================================================================
# Function: fncGetDefenseEvasionAVBypassAttackSurface
# Purpose : Defender exclusions -> exploitability + correlation
# Notes   : Low-priv friendly (registry read + CIM/tasks/runkeys)
# ================================================================
function fncGetDefenseEvasionAVBypassAttackSurface {

    fncPrintMessage "Enumerating Defender exclusions and correlating practical AV-bypass attack surfaces..." "info"
    Write-Host ""

    # ==========================================================
    # Helpers (baseline-aligned)
    # ==========================================================
    function fncGetTokenSids {
        try {
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $sids = New-Object System.Collections.Generic.HashSet[string]
            if ($id.User) { [void]$sids.Add($id.User.Value) }
            foreach ($g in $id.Groups) { try { [void]$sids.Add($g.Value) } catch {} }
            return $sids
        } catch { return $null }
    }

    function fncResolvePathSafe {
        param([string]$RawPath)
        if (-not $RawPath) { return $null }

        try {
            $p = $RawPath.Trim().Trim('"')
            $p = [Environment]::ExpandEnvironmentVariables($p)
            try { $p = $p.TrimEnd("\") } catch {}

            if (Test-Path -LiteralPath $p -ErrorAction SilentlyContinue) {
                return (Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).FullName
            }
        } catch {}

        return $null
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
            $p -like "*\users\*" -or
            $p -like "*\appdata\*" -or
            $p -like "*\temp\*" -or
            $p -like "*\tmp\*" -or
            $p -like "*\programdata\*" -or
            $p -like "*\users\public\*" -or
            $p -like "*\downloads\*"
        )
    }

    function fncIsLOLBINName {
        param([string]$NameOrPath)
        if (-not $NameOrPath) { return $false }

        $n = [System.IO.Path]::GetFileName($NameOrPath).ToLowerInvariant()

        return @(
            "powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe",
            "rundll32.exe","regsvr32.exe","installutil.exe","wmic.exe","msbuild.exe",
            "reg.exe","bitsadmin.exe","certutil.exe","schtasks.exe","svchost.exe"
        ) -contains $n
    }

    function fncGetExecutableFromCommandLine {
        param([string]$CommandLine)
        if (-not $CommandLine) { return $null }
        $cmd = $CommandLine.Trim()
        if ($cmd -match '^\s*"(.*?)"') { return $matches[1] }
        return ($cmd.Split(" ")[0])
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
                try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { continue }
                if (-not $TokenSids.Contains($sid)) { continue }

                $rights = [string]$ace.FileSystemRights

                if ($rights -match "FullControl" -or $rights -match "Modify" -or $rights -match "\bWrite\b") { return $true }
                if ($rights -match "WriteData" -or $rights -match "CreateFiles" -or $rights -match "AppendData") { return $true }
            }
        } catch {}

        return $false
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

    function fncGetOffsecContext {
        param(
            [string]$SurfaceType,  # ExcludedPath | ExcludedProcess | ExcludedExtension
            [bool]$Writable,
            [bool]$LinkedToSystemExec,
            [bool]$IsLOLBIN,
            [bool]$IsWildcard
        )

        $trigger = "Manual Use"
        $impact  = "Reduced AV Coverage"
        $effort  = "Medium"
        $stealth = "High"

        switch ($SurfaceType) {

            "ExcludedPath" {
                $trigger = "Drop/Stage in Excluded Path (then execute)"
                $impact  = "Payload staging bypasses AV scanning"
                $effort  = "Low"
                $stealth = "Very High"
            }

            "ExcludedProcess" {
                $trigger = "Execute via Excluded Process"
                $impact  = "Payload execution evades scanning (process excluded)"
                $effort  = "Medium"
                $stealth = "High"
            }

            "ExcludedExtension" {
                $trigger = "Drop file with Excluded Extension"
                $impact  = "Malicious file evades scanning by extension"
                $effort  = "Low"
                $stealth = "High"
            }
        }

        if ($Writable) { $effort = "Low" }
        if ($IsLOLBIN) { $effort = "Low"; $stealth = "Very High" }
        if ($IsWildcard) { $impact = "Broad AV bypass surface"; $stealth = "Very High" }

        if ($LinkedToSystemExec) {
            $impact = "AV bypass + privileged execution chain potential"
            $trigger = "Service/Task triggers execution"
            $effort = "Low"
            $stealth = "Very High"
        }

        return @{ Trigger=$trigger; Impact=$impact; Effort=$effort; Stealth=$stealth }
    }

    function fncPrintSurface {
        param([string]$Header,[array]$Items)

        fncPrintSectionHeader $Header

        if (-not $Items -or $Items.Count -eq 0) {
            fncPrintMessage "None detected." "success"
            Write-Host ""
            return
        }

        foreach ($i in $Items) {

            $colour = fncGetSeverityColour $i.Severity

            Write-Host ("  -> [{0}/100 | {1} | {2}] {3}" -f `
                $i.Score, $i.Severity, $i.Confidence, $i.Summary) `
                -ForegroundColor $colour

            if ($i.SurfaceType) {

                $rt = fncGetOffsecContext `
                    -SurfaceType $i.SurfaceType `
                    -Writable:$i.Writable `
                    -LinkedToSystemExec:$i.LinkedToSystemExec `
                    -IsLOLBIN:$i.IsLOLBIN `
                    -IsWildcard:$i.IsWildcard

                Write-Host ("       Offsec: Impact={0} `n       Trigger={1} `n       Effort={2}  `n       Stealth={3}" -f `
                    $rt.Impact, $rt.Trigger, $rt.Effort, $rt.Stealth) `
                    -ForegroundColor DarkGray
            }

            if ($i.Links -and $i.Links.Count -gt 0) {
                foreach ($l in ($i.Links | Select-Object -First 4)) {
                    Write-Host ("       Link: {0}" -f $l) -ForegroundColor DarkGray
                }
                if ($i.Links.Count -gt 4) {
                    Write-Host ("       Link: (+{0} more...)" -f ($i.Links.Count - 4)) -ForegroundColor DarkGray
                }
            }
        }

        Write-Host ""
    }

    function fncNormalisePrefix {
        param([string]$Path)
        if (-not $Path) { return $null }
        try {
            $p = [Environment]::ExpandEnvironmentVariables($Path.Trim().Trim('"'))
            return $p.TrimEnd("\")
        } catch { return $Path }
    }

    function fncIsWildcardValue {
        param([string]$Value)
        if (-not $Value) { return $false }
        return ($Value -eq "*" -or $Value -like "*`**" -or $Value -like "*\*" -or $Value -like "*?*")
    }

    function fncIsRiskyExtension {
        param([string]$Ext)
        if (-not $Ext) { return $false }
        $e = $Ext.ToLowerInvariant()
        if (-not $e.StartsWith(".")) { $e = "." + $e }

        return @(
            ".exe",".dll",".sys",".msi",".msp",".ps1",".psm1",".bat",".cmd",".com",".vbs",".js",".jse",
            ".hta",".wsf",".lnk",".scr",".cpl",".jar",".iso",".img"
        ) -contains $e
    }

    # NEW: for wildcard paths, extract the "real" parent directory to test
    function fncGetWildcardParentDir {
        param([string]$Value)

        if (-not $Value) { return $null }

        try {
            $v = fncNormalisePrefix $Value
            if (-not $v) { return $null }

            $wildIdx = $v.IndexOfAny(@('*','?'))
            if ($wildIdx -lt 0) { return $null }

            $prefix = $v.Substring(0, $wildIdx)

            # walk back to a directory boundary
            $lastSlash = $prefix.LastIndexOf("\")
            if ($lastSlash -le 2) { return $null } # e.g. "C:\"
            $parent = $prefix.Substring(0, $lastSlash).TrimEnd("\")
            if (-not $parent) { return $null }

            return $parent
        } catch { return $null }
    }

    # ==========================================================
    # Collect "execution surfaces" to correlate against exclusions
    # ==========================================================
    $execRefs = New-Object System.Collections.Generic.List[object]

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue
        foreach ($svc in $services) {
            $pn = [string]$svc.PathName
            if (-not $pn) { continue }

            $exeRaw = fncGetExecutableFromCommandLine $pn
            $exe = fncResolvePathSafe $exeRaw
            if (-not $exe) { $exe = fncNormalisePrefix $exeRaw }

            $execRefs.Add([PSCustomObject]@{
                Type  = "Service"
                Name  = [string]$svc.Name
                Path  = [string]$exe
                Raw   = $pn
                RunsAsSystem = ([string]$svc.StartName -match "LocalSystem|NT AUTHORITY\\SYSTEM")
                StartName = [string]$svc.StartName
            }) | Out-Null
        }
    } catch {}

    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue
        foreach ($t in $tasks) {
            try {
                foreach ($a in $t.Actions) {
                    $exe = $null
                    $raw = $null

                    try { $exe = [string]$a.Execute } catch {}
                    try { $raw = ("{0} {1}" -f $a.Execute, $a.Arguments).Trim() } catch {}

                    if (-not $exe) { continue }

                    $exeResolved = fncResolvePathSafe $exe
                    if (-not $exeResolved) { $exeResolved = fncNormalisePrefix $exe }

                    $runsAsSystem = $false
                    try {
                        if ($t.Principal -and $t.Principal.UserId -match "SYSTEM|NT AUTHORITY\\SYSTEM") { $runsAsSystem = $true }
                    } catch {}

                    $execRefs.Add([PSCustomObject]@{
                        Type  = "ScheduledTask"
                        Name  = [string]$t.TaskName
                        Path  = [string]$exeResolved
                        Raw   = $raw
                        RunsAsSystem = $runsAsSystem
                        StartName = (if ($runsAsSystem) { "SYSTEM" } else { "" })
                    }) | Out-Null
                }
            } catch {}
        }
    } catch {}

    $runKeyCandidates = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($rk in $runKeyCandidates) {
        if (-not (Test-Path $rk -ErrorAction SilentlyContinue)) { continue }

        try {
            $vals = Get-ItemProperty -Path $rk -ErrorAction SilentlyContinue
            if (-not $vals) { continue }

            foreach ($p in $vals.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" }) {
                $raw = [string]$p.Value
                if (-not $raw) { continue }

                $exeRaw = fncGetExecutableFromCommandLine $raw
                $exeResolved = fncResolvePathSafe $exeRaw
                if (-not $exeResolved) { $exeResolved = fncNormalisePrefix $exeRaw }

                $execRefs.Add([PSCustomObject]@{
                    Type  = "Autorun"
                    Name  = ("{0}::{1}" -f $rk, [string]$p.Name)
                    Path  = [string]$exeResolved
                    Raw   = $raw
                    RunsAsSystem = $false
                    StartName = ""
                }) | Out-Null
            }
        } catch {}
    }

    $startupDirs = @()
    try { $startupDirs += (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup") } catch {}
    try { $startupDirs += (Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Startup") } catch {}

    foreach ($sd in ($startupDirs | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $sd -PathType Container -ErrorAction SilentlyContinue)) { continue }
        try {
            Get-ChildItem -LiteralPath $sd -File -ErrorAction SilentlyContinue | ForEach-Object {
                $execRefs.Add([PSCustomObject]@{
                    Type  = "StartupFolder"
                    Name  = $_.Name
                    Path  = $_.FullName
                    Raw   = $_.FullName
                    RunsAsSystem = $false
                    StartName = ""
                }) | Out-Null
            }
        } catch {}
    }

    # ==========================================================
    # Read Defender exclusions (Registry, low-priv friendly)
    # ==========================================================
    $tokenSids = fncGetTokenSids
    if (-not $tokenSids) {
        fncPrintMessage "Failed to build token SID set; writable checks may be less accurate." "warning"
    }

    $exclRoots = @(
        "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
    )

    $types = @("Paths","Processes","Extensions")
    $surfaces = @()

    foreach ($root in $exclRoots) {

        foreach ($type in $types) {

            $key = Join-Path $root $type
            if (-not (Test-Path $key -ErrorAction SilentlyContinue)) { continue }

            try {
                $ip = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                if (-not $ip) { continue }

                foreach ($prop in ($ip.PSObject.Properties | Where-Object { $_.MemberType -eq "NoteProperty" })) {

                    $val = [string]$prop.Name
                    if (-not $val) { continue }

                    $isWildcard = fncIsWildcardValue $val
                    $writable = $false
                    $exists = $false
                    $owner = ""
                    $isHighPrivOwner = $false
                    $isSuspicious = $false
                    $isLOL = $false
                    $linkedToSystem = $false
                    $links = New-Object System.Collections.Generic.List[string]

                    # NEW flags for wildcard parent handling
                    $wildParent = $null
                    $wildParentExists = $false
                    $wildParentWritable = $false

                    $surfaceType = ""
                    $normVal = $val

                    if ($type -eq "Paths") {

                        $surfaceType = "ExcludedPath"

                        # If wildcard path, don't try to resolve the full path;
                        # instead, compute a real parent directory and test it.
                        if ($isWildcard) {

                            $wildParent = fncGetWildcardParentDir $val
                            if ($wildParent) {
                                try { if (Test-Path -LiteralPath $wildParent -ErrorAction SilentlyContinue) { $wildParentExists = $true } } catch {}
                                if ($wildParentExists -and $tokenSids) {
                                    $wildParentWritable = fncTokenCanWritePath -Path $wildParent -TokenSids $tokenSids
                                }

                                # Treat "writable" as true if parent is writable (attacker can create the excluded folder subtree)
                                if (-not $wildParentWritable) {
                                    $writable = $false
                                } else {
                                    $writable = $true
                                }

                                $isSuspicious = fncIsSuspiciousPath $wildParent
                                $normVal = ("{0} (wildcard; parent='{1}', parentWritable={2})" -f (fncNormalisePrefix $val), $wildParent, $wildParentWritable)
                            } else {
                                $normVal = (fncNormalisePrefix $val)
                            }

                            # Exists stays false unless the literal wildcard path exists (it generally won't)
                            $exists = $false

                        } else {

                            $resolved = fncResolvePathSafe $val
                            if (-not $resolved) { $resolved = fncNormalisePrefix $val }
                            $normVal = $resolved

                            $isSuspicious = fncIsSuspiciousPath $resolved

                            try {
                                if ($resolved -and (Test-Path -LiteralPath $resolved -ErrorAction SilentlyContinue)) { $exists = $true }
                            } catch {}

                            if ($exists -and $tokenSids) {
                                $writable = fncTokenCanWritePath -Path $resolved -TokenSids $tokenSids

                                try {
                                    $parent = [System.IO.Path]::GetDirectoryName($resolved)
                                    if (-not $writable -and $parent) {
                                        $writable = fncTokenCanWritePath -Path $parent -TokenSids $tokenSids
                                    }
                                } catch {}
                            }

                            if ($exists) {
                                $owner = fncGetOwnerString $resolved
                                $isHighPrivOwner = fncIsHighPrivOwner $owner
                            }
                        }

                        # Correlate with execution refs
                        # For wildcard paths, use wildcard parent if available, else best-effort string prefix before wildcard.
                        $corrBase = $null
                        if ($isWildcard -and $wildParent) { $corrBase = $wildParent }
                        else { $corrBase = ($normVal -replace "\s+\(wildcard.*$","") }

                        if ($corrBase) {
                            foreach ($r in $execRefs) {
                                if (-not $r.Path) { continue }
                                if ($r.Path.ToLowerInvariant().StartsWith($corrBase.ToLowerInvariant())) {
                                    $links.Add(("{0}: {1} -> {2}" -f $r.Type,$r.Name,$r.Path)) | Out-Null
                                    if ($r.RunsAsSystem) { $linkedToSystem = $true }
                                }
                            }
                        }
                    }
                    elseif ($type -eq "Processes") {

                        $surfaceType = "ExcludedProcess"

                        $proc = fncNormalisePrefix $val
                        $normVal = $proc
                        $isLOL = fncIsLOLBINName $proc

                        $resolved = fncResolvePathSafe $proc
                        if ($resolved) { $exists = $true; $normVal = $resolved }

                        if ($resolved -and $tokenSids) {
                            $writable = fncTokenCanWritePath -Path $resolved -TokenSids $tokenSids
                            if (-not $writable) {
                                try {
                                    $parent = [System.IO.Path]::GetDirectoryName($resolved)
                                    if ($parent) { $writable = fncTokenCanWritePath -Path $parent -TokenSids $tokenSids }
                                } catch {}
                            }

                            $owner = fncGetOwnerString $resolved
                            $isHighPrivOwner = fncIsHighPrivOwner $owner
                            $isSuspicious = fncIsSuspiciousPath $resolved
                        }

                        foreach ($r in $execRefs) {
                            if (-not $r.Path) { continue }
                            $rn = [System.IO.Path]::GetFileName($r.Path)
                            $pn = [System.IO.Path]::GetFileName($proc)
                            if ($rn -and $pn -and ($rn.ToLowerInvariant() -eq $pn.ToLowerInvariant())) {
                                $links.Add(("{0}: {1} uses excluded process -> {2}" -f $r.Type,$r.Name,$r.Raw)) | Out-Null
                                if ($r.RunsAsSystem) { $linkedToSystem = $true }
                            }
                        }
                    }
                    elseif ($type -eq "Extensions") {

                        $surfaceType = "ExcludedExtension"

                        $ext = $val.Trim()
                        if (-not $ext.StartsWith(".")) { $ext = "." + $ext }
                        $normVal = $ext

                        $isSuspicious = fncIsRiskyExtension $ext
                    }

                    # ==================================================
                    # Scoring (exploitability-first)
                    # ==================================================
                    $score = 0

                    switch ($surfaceType) {
                        "ExcludedPath"      { $score += 35 }
                        "ExcludedProcess"   { $score += 30 }
                        "ExcludedExtension" { $score += 20 }
                    }

                    if ($isWildcard) { $score += 35 }

                    # Writable signal:
                    # - normal paths: writable means drop/modify inside exclusion
                    # - wildcard paths: writable means can CREATE excluded subtree under writable parent
                    if ($writable)   { $score += 45 }

                    if ($isSuspicious) { $score += 20 }
                    if ($isLOL) { $score += 20 }

                    if ($links.Count -gt 0) { $score += 10 }
                    if ($links.Count -ge 3) { $score += 10 }
                    if ($linkedToSystem) { $score += 25 }

                    if ($isHighPrivOwner -and $writable) { $score += 10 }

                    # NEW: wildcard parent exists + writable but excluded folder doesn't exist yet => still a strong creation vector
                    if ($surfaceType -eq "ExcludedPath" -and $isWildcard -and (-not $exists) -and $wildParentExists -and $wildParentWritable) {
                        $score += 10
                    }

                    if ($score -gt 100) { $score = 100 }

                    $sc = fncScoreToSeverityAndConfidence $score

                    $extra = @()
                    if ($surfaceType -eq "ExcludedPath") {
                        $extra += ("Writable={0}" -f $writable)
                        if ($isWildcard -and $wildParent) { $extra += ("WildcardParent='{0}'" -f $wildParent); $extra += ("ParentWritable={0}" -f $wildParentWritable) }
                        if ($exists) { $extra += ("Owner='{0}'" -f $owner) }
                        if ($linkedToSystem) { $extra += "LinkedToSYSTEMExec=True" }
                        if ($isWildcard) { $extra += "Wildcard=True" }
                        if ($isSuspicious) { $extra += "SuspiciousPath=True" }
                    }
                    elseif ($surfaceType -eq "ExcludedProcess") {
                        $extra += ("LOLBIN={0}" -f $isLOL)
                        $extra += ("Writable={0}" -f $writable)
                        if ($linkedToSystem) { $extra += "LinkedToSYSTEMExec=True" }
                        if ($isWildcard) { $extra += "Wildcard=True" }
                    }
                    else {
                        $extra += ("RiskyExt={0}" -f $isSuspicious)
                        if ($isWildcard) { $extra += "Wildcard=True" }
                    }

                    $summary = "Defender exclusion [$surfaceType] Value='$normVal' Source='$key' ({0})" -f ($extra -join ", ")

                    $surfaces += [PSCustomObject]@{
                        SurfaceType       = $surfaceType
                        Score             = $score
                        Severity          = $sc.Severity
                        Confidence        = $sc.Confidence
                        Summary           = $summary
                        Type              = $type
                        Value             = $normVal
                        SourceKey         = $key
                        Writable          = $writable
                        IsWildcard        = $isWildcard
                        IsLOLBIN          = $isLOL
                        LinkedToSystemExec= $linkedToSystem
                        Links             = $links
                    }

                    fncAddFinding `
                        -Id ("DEF_EVASION_AVBYPASS_" + ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($surfaceType + "|" + $normVal + "|" + $key)) -replace '[^A-Za-z0-9]','')) `
                        -TestId "DEFENSEEVADE-AV-BYPASS-ATTACK-SURFACE" `
                        -Category "Defense Evasion" `
                        -Title "AV Bypass Attack Surface (Defender Exclusion)" `
                        -Severity $sc.Severity `
                        -Status "Detected" `
                        -Message ("{0} (Score={1}/100, Confidence={2})" -f $summary,$score,$sc.Confidence) `
                        -Recommendation "Review and minimise Defender exclusions. Prioritise removal of wildcard exclusions and user-writable excluded paths; investigate excluded paths/processes referenced by services/tasks/autoruns."
                }
            } catch {}
        }
    }

    $surfaces = $surfaces | Sort-Object Score -Descending

    fncPrintSurface "AV Bypass Attack Surface (Defender Exclusions + Correlation)" $surfaces

    fncPrintMessage ("Enumerated {0} exclusion surface(s)." -f ($surfaces | Measure-Object).Count) "warning"
    Write-Host ""
}

Export-ModuleMember -Function fncGetDefenseEvasionAVBypassAttackSurface