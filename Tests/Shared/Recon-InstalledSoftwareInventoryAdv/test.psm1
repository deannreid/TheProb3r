# ================================================================
# Module  : Recon-Installed.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Module-scoped defaults
# ------------------------------------------------------------
$script:ReconSoftware = [pscustomobject]@{
    CacheRoot = $null

    OffensiveIndicators = @(

        # -------------------------------------------------
        # Recon / Enumeration (Low–Medium Weight)
        # -------------------------------------------------
        @{ Pattern="nmap";               Category="Recon"; Weight=5 },
        @{ Pattern="masscan";            Category="Recon"; Weight=6 },
        @{ Pattern="rustscan";           Category="Recon"; Weight=6 },
        @{ Pattern="wireshark";          Category="Recon"; Weight=4 },
        @{ Pattern="tshark";             Category="Recon"; Weight=4 },
        @{ Pattern="tcpdump";            Category="Recon"; Weight=4 },
        @{ Pattern="amass";              Category="Recon"; Weight=5 },
        @{ Pattern="recon-ng";           Category="Recon"; Weight=5 },
        @{ Pattern="enum4linux";         Category="Recon"; Weight=6 },
        @{ Pattern="linpeas";            Category="Recon"; Weight=6 },
        @{ Pattern="winpeas";            Category="Recon"; Weight=6 },

        # -------------------------------------------------
        # AD / Credential Access (High Weight)
        # -------------------------------------------------
        @{ Pattern="mimikatz";           Category="CredDump"; Weight=20 },
        @{ Pattern="rubeus";             Category="Kerberos Abuse"; Weight=18 },
        @{ Pattern="sharphound";         Category="AD Recon"; Weight=15 },
        @{ Pattern="bloodhound";         Category="AD Recon"; Weight=15 },
        @{ Pattern="secretsdump";        Category="CredDump"; Weight=20 },
        @{ Pattern="impacket";           Category="Lateral Movement"; Weight=15 },
        @{ Pattern="ntlmrelayx";         Category="Relay Attack"; Weight=18 },
        @{ Pattern="certipy";            Category="ADCS Abuse"; Weight=20 },
        @{ Pattern="certify";            Category="ADCS Abuse"; Weight=20 },
        @{ Pattern="nanodump";           Category="CredDump"; Weight=18 },
        @{ Pattern="lsassy";             Category="CredDump"; Weight=18 },

        # -------------------------------------------------
        # Exploitation Frameworks (Very High Weight)
        # -------------------------------------------------
        @{ Pattern="metasploit";         Category="Exploitation Framework"; Weight=20 },
        @{ Pattern="msfconsole";         Category="Exploitation Framework"; Weight=20 },
        @{ Pattern="cobalt strike";      Category="C2"; Weight=25 },
        @{ Pattern="beacon";             Category="C2"; Weight=25 },
        @{ Pattern="sliver";             Category="C2"; Weight=22 },
        @{ Pattern="mythic";             Category="C2"; Weight=22 },
        @{ Pattern="havoc";              Category="C2"; Weight=22 },
        @{ Pattern="bruteratel";         Category="C2"; Weight=22 },
        @{ Pattern="empire";             Category="C2"; Weight=20 },

        # -------------------------------------------------
        # Web / API Attack Tooling
        # -------------------------------------------------
        @{ Pattern="sqlmap";             Category="Web Exploitation"; Weight=12 },
        @{ Pattern="burp";               Category="Web Testing"; Weight=10 },
        @{ Pattern="zaproxy";            Category="Web Testing"; Weight=10 },
        @{ Pattern="ffuf";               Category="Web Fuzzing"; Weight=8 },
        @{ Pattern="gobuster";           Category="Web Fuzzing"; Weight=8 },
        @{ Pattern="nikto";              Category="Web Exploitation"; Weight=8 },
        @{ Pattern="wfuzz";              Category="Web Fuzzing"; Weight=8 },

        # -------------------------------------------------
        # Password Attacks
        # -------------------------------------------------
        @{ Pattern="hashcat";            Category="Password Cracking"; Weight=15 },
        @{ Pattern="john";               Category="Password Cracking"; Weight=15 },
        @{ Pattern="hydra";              Category="Password Attack"; Weight=12 },
        @{ Pattern="medusa";             Category="Password Attack"; Weight=12 },

        # -------------------------------------------------
        # Pivoting / Tunnelling (Medium–High)
        # -------------------------------------------------
        @{ Pattern="chisel";             Category="Pivot"; Weight=15 },
        @{ Pattern="ligolo";             Category="Pivot"; Weight=15 },
        @{ Pattern="frp";                Category="Pivot"; Weight=15 },
        @{ Pattern="ngrok";              Category="Tunnel"; Weight=12 },
        @{ Pattern="cloudflared";        Category="Tunnel"; Weight=12 },
        @{ Pattern="sshuttle";           Category="Tunnel"; Weight=12 },

        # -------------------------------------------------
        # Debug / Reverse Engineering
        # -------------------------------------------------
        @{ Pattern="x64dbg";             Category="Exploit Dev"; Weight=8 },
        @{ Pattern="ollydbg";            Category="Exploit Dev"; Weight=8 },
        @{ Pattern="ghidra";             Category="Reverse Engineering"; Weight=8 },
        @{ Pattern="ida";                Category="Reverse Engineering"; Weight=10 },
        @{ Pattern="cutter";             Category="Reverse Engineering"; Weight=8 },

        # -------------------------------------------------
        # Cloud Attack
        # -------------------------------------------------
        @{ Pattern="awscli";             Category="Cloud Tooling"; Weight=6 },
        @{ Pattern="azure cli";          Category="Cloud Tooling"; Weight=6 },
        @{ Pattern="gcloud";             Category="Cloud Tooling"; Weight=6 },
        @{ Pattern="prowler";            Category="Cloud Attack"; Weight=10 },

        # -------------------------------------------------
        # Container / K8s Attack
        # -------------------------------------------------
        @{ Pattern="kubectl";            Category="Container Tooling"; Weight=6 },
        @{ Pattern="kube-hunter";        Category="Container Attack"; Weight=10 },
        @{ Pattern="trivy";              Category="Container Scan"; Weight=6 },

        # -------------------------------------------------
        # LOLBIN Abuse Indicators
        # -------------------------------------------------
        @{ Pattern="installutil";        Category="LOLBIN"; Weight=8 },
        @{ Pattern="regsvr32";           Category="LOLBIN"; Weight=8 },
        @{ Pattern="mshta";              Category="LOLBIN"; Weight=8 },
        @{ Pattern="rundll32";           Category="LOLBIN"; Weight=8 }
    )

    PivotIndicators = @(
        @{ Pattern="teamviewer";         Weight=10 },
        @{ Pattern="anydesk";            Weight=10 },
        @{ Pattern="rustdesk";           Weight=10 },
        @{ Pattern="vnc";                Weight=10 },
        @{ Pattern="tightvnc";           Weight=10 },
        @{ Pattern="realvnc";            Weight=10 },
        @{ Pattern="screenconnect";      Weight=12 },
        @{ Pattern="connectwise";        Weight=12 },
        @{ Pattern="bomgar";             Weight=12 },
        @{ Pattern="beyondtrust";        Weight=12 },
        @{ Pattern="logmein";            Weight=10 },
        @{ Pattern="openvpn";            Weight=8 },
        @{ Pattern="wireguard";          Weight=8 },
        @{ Pattern="tailscale";          Weight=8 },
        @{ Pattern="zerotier";           Weight=8 }
    )

    EolIndicators = @(
        @{ Pattern="(?i)\badobe flash\b";                 Reason="Adobe Flash is EOL" },
        @{ Pattern="(?i)\bsilverlight\b";                Reason="Microsoft Silverlight is EOL" },
        @{ Pattern="(?i)\bjava\s*(6|7)\b";               Reason="Legacy Java is EOL" },
        @{ Pattern="(?i)\bpython\s*(2(\.|$))\b";         Reason="Python 2 is EOL" },
        @{ Pattern="(?i)\binternet explorer\b";          Reason="Internet Explorer is retired" },
        @{ Pattern="(?i)\boffice\s*2010\b";              Reason="Office 2010 is EOL" },
        @{ Pattern="(?i)\boffice\s*2013\b";              Reason="Office 2013 is EOL" },
        @{ Pattern="(?i)\bwindows\s*7\b";                Reason="Windows 7 is EOL" },
        @{ Pattern="(?i)\bwindows\s*8(\.1)?\b";          Reason="Windows 8/8.1 is EOL" }
    )
}

function fncInitReconSoftwareCache {

    fncLog "DEBUG" "Entering fncInitReconSoftwareCache"

    try {

        fncLog "DEBUG" ("LogRoot value: [{0}]" -f $global:LogRoot)

        if (-not $global:LogRoot) {
            fncLog "ERROR" "LogRoot is NULL or empty."
            throw "LogRoot not initialised by runner."
        }

        if (-not (Test-Path -LiteralPath $global:LogRoot)) {
            fncLog "ERROR" ("LogRoot path does not exist: {0}" -f $global:LogRoot)
            throw "LogRoot path invalid."
        }

        $root = Join-Path -Path $global:LogRoot -ChildPath "GlobalCache"

        fncLog "DEBUG" ("Computed GlobalCache path: [{0}]" -f $root)

        # Validate path characters explicitly
        try {
            [System.IO.Path]::GetFullPath($root) | Out-Null
            fncLog "DEBUG" "Path validation succeeded."
        }
        catch {
            fncLogException $_.Exception "PathValidation"
            throw
        }

        if (-not (Test-Path -LiteralPath $root)) {
            fncLog "DEBUG" "GlobalCache directory does not exist. Creating..."
            New-Item -ItemType Directory -Path $root -Force | Out-Null
            fncLog "INFO" ("Created GlobalCache directory: {0}" -f $root)
        }

        $script:ReconSoftware.CacheRoot = $root
        fncLog "DEBUG" "Cache root initialised successfully."
    }
    catch {
        fncLogException $_.Exception "fncInitReconSoftwareCache"
        throw
    }
}

function fncShowReconColourKey {

    fncSafeSectionHeader "Risk Classification Key"

    Write-Host "EOL (End Of Life)" -ForegroundColor Red
    Write-Host "KEV (Known Exploited Vulnerability)" -ForegroundColor Magenta
    Write-Host "High CVSS (>= 8.0)" -ForegroundColor DarkYellow
    Write-Host "Unsigned Binary" -ForegroundColor Yellow
    Write-Host "Informational / Low Risk" -ForegroundColor Gray
    Write-Host "Offensive / Pivot Tool Detected" -ForegroundColor Cyan
    fncPrintMessage "" "plain"
}

function fncSafeHasProp {
    param(
        [Parameter(Mandatory=$true)]$Obj,
        [Parameter(Mandatory=$true)][string]$Name
    )
    if ($null -eq $Obj) { return $false }
    try { return ($Obj.PSObject.Properties.Name -contains $Name) } catch { return $false }
}

function fncSafeGetProp {
    param(
        [Parameter(Mandatory=$true)]$Obj,
        [Parameter(Mandatory=$true)][string]$Name,
        $Default = $null
    )
    if (-not (fncSafeHasProp $Obj $Name)) { return $Default }
    try { return $Obj.$Name } catch { return $Default }
}

function fncToSafeString {
    param($Value)
    if ($null -eq $Value) { return "" }
    return [string]$Value
}

function fncTryParseVersion {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }

    $m = [regex]::Match($Text.Trim(), '^\s*(\d+(\.\d+){0,4})')
    if (-not $m.Success) { return $null }

    try { return [version]$m.Groups[1].Value } catch { return $null }
}

function fncCompareVersions {
    param(
        [string]$A,
        [string]$B
    )
    $va = fncTryParseVersion $A
    $vb = fncTryParseVersion $B

    if ($null -ne $va -and $null -ne $vb) {
        if ($va -lt $vb) { return -1 }
        if ($va -gt $vb) { return 1 }
        return 0
    }

    $sa = (fncToSafeString $A).Trim()
    $sb = (fncToSafeString $B).Trim()
    return [string]::Compare($sa, $sb, $true)
}

function fncTestVersionInRange {
    param(
        [string]$InstalledVersion,
        [string]$StartIncluding,
        [string]$StartExcluding,
        [string]$EndIncluding,
        [string]$EndExcluding
    )

    if ([string]::IsNullOrWhiteSpace($InstalledVersion)) { return $false }

    if (-not [string]::IsNullOrWhiteSpace($StartIncluding)) {
        if ((fncCompareVersions $InstalledVersion $StartIncluding) -lt 0) { return $false }
    }
    if (-not [string]::IsNullOrWhiteSpace($StartExcluding)) {
        if ((fncCompareVersions $InstalledVersion $StartExcluding) -le 0) { return $false }
    }

    if (-not [string]::IsNullOrWhiteSpace($EndIncluding)) {
        if ((fncCompareVersions $InstalledVersion $EndIncluding) -gt 0) { return $false }
    }
    if (-not [string]::IsNullOrWhiteSpace($EndExcluding)) {
        if ((fncCompareVersions $InstalledVersion $EndExcluding) -ge 0) { return $false }
    }

    return $true
}

function fncNormaliseSoftwareName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) { return "" }

    $n = $Name.ToLowerInvariant()
    $n = $n -replace '\(.*?\)', ''
    $n = $n -replace '\b(microsoft|inc\.?|ltd\.?|limited|corporation|corp\.?|software|systems)\b', ''
    $n = $n -replace '[^a-z0-9\.\+\- ]', ' '
    $n = $n -replace '\s+', ' '
    return $n.Trim()
}

function fncExtractVendorProductFromEntry {
    param(
        [string]$Name,
        [string]$Publisher
    )

    $cleanName = fncNormaliseSoftwareName $Name
    $cleanPub  = fncNormaliseSoftwareName $Publisher

    if ([string]::IsNullOrWhiteSpace($cleanName)) {
        return [pscustomobject]@{
            Vendor  = ""
            Product = ""
        }
    }

    # Determine vendor
    $vendor = ""
    if (-not [string]::IsNullOrWhiteSpace($cleanPub)) {
        $vendor = $cleanPub
    }
    else {
        $parts = $cleanName -split '\s+'
        if ($parts.Count -gt 0) {
            $vendor = $parts[0]
        }
    }

    # Remove vendor prefix from product safely (no regex)
    $product = $cleanName

    if (-not [string]::IsNullOrWhiteSpace($vendor)) {
        if ($cleanName.StartsWith($vendor, [System.StringComparison]::InvariantCultureIgnoreCase)) {
            $product = $cleanName.Substring($vendor.Length).Trim()
        }
    }

    return [pscustomobject]@{
        Vendor  = $vendor.Trim()
        Product = $product.Trim()
    }
}

function fncIsOffensiveTool {
    param(
        [string]$Name,
        [string]$Publisher,
        [string]$InstallLocation,
        [string]$DisplayIcon,
        [string]$UninstallString,
        [string]$PrimaryBinary
    )

    $hay = ("{0} {1} {2} {3} {4} {5}" -f `
        (fncToSafeString $Name),
        (fncToSafeString $Publisher),
        (fncToSafeString $InstallLocation),
        (fncToSafeString $DisplayIcon),
        (fncToSafeString $UninstallString),
        (fncToSafeString $PrimaryBinary)
    ).ToLowerInvariant()

    $matchedCategories = @()
    $totalWeight = 0

    foreach ($indicator in $script:ReconSoftware.OffensiveIndicators) {

        $pattern  = $indicator.Pattern.ToLowerInvariant()
        $category = $indicator.Category
        $weight   = [int]$indicator.Weight

        if ($hay -like "*$pattern*") {
            $matchedCategories += $category
            $totalWeight += $weight
        }
    }

    return [pscustomobject]@{
        Matched    = ($totalWeight -gt 0)
        Categories = ($matchedCategories | Sort-Object -Unique)
        TotalWeight = $totalWeight
    }
}

function fncIsPivotCapable {
    param(
        [string]$Name,
        [string]$Publisher,
        [string]$InstallLocation,
        [string]$DisplayIcon,
        [string]$UninstallString,
        [string]$PrimaryBinary
    )

    $hay = ("{0} {1} {2} {3} {4} {5}" -f `
        (fncToSafeString $Name),
        (fncToSafeString $Publisher),
        (fncToSafeString $InstallLocation),
        (fncToSafeString $DisplayIcon),
        (fncToSafeString $UninstallString),
        (fncToSafeString $PrimaryBinary)
    ).ToLowerInvariant()

    foreach ($i in $script:ReconSoftware.PivotIndicators) {

        $pattern = $i.Pattern.ToLowerInvariant()

        if ($hay -like "*$pattern*") {
            return $true
        }
    }

    return $false
}

function fncDetectEolHeuristic {
    param(
        [string]$Name,
        [string]$Version
    )

    $n = "{0} {1}" -f (fncToSafeString $Name), (fncToSafeString $Version)

    foreach ($rule in $script:ReconSoftware.EolIndicators) {
        $pat = fncSafeGetProp $rule "Pattern" ""
        $why = fncSafeGetProp $rule "Reason"  ""
        if (-not [string]::IsNullOrWhiteSpace($pat) -and $n -match $pat) {
            return [pscustomobject]@{ Eol=$true; Reason=$why }
        }
    }

    return [pscustomobject]@{ Eol=$false; Reason="" }
}

function fncGetInstalledSoftwareFromRegistry {
    param(
        [switch]$ExcludePerUser
    )

    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    if (-not $ExcludePerUser) {
        $paths += "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }

    $items = @()

    foreach ($p in $paths) {
        try {
            Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
                Where-Object { $_ -and (fncSafeHasProp $_ "DisplayName") -and -not [string]::IsNullOrWhiteSpace($_.DisplayName) } |
                ForEach-Object {

                    $dn = fncToSafeString (fncSafeGetProp $_ "DisplayName" "")
                    $dv = fncToSafeString (fncSafeGetProp $_ "DisplayVersion" "")
                    $pb = fncToSafeString (fncSafeGetProp $_ "Publisher" "")
                    $il = fncToSafeString (fncSafeGetProp $_ "InstallLocation" "")
                    $di = fncToSafeString (fncSafeGetProp $_ "DisplayIcon" "")
                    $un = fncToSafeString (fncSafeGetProp $_ "UninstallString" "")

                    $items += [pscustomobject]@{
                        Name            = $dn.Trim()
                        Version         = $dv.Trim()
                        Publisher       = $pb.Trim()
                        InstallLocation = $il.Trim()
                        DisplayIcon     = $di.Trim()
                        UninstallString = $un.Trim()
                        SourcePath      = $p
                    }
                }
        }
        catch {
            # swallow per path
        }
    }

    $items | Sort-Object Name,Version,Publisher -Unique
}

function fncGetProcessSnapshot {
    $procs = @()
    try {
        $procs = Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
            $p = $_
            $path = ""
            try { if (fncSafeHasProp $p "Path") { $path = fncToSafeString $p.Path } } catch {}
            [pscustomobject]@{
                Id   = $p.Id
                Name = fncToSafeString $p.ProcessName
                Path = $path
            }
        }
    }
    catch { }
    return $procs
}

function fncGetServiceSnapshot {
    $svcs = @()
    try {
        $svcs = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | ForEach-Object {
            [pscustomobject]@{
                Name        = fncToSafeString (fncSafeGetProp $_ "Name" "")
                DisplayName = fncToSafeString (fncSafeGetProp $_ "DisplayName" "")
                State       = fncToSafeString (fncSafeGetProp $_ "State" "")
                StartMode   = fncToSafeString (fncSafeGetProp $_ "StartMode" "")
                PathName    = fncToSafeString (fncSafeGetProp $_ "PathName" "")
                ProcessId   = fncSafeGetProp $_ "ProcessId" 0
            }
        }
    }
    catch { }
    return $svcs
}

function fncGetListeningPortsSnapshot {
    $listens = @()
    try {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $listens = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
                [pscustomobject]@{
                    LocalAddress  = fncToSafeString (fncSafeGetProp $_ "LocalAddress" "")
                    LocalPort     = fncSafeGetProp $_ "LocalPort" 0
                    OwningProcess = fncSafeGetProp $_ "OwningProcess" 0
                }
            }
        }
    }
    catch { }
    return $listens
}

function fncResolvePrimaryBinaryPath {
    param(
        [string]$DisplayIcon,
        [string]$InstallLocation
    )

    $candidate = (fncToSafeString $DisplayIcon).Trim()

    if (-not [string]::IsNullOrWhiteSpace($candidate)) {

        $c = $candidate.Trim().Trim('"')

        $c = $c -replace ',\d+$',''
        $c = $c -replace '\s+/.*$',''
        $c = $c -replace '\s+-.*$',''

        if ($c -match '^[a-zA-Z]+://') { return "" }
        if ($c -match ':\w+\.\w+$') { return "" }

        try {
            if (Test-Path -LiteralPath $c -ErrorAction Stop) {
                return $c
            }
        }
        catch {
            return ""
        }
    }

    $il = (fncToSafeString $InstallLocation).Trim()
    if (-not [string]::IsNullOrWhiteSpace($il)) {
        try {
            if (Test-Path -LiteralPath $il -ErrorAction Stop) {
                $exe = Get-ChildItem -LiteralPath $il -Filter *.exe -File -ErrorAction SilentlyContinue |
                    Sort-Object Length -Descending |
                    Select-Object -First 1
                if ($exe) { return $exe.FullName }
            }
        }
        catch {}
    }

    return ""
}

function fncGetSignatureStatus {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{ HasBinary=$false; Status="Unknown"; Unsigned=$false; Signer="" }
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ HasBinary=$false; Status="Missing"; Unsigned=$true; Signer="" }
    }

    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction SilentlyContinue
        if ($null -eq $sig) {
            return [pscustomobject]@{ HasBinary=$true; Status="Unknown"; Unsigned=$true; Signer="" }
        }

        $st = fncToSafeString (fncSafeGetProp $sig "Status" "Unknown")
        $signer = ""
        try {
            $sc = fncSafeGetProp $sig "SignerCertificate" $null
            if ($null -ne $sc) {
                $signer = fncToSafeString (fncSafeGetProp $sc "Subject" "")
            }
        } catch { }

        $unsigned = $true
        if ($st -eq "Valid") { $unsigned = $false }

        return [pscustomobject]@{
            HasBinary = $true
            Status    = $st
            Unsigned  = $unsigned
            Signer    = $signer
        }
    }
    catch {
        return [pscustomobject]@{ HasBinary=$true; Status="Error"; Unsigned=$true; Signer="" }
    }
}

function fncCorrelateRuntimeSignals {
    param(
        [Parameter(Mandatory=$true)]$Entry,
        [Parameter(Mandatory=$true)]$ProcSnap,
        [Parameter(Mandatory=$true)]$SvcSnap,
        [Parameter(Mandatory=$true)]$ListenSnap
    )

    $install = fncToSafeString (fncSafeGetProp $Entry "InstallLocation" "")
    $bin     = fncToSafeString (fncSafeGetProp $Entry "PrimaryBinary" "")

    $running = $false
    $matchedProcs = @()

    if (-not [string]::IsNullOrWhiteSpace($install)) {
        $il = $install.ToLowerInvariant()
        foreach ($p in $ProcSnap) {
            $pp = fncToSafeString (fncSafeGetProp $p "Path" "")
            if (-not [string]::IsNullOrWhiteSpace($pp)) {
                if ($pp.ToLowerInvariant().StartsWith($il)) {
                    $running = $true
                    $matchedProcs += $p
                }
            }
        }
    }

    if (-not $running -and -not [string]::IsNullOrWhiteSpace($bin)) {
        $bn = $bin.ToLowerInvariant()
        foreach ($p in $ProcSnap) {
            $pp = fncToSafeString (fncSafeGetProp $p "Path" "")
            if (-not [string]::IsNullOrWhiteSpace($pp) -and ($pp.ToLowerInvariant() -eq $bn)) {
                $running = $true
                $matchedProcs += $p
            }
        }
    }

    $svcMatches = @()
    foreach ($s in $SvcSnap) {
        $pathName = fncToSafeString (fncSafeGetProp $s "PathName" "")
        if ([string]::IsNullOrWhiteSpace($pathName)) { continue }

        $pn = $pathName.ToLowerInvariant()
        $hit = $false

        if (-not [string]::IsNullOrWhiteSpace($bin)) {
            if ($pn -like ("*{0}*" -f ($bin.ToLowerInvariant()))) { $hit = $true }
        }
        if (-not $hit -and -not [string]::IsNullOrWhiteSpace($install)) {
            if ($pn -like ("*{0}*" -f ($install.ToLowerInvariant()))) { $hit = $true }
        }

        if ($hit) { $svcMatches += $s }
    }

    $svcState = "None"
    if ($svcMatches.Count -gt 0) {
        $anyRunning = $false
        foreach ($s in $svcMatches) {
            if ((fncToSafeString (fncSafeGetProp $s "State" "")) -eq "Running") { $anyRunning = $true; break }
        }
        $svcState = if ($anyRunning) { "Running" } else { "Present" }
    }

    $pids = @()
    foreach ($p in $matchedProcs) {
        $apppid = fncSafeGetProp $p "Id" 0
        if ($apppid -gt 0) { $pids += $apppid }
    }
    foreach ($s in $svcMatches) {
        $spid = fncSafeGetProp $s "ProcessId" 0
        if ($spid -gt 0) { $pids += $spid }
    }
    $pids = @($pids | Sort-Object -Unique)

    $ports = @()
    if ($pids.Count -gt 0) {
        foreach ($l in $ListenSnap) {
            $op = fncSafeGetProp $l "OwningProcess" 0
            if ($pids -contains $op) {
                $lp = fncSafeGetProp $l "LocalPort" 0
                if ($lp -gt 0) { $ports += $lp }
            }
        }
    }
    $ports = @($ports | Sort-Object -Unique)

    return [pscustomobject]@{
        Running         = $running
        MatchedProcs    = $matchedProcs
        ServiceState    = $svcState
        ServiceMatches  = $svcMatches
        ListeningPorts  = $ports
        IsListening     = ($ports.Count -gt 0)
    }
}

function fncComputeExploitScore {
    param(
        [double]$BaseCvss,
        [bool]$HasKev,
        [bool]$Running,
        [bool]$Listening,
        [bool]$Unsigned,
        [bool]$Eol,
        [int]$OffensiveWeight
    )

    if ($Eol) { return 100 }

    $score = 0.0

    if ($BaseCvss -lt 0) { $BaseCvss = 0 }
    if ($BaseCvss -gt 10) { $BaseCvss = 10 }
    $score += ($BaseCvss * 7.0)

    if ($HasKev)    { $score += 20 }
    if ($Listening) { $score += 15 }
    if ($Running)   { $score += 10 }
    if ($Unsigned)  { $score += 10 }

    # Add offensive tool influence
    $score += $OffensiveWeight

    if ($score -gt 100) { $score = 100 }
    return [int][math]::Round($score, 0)
}

function fncGetReconInstalledSoftwareAdv {

    [CmdletBinding()]
    param(
        [switch]$ExcludePerUser,

        [int]$NvdDelayMs = 900,
        [int]$NvdMaxCpeCandidates = 5,
        [int]$NvdMaxCvePages = 3,
        [int]$NvdResultsPerPage = 200,

        [int]$KevMaxAgeHours = 24,
        [switch]$ForceKevRefresh,

        [switch]$ReturnObjects
    )

    $verboseMode = $false
    if ($global:config -and $global:config.DEBUG) { $verboseMode = $true }

    if (Get-Command fncSafeSectionHeader -ErrorAction SilentlyContinue) {
        fncSafeSectionHeader "Installed Software Recon (Advanced)"
    }

    fncInitReconSoftwareCache

    $enableNvd = $false
    $useCache  = $false
    $enableKev = $false
    $noNetwork = $false
    $nvdApiKey = ""

    if (fncAskYesNo "Enable NVD & KEV vulnerability enrichment?" "N") {

        $enableNvd = $true
        $enableKev = $true

        if (fncAskYesNo "Use existing NVD cache only (no API calls if cache exists)?" "Y") {
            $useCache = $true
        }

        if (-not $useCache) {
            if (fncAskYesNo "Use NVD API key for higher rate limits?" "N") {
                $nvdApiKey = Read-Host "Enter NVD API key"
            }
        }
    }
    else {
        if (fncAskYesNo "Run in offline mode?" "Y") {
            $noNetwork = $true
        }
    }

    if ($noNetwork) {
        $enableNvd = $false
        $useCache  = $true
    }

    $raw = fncGetInstalledSoftwareFromRegistry -ExcludePerUser:$ExcludePerUser
    $entries = @()

    foreach ($r in @($raw)) {

        $name = fncToSafeString (fncSafeGetProp $r "Name" "")
        if ([string]::IsNullOrWhiteSpace($name)) { continue }

        $ver = fncToSafeString (fncSafeGetProp $r "Version" "")
        $pub = fncToSafeString (fncSafeGetProp $r "Publisher" "")
        $il  = fncToSafeString (fncSafeGetProp $r "InstallLocation" "")
        $di  = fncToSafeString (fncSafeGetProp $r "DisplayIcon" "")
        $un  = fncToSafeString (fncSafeGetProp $r "UninstallString" "")

        $primary = fncResolvePrimaryBinaryPath -DisplayIcon $di -InstallLocation $il
        $sig = fncGetSignatureStatus -Path $primary
        $eol = fncDetectEolHeuristic -Name $name -Version $ver

        $offResult = fncIsOffensiveTool `
            -Name $name `
            -Publisher $pub `
            -InstallLocation $il `
            -DisplayIcon $di `
            -UninstallString $un `
            -PrimaryBinary $primary      

        $entries += [pscustomobject]@{
            Name            = $name
            Version         = $ver
            Publisher       = $pub
            InstallLocation = $il
            DisplayIcon     = $di
            UninstallString = $un
            PrimaryBinary   = $primary

            Unsigned        = [bool](fncSafeGetProp $sig "Unsigned" $false)
            SignatureStatus = fncToSafeString (fncSafeGetProp $sig "Status" "Unknown")
            Signer          = fncToSafeString (fncSafeGetProp $sig "Signer" "")

            EOL             = [bool](fncSafeGetProp $eol "Eol" $false)

            OffensiveTool       = [bool]$offResult.Matched
            OffensiveCategories = $offResult.Categories
            OffensiveWeight     = [int]$offResult.TotalWeight

            PivotCapable    = [bool](fncIsPivotCapable `
                -Name $name `
                -Publisher $pub `
                -InstallLocation $il `
                -DisplayIcon $di `
                -UninstallString $un `
                -PrimaryBinary $primary)

            Running         = $false
            ServiceState    = "Unknown"
            ListeningPorts  = @()

            NvdCpe          = ""
            TopCvss         = 0.0
            TopCveId        = ""
            Kev             = $false
            Vulnerabilities = @()
            ExploitScore    = 0
        }
    }

    if ($verboseMode) {
        fncSafePrintMessage ("Enumerated {0} installed applications." -f (fncSafeCount $entries)) "debug"
    }

    if (Get-Command fncSafeSectionHeader -ErrorAction SilentlyContinue) {
        fncPrintMessage "" "plain"
        fncSafeSectionHeader ("Installed Applications ({0} detected)" -f (fncSafeCount $entries))
        Write-Host "Note: This initial list is based on registry enumeration and heuristics. Runtime signals and vulnerability data will be correlated in subsequent steps." -ForegroundColor Yellow
        Write-Host "      The Vulnerability and Exploitability scan can be time-consuming if NVD enrichment is enabled." -ForegroundColor Yellow
        fncPrintMessage "" "plain"
    }
    
    if ((fncSafeCount $entries) -gt 0) {
        $entries |
            Sort-Object -Property Name |
            Select-Object Name,Version,Publisher |
            Format-Table -AutoSize
    } else {
        fncSafePrintMessage "No installed applications detected." "warning"
    }

    $procSnap   = fncGetProcessSnapshot
    $svcSnap    = fncGetServiceSnapshot
    $listenSnap = fncGetListeningPortsSnapshot

    foreach ($e in $entries) {
        $rt = fncCorrelateRuntimeSignals -Entry $e -ProcSnap $procSnap -SvcSnap $svcSnap -ListenSnap $listenSnap
        $e.Running = [bool](fncSafeGetProp $rt "Running" $false)
        $e.ServiceState = fncToSafeString (fncSafeGetProp $rt "ServiceState" "None")
        $e.ListeningPorts = @((fncSafeGetProp $rt "ListeningPorts" @()) | Sort-Object -Unique)
    }

    $kev = $null
    $kevLookup = @{}

    if ($enableKev) {

        $kev = fncGetKevData `
            -CacheRoot $script:ReconSoftware.CacheRoot `
            -MaxAgeHours $KevMaxAgeHours `
            -ForceRefresh:$ForceKevRefresh `
            -NoNetwork:$noNetwork

        $kevLookup = fncSafeGetProp $kev "Lookup" @{}

        if ($verboseMode) {
            fncSafePrintMessage ("KEV entries loaded: {0}" -f (fncSafeCount $kevLookup.Keys)) "debug"
        }
    }

    $ordered = $entries | Sort-Object `
        @{Expression={ if ($_.EOL) { 1 } else { 0 } }; Descending=$true},
        @{Expression={ if ($_.Running) { 1 } else { 0 } }; Descending=$true},
        @{Expression={ if ((fncSafeCount $_.ListeningPorts) -gt 0) { 1 } else { 0 } }; Descending=$true},
        @{Expression={ if ($_.OffensiveTool -or $_.PivotCapable) { 1 } else { 0 } }; Descending=$true},
        @{Expression={ if ($_.Unsigned) { 1 } else { 0 } }; Descending=$true},
        @{Expression={ $_.Name }; Descending=$false}

    if ($enableNvd) {

        $total = fncSafeCount $ordered
        $index = 0

        foreach ($e in $ordered) {

            $index++
            if ($verboseMode) {
                fncSafePrintMessage ("[{0}/{1}] Processing {2}" -f $index,$total,$e.Name) "debug"
            }

            $vp = fncExtractVendorProductFromEntry -Name $e.Name -Publisher $e.Publisher

            $vendor = fncToSafeString (fncSafeGetProp $vp "Vendor" "")
            $product= fncToSafeString (fncSafeGetProp $vp "Product" "")

            $cpeCandidates = @()

            if (-not [string]::IsNullOrWhiteSpace($product)) {

                $cpeCachePath = Join-Path $script:ReconSoftware.CacheRoot "cpe_$($vendor)_$($product).json"

                if (fncIsCacheFresh -Path $cpeCachePath -MaxAgeHours 24) {

                    if ($verboseMode) {
                        fncSafePrintMessage "Using cached CPE data for $product" "debug"
                    }

                    $cpeCandidates = Get-Content $cpeCachePath | ConvertFrom-Json
                }
                else {

                    $cpeCandidates = fncResolveCpeCandidates `
                        -Vendor $vendor `
                        -Product $product `
                        -CacheRoot $script:ReconSoftware.CacheRoot `
                        -ApiKey $nvdApiKey `
                        -MaxCandidates $NvdMaxCpeCandidates `
                        -DelayMs $NvdDelayMs

                    $cpeCandidates | ConvertTo-Json | Set-Content $cpeCachePath
                }
            }
            else {
                if ($verboseMode) {
                    fncSafePrintMessage "  Skipping NVD lookup (empty product after normalisation)." "debug"
                }
            }

            $cpeCandidates = @($cpeCandidates)

            $picked = ""
            if ((fncSafeCount $cpeCandidates) -gt 0) {
                $picked = fncToSafeString $cpeCandidates[0]
                $e.NvdCpe = $picked
            }

            $cves = @()

            if (-not [string]::IsNullOrWhiteSpace($picked)) {
                $sanitisedCpe = $picked `
                    -replace '[\\/:*?"<>|]', '_' `
                    -replace '\*', 'any' `
                    -replace '\s+', '_' `
                    -replace '_+', '_'

                $cveCachePath = Join-Path $script:ReconSoftware.CacheRoot "cve_$sanitisedCpe.json"

                if (fncIsCacheFresh -Path $cveCachePath -MaxAgeHours 24) {

                    if ($verboseMode) {
                        fncSafePrintMessage "Using cached CVE data for $picked" "debug"
                    }

                    $cves = Get-Content $cveCachePath | ConvertFrom-Json
                }
                else {

                    $cves = fncGetNvdCvesForCpe `
                        -CpeName $picked `
                        -CacheRoot $script:ReconSoftware.CacheRoot `
                        -ApiKey $nvdApiKey `
                        -ResultsPerPage $NvdResultsPerPage `
                        -MaxPages $NvdMaxCvePages `
                        -DelayMs $NvdDelayMs

                    $cves | ConvertTo-Json -Depth 6 | Set-Content $cveCachePath
                }
            }

            $cves = @($cves)

            if ($verboseMode) {
                fncSafePrintMessage ("  CVEs retrieved: {0}" -f (fncSafeCount $cves)) "debug"
            }

            $topCvss = 0.0
            $topCveId = ""
            $hasKev = $false

            $sortedCves = @($cves | Sort-Object -Property @{Expression='CvssScore'; Descending=$true})

            foreach ($cv in $sortedCves) {

                $cveId = fncToSafeString (fncSafeGetProp $cv "CveId" "")
                if ([string]::IsNullOrWhiteSpace($cveId)) { continue }

                if ([string]::IsNullOrWhiteSpace($topCveId)) {
                    $topCveId = $cveId
                    $topCvss  = [double](fncSafeGetProp $cv "CvssScore" 0.0)
                }

                if ($enableKev -and $kevLookup -and ($kevLookup.ContainsKey($cveId))) {
                    $hasKev = $true
                    $cv | Add-Member -MemberType NoteProperty -Name Kev -Value $true -Force
                }
            }

            $e.Kev = $hasKev
            $e.TopCvss = $topCvss
            $e.TopCveId = $topCveId
            $e.Vulnerabilities = @($sortedCves | Select-Object -First 25)

            $e.ExploitScore = fncComputeExploitScore `
                -BaseCvss $e.TopCvss `
                -HasKev $e.Kev `
                -Running $e.Running `
                -Listening ((fncSafeCount $e.ListeningPorts) -gt 0) `
                -Unsigned $e.Unsigned `
                -Eol $e.EOL `
                -OffensiveWeight $e.OffensiveWeight
            # -------------------------------------------------
            # Findings Generation
            # -------------------------------------------------
            if ($e.EOL) {

                fncAddFinding `
                    -Id ("EOL_" + ($e.Name -replace '[^A-Za-z0-9]','')) `
                    -Category "End Of Life Software" `
                    -Title "End-of-Life Software Detected" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("{0} {1} is End-of-Life and no longer receives security updates." -f $e.Name,$e.Version) `
                    -Recommendation "Upgrade or remove this software immediately."
            }

            if ($e.Kev -and -not [string]::IsNullOrWhiteSpace($e.TopCveId)) {

                fncAddFinding `
                    -Id ("KEV_" + $e.TopCveId) `
                    -Category "Known Exploited Vulnerability" `
                    -Title "Actively Exploited Vulnerability Present" `
                    -Severity "Critical" `
                    -Status "Detected" `
                    -Message ("{0} affected by {1} (CVSS {2}) which is in CISA KEV list." -f $e.Name,$e.TopCveId,$e.TopCvss) `
                    -Recommendation "Patch immediately. This vulnerability is known to be exploited in the wild."
            }

            elseif ($e.TopCvss -ge 8.0) {

                fncAddFinding `
                    -Id ("HIGHCVSS_" + $e.TopCveId) `
                    -Category "High Severity Vulnerability" `
                    -Title "High CVSS Vulnerability Detected" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("{0} vulnerable to {1} (CVSS {2})." -f $e.Name,$e.TopCveId,$e.TopCvss) `
                    -Recommendation "Apply vendor patches or mitigation guidance."
            }

            if ($e.OffensiveTool) {

                $cats = ($e.OffensiveCategories -join ",")

                fncAddFinding `
                    -Id ("OFFTOOL_" + ($e.Name -replace '[^A-Za-z0-9]','')) `
                    -Category "Offensive Tooling" `
                    -Title "Offensive Security Tool Detected" `
                    -Severity "Medium" `
                    -Status "Detected" `
                    -Message ("{0} identified as offensive tooling (Categories: {1})." -f $e.Name,$cats) `
                    -Recommendation "Validate business justification or remove if unauthorised."
            }

            if ($e.PivotCapable) {

                fncAddFinding `
                    -Id ("PIVOT_" + ($e.Name -replace '[^A-Za-z0-9]','')) `
                    -Category "Lateral Movement Risk" `
                    -Title "Pivot-Capable Tool Installed" `
                    -Severity "Medium" `
                    -Status "Detected" `
                    -Message ("{0} enables remote access or tunnelling." -f $e.Name) `
                    -Recommendation "Ensure MFA and strong access controls are enforced."
            }

            if ($e.Unsigned -and -not $e.OffensiveTool) {

                fncAddFinding `
                    -Id ("UNSIGNED_" + ($e.Name -replace '[^A-Za-z0-9]','')) `
                    -Category "Binary Integrity" `
                    -Title "Unsigned Executable Detected" `
                    -Severity "Medium" `
                    -Status "Detected" `
                    -Message ("Primary binary for {0} is unsigned." -f $e.Name) `
                    -Recommendation "Verify binary integrity and validate vendor authenticity."
            }

            if ($e.ExploitScore -ge 70 -and -not $e.EOL -and -not $e.Kev) {

                fncAddFinding `
                    -Id ("EXPSCORE_" + ($e.Name -replace '[^A-Za-z0-9]','')) `
                    -Category "Exploitability Risk" `
                    -Title "Elevated Exploitability Score" `
                    -Severity "High" `
                    -Status "Detected" `
                    -Message ("{0} scored {1}/100 on exploitability index." -f $e.Name,$e.ExploitScore) `
                    -Recommendation "Investigate and prioritise remediation."
            }
            
            if ($verboseMode) {
                fncSafePrintMessage ("  ExploitScore: {0}" -f $e.ExploitScore) "debug"
            }
        }

    } else {

        foreach ($e in $entries) {
            $e.ExploitScore = fncComputeExploitScore `
                -BaseCvss 0.0 `
                -HasKev $false `
                -Running $e.Running `
                -Listening ((fncSafeCount $e.ListeningPorts) -gt 0) `
                -Unsigned $e.Unsigned `
                -Eol $e.EOL
                
        }
    }

    function fncWriteReconSoftwareLine {
        param(
            [Parameter(Mandatory=$true)]$Entry
        )
        # Column widths
        $W_NAME  = 32
        $W_VER   = 15
        $W_PUB   = 32
        $W_CLASS = 26
        $W_RUN   = 15
        $W_PORT  = 15
        $W_CVSS  = 15
        $W_SCORE = 15
        $classification = "INFO"
        $fg = [System.ConsoleColor]::Gray

        if ($Entry.EOL) {
            $classification = "!!! EOL !!!"
            $fg = [System.ConsoleColor]::Red
        }
        elseif ($Entry.Kev) {
            $classification = "!!!! KEV !!!!"
            $fg = [System.ConsoleColor]::Red
        }
        elseif ($Entry.TopCvss -ge 8.0) {
            $classification = "!! HIGH CVSS !!"
            $fg = [System.ConsoleColor]::DarkYellow
        }
        elseif ($Entry.OffensiveTool -and $Entry.PivotCapable) {
            $classification = "! OFFENSIVE + PIVOT TOOL !"
            $fg = [System.ConsoleColor]::Yellow
        }
        elseif ($Entry.OffensiveTool) {
            $cats = ($Entry.OffensiveCategories -join ",")
            $classification = "! OFFENSIVE [$cats] !"
        }
        elseif ($Entry.PivotCapable) {
            $classification = "! PIVOT CAPABLE !"
            $fg = [System.ConsoleColor]::Yellow
        }
        elseif ($Entry.Unsigned) {
            $classification = "UNSIGNED"
            $fg = [System.ConsoleColor]::Cyan
        }

        $ports = ""
        if ((fncSafeCount $Entry.ListeningPorts) -gt 0) {
            $ports = ($Entry.ListeningPorts -join ",")
        }

        $line =
            (fncFormatColumn $Entry.Name $W_NAME) +
            (fncFormatColumn $Entry.Version $W_VER) +
            (fncFormatColumn $Entry.Publisher $W_PUB) +
            (fncFormatColumn $classification $W_CLASS) +
            (fncFormatColumn ("Run:" + $Entry.Running) $W_RUN) +
            (fncFormatColumn ("Ports:" + $ports) $W_PORT) +
            (fncFormatColumn ("CVSS:" + $Entry.TopCvss) $W_CVSS) +
            (fncFormatColumn ("Score:" + $Entry.ExploitScore) $W_SCORE)

        Write-Host $line -ForegroundColor $fg
    }

    function fncWriteHighCvssDetails {
        param(
            [Parameter(Mandatory=$true)]$Entry
        )

        if (-not $Entry.Vulnerabilities) { return }

        $highCves = @(
            $Entry.Vulnerabilities | Where-Object {
                $_.CvssScore -ge 8.0
            }
        )

        if ($highCves.Count -eq 0) { return }

        foreach ($cv in $highCves) {

            $cveId = fncToSafeString (fncSafeGetProp $cv "CveId" "")
            $cvss  = [double](fncSafeGetProp $cv "CvssScore" 0.0)

            $fg = [System.ConsoleColor]::DarkYellow
            if ($cvss -ge 9.0) {
                $fg = [System.ConsoleColor]::Red
            }

            $detail = ("    -> {0}  (CVSS: {1})" -f $cveId, $cvss)

            Write-Host $detail -ForegroundColor $fg
        }
    }

    fncShowReconColourKey
    fncSafeSectionHeader "Installed Software Inventory"

    $sortedEntries = @(
        $entries | Sort-Object `
            @{Expression={ if ($_.EOL) { 1 } else { 0 } }; Descending=$true},
            @{Expression={ if ($_.Kev) { 1 } else { 0 } }; Descending=$true},
            @{Expression={ if ($_.TopCvss -ge 8.0) { 1 } else { 0 } }; Descending=$true},
            @{Expression={ if ($_.OffensiveTool -and $_.PivotCapable) { 1 } else { 0 } }; Descending=$true},
            @{Expression={ if ($_.OffensiveTool) { 1 } else { 0 } }; Descending=$true},
            @{Expression={ if ($_.PivotCapable) { 1 } else { 0 } }; Descending=$true},
            @{Expression={ if ($_.Unsigned) { 1 } else { 0 } }; Descending=$true},
            @{Expression='ExploitScore'; Descending=$true},
            @{Expression='Name'; Descending=$false}
    )

    if ((fncSafeCount $sortedEntries) -gt 0) {
        foreach ($e in $sortedEntries) {

            fncWriteReconSoftwareLine -Entry $e

            if ($e.TopCvss -ge 8.0) {
                fncWriteHighCvssDetails -Entry $e
            }
        }
    }
    else {
        fncSafePrintMessage "No inventory entries to display." "warning"
    }

    $inv = $sortedEntries | ForEach-Object {
        [pscustomobject]@{
            Name           = $_.Name
            Version        = $_.Version
            Publisher      = $_.Publisher
            Running        = $_.Running
            ListeningPorts = if ((fncSafeCount $_.ListeningPorts) -gt 0) { $_.ListeningPorts -join "," } else { "" }
            Unsigned       = $_.Unsigned
            EOL            = $_.EOL
            Kev            = $_.Kev
            TopCvss        = $_.TopCvss
            TopCveId       = $_.TopCveId
            OffensiveTool       = $_.OffensiveTool
            OffensiveCategories = $_.OffensiveCategories
            OffensiveWeight     = $_.OffensiveWeight
            PivotCapable   = $_.PivotCapable
            ExploitScore   = $_.ExploitScore
        }
    }

    fncSafeSectionHeader "High Risk Vulnerabilities (Filtered)"

    $high = @(
        $sortedEntries | Where-Object {
            $_.EOL -or $_.Kev -or $_.TopCvss -ge 8.0 -or $_.OffensiveTool -or $_.PivotCapable
        }
    )

    if ((fncSafeCount $high) -gt 0) {
        foreach ($e in $high) {

            fncWriteReconSoftwareLine -Entry $e

            if ($e.TopCvss -ge 8.0) {
                fncWriteHighCvssDetails -Entry $e
            }
        }
    }
    else {
        fncSafePrintMessage "No high risk items matched (KEV / CVSS>=8 / EOL)." "success"
    }

    if ($ReturnObjects) {
        return [pscustomobject]@{
            Inventory  = $inv
            HighRisk   = $high
            RawEntries = $entries
            KevMeta    = if ($enableKev) { $kev } else { $null }
        }
    }
}

Export-ModuleMember -Function @(
    "fncGetReconInstalledSoftwareAdv"
)