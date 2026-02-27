# ================================================================
# Module  : Registry.psm1
# ================================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function fncNotifyTestModuleLoaded {

    param(
        [Parameter(Mandatory)][psobject]$TestMeta,
        [string]$SourcePath = "",
        [bool]$IsNew = $false
    )

    try {

        $name   = fncSafeString $TestMeta.Name
        $catObj = $TestMeta.Category

        if ($catObj -is [psobject] -and $catObj.PSObject.Properties.Name -contains "Primary") {
            $cat = $catObj.Primary
        }
        else {
            $cat = fncSafeString $catObj
        }
        $scopes = (@(fncSafeArray $TestMeta.Scopes) -join ", ")

        $debugMode = $false
        try { $debugMode = [bool]$global:ProberState.Config.DEBUG } catch {}

        if ($debugMode -or $IsNew) {

            if (fncCommandExists "fncPrintMessage") {

                if ($IsNew) {
                    fncPrintMessage ("New Test Module Loaded: {0}" -f $name) "success"
                }
                else {
                    fncPrintMessage ("Loaded Test Module: {0}" -f $name) "debug"
                }

                Write-Host ("    > Category : {0}" -f $cat)
                Write-Host ("    > Scopes   : {0}" -f $scopes)

                if ($SourcePath) {
                    Write-Host ("    > Path     : {0}" -f $SourcePath)
                }
            }
            else {
                Write-Host ("[+] Loaded Test Module: {0}" -f $name)
            }
        }

        try {
            if (fncCommandExists "fncLog") {
                fncLog "INFO" ("Test module registered: {0} [{1}] ({2})" -f $name,$cat,$scopes)
            }
        } catch {}

    }
    catch {}
}

function fncNotifyTestModuleFailed {

    param(
        [string]$Name,
        [string]$Reason,
        [string]$Path
    )

    fncPrintMessage ("Test module failed validation: {0}" -f $Name) "warning"

    Write-Host ("    > Reason : {0}" -f $Reason)
    if ($Path) {
        Write-Host ("    > Path   : {0}" -f $Path)
    }

    try { fncLog "WARN" ("Test module load failure: {0} - {1}" -f $Name,$Reason) } catch {}
}

function fncRegisterTest {
    param(
        [Parameter(Mandatory=$true)][string]$Id,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Function,

        [object]$Category = "Uncategorised",

        [ValidateSet("All","Workstation","Server","Domain","DMZ","Cloud","SaaS","Container","Network","WebApp")]
        [string[]]$Scopes = @("All"),

        [bool]$Enabled = $true,
        [bool]$RequiresAdmin = $false,

        [string]$Description = "",

        # NEW
        [int]$SchemaVersion = 1,
        [object]$Mappings = $null,
        [object]$References = $null
    )

    if ($null -eq $global:ProberState) {
        throw "ProberState is not initialised. Call fncBootstrapProberState first."
    }

    if ($null -eq $global:ProberState.Tests) {
        $global:ProberState.Tests = @()
    }

    # Remove existing test with same ID
    $global:ProberState.Tests = @(
        $global:ProberState.Tests |
        Where-Object { (fncSafeString $_.Id) -ne (fncSafeString $Id) }
    )

    # -------------------------
    # Normalise Category
    # -------------------------
    $normalisedCategory = "Uncategorised"

    if ($Category -is [psobject] -and $Category.PSObject.Properties.Name -contains "Primary") {

        $primary = fncSafeString $Category.Primary
        if ([string]::IsNullOrWhiteSpace($primary)) {
            $primary = "Uncategorised"
        }

        $subs = @()
        if ($Category.PSObject.Properties.Name -contains "Subcategories") {
            $subs = @(fncSafeArray $Category.Subcategories)
        }

        $normalisedCategory = [pscustomobject]@{
            Primary       = $primary
            Subcategories = $subs
        }
    }
    else {
        $c = fncSafeString $Category
        if (-not [string]::IsNullOrWhiteSpace($c)) {
            $normalisedCategory = $c
        }
    }

    # -------------------------
    # Store Test
    # -------------------------
    $global:ProberState.Tests += [pscustomobject]@{
        SchemaVersion = [int]$SchemaVersion
        Id            = (fncSafeString $Id)
        Name          = (fncSafeString $Name)
        Function      = (fncSafeString $Function)
        Category      = $normalisedCategory
        Scopes        = @(fncSafeArray $Scopes)
        Enabled       = [bool]$Enabled
        RequiresAdmin = [bool]$RequiresAdmin
        Description   = (fncSafeString $Description)

        # NEW
        Mappings      = $Mappings
        References    = $References
    }

    if (-not ($global:ProberState.PSObject.Properties.Name -contains "_LoadedTestIds")) {
        $global:ProberState | Add-Member -NotePropertyName "_LoadedTestIds" -NotePropertyValue @()
    }

    if ($global:ProberState._LoadedTestIds -notcontains $Id) {
        $global:ProberState._LoadedTestIds += $Id
    }
}

function fncRescanTestModules {

    try { fncPrintMessage "Rescanning test modules..." "info" } catch {}

    $previousIds = @()
    try {
        if ($global:ProberState -and $global:ProberState.Tests) {
            $previousIds = @(
                fncSafeArray (
                    $global:ProberState.Tests |
                    ForEach-Object { fncSafeString $_.Id }
                )
            )
        }
    } catch {}

    try {

        if ($global:ProberState) {
            $global:ProberState.Tests = @()
        }

    } catch {}

    try {

        $loaded = Get-Module | Where-Object {
            $_.Path -and $_.Path -match "\\Tests\\"
        }

        foreach ($m in $loaded) {
            try {
                Remove-Module $m.Name -Force -ErrorAction SilentlyContinue
            } catch {}
        }

    } catch {}

    try {

        fncDiscoverTests

        $currentTests = fncSafeArray $global:ProberState.Tests
        $count = fncSafeCount $currentTests

        $newTests = @(
            $currentTests |
            Where-Object {
                $previousIds -notcontains (fncSafeString $_.Id)
            }
        )

        if ((fncSafeCount $newTests) -gt 0) {

            try { fncPrintMessage "New test modules detected:" "success" } catch {}

            foreach ($t in $newTests) {
                try {
                    Write-Host ("   + {0}" -f (fncSafeString $t.Name))
                } catch {}
            }

            Write-Host ""
        }

        fncPrintMessage ("Rescan complete. Tests loaded: {0}" -f $count) "success"

        try {
            if (fncCommandExists "fncLog") {
                fncLog "INFO" ("Test module rescan completed. Total tests: {0}, New tests: {1}" -f $count,(fncSafeCount $newTests))
            }
        } catch {}

    }
    catch {

        try { fncPrintMessage ("Rescan failed: {0}" -f $_.Exception.Message) "error" } catch {}

        try {
            if (fncCommandExists "fncLog") {
                fncLogException $_.Exception "fncRescanTestModules"
            }
        } catch {}
    }
}

function fncGetTestsRoot {

    try {

        if (-not (Get-Command -Name fncGetScriptDirectory -ErrorAction SilentlyContinue)) {
            return $null
        }

        $modulesRoot = fncGetScriptDirectory
        if ([string]::IsNullOrWhiteSpace([string]$modulesRoot)) { return $null }

        $projectRoot = Split-Path -Path $modulesRoot -Parent
        if ([string]::IsNullOrWhiteSpace([string]$projectRoot)) { return $null }

        $testsPath = Join-Path -Path $projectRoot -ChildPath "Tests"

        try { if (fncCommandExists "fncLog") { fncLog "DEBUG" ("Resolved Tests root: {0}" -f $testsPath) } } catch {}

        return $testsPath
    }
    catch {
        try { if (fncCommandExists "fncLog") { fncLogException $_.Exception "fncGetTestsRoot" } } catch {}
        return $null
    }
}

function fncImportTestScript {
    param(
        [Parameter(Mandatory=$true)][string]$FolderPath
    )

    try { if (fncCommandExists "fncLog") { fncLog "DEBUG" ("Importing test script from: {0}" -f $FolderPath) } } catch {}

    $moduleFile = Get-ChildItem -LiteralPath $FolderPath -Filter "test.psm1" -File -ErrorAction SilentlyContinue | Select-Object -First 1
    $scriptFile = Get-ChildItem -LiteralPath $FolderPath -Filter "test.ps1"  -File -ErrorAction SilentlyContinue | Select-Object -First 1

    $target = $null
    if ($moduleFile) { $target = $moduleFile.FullName }
    elseif ($scriptFile) { $target = $scriptFile.FullName }

    if ([string]::IsNullOrWhiteSpace([string]$target)) {
        try { fncPrintMessage ("No test.ps1/test.psm1 found in: {0}" -f $FolderPath) "warning" } catch {}
        try { if (fncCommandExists "fncLog") { fncLog "WARN" ("No test script found in folder: {0}" -f $FolderPath) } } catch {}
        return $false
    }

    try {
        Import-Module -Name $target -Force -ErrorAction Stop | Out-Null
        try { if (fncCommandExists "fncLog") { fncLog "INFO" ("Imported test script: {0}" -f $target) } } catch {}
        return $true
    }
    catch {
        try { fncPrintMessage ("Failed importing test script: {0}" -f $target) "error" } catch {}
        try { if (fncCommandExists "fncLog") { fncLogException $_.Exception "fncImportTestScript" } } catch {}
        return $false
    }
}

function fncResolveScopes {
    param(
        [AllowNull()][object]$Scopes
    )

    if ($null -eq $Scopes) { return @("All") }

    $s = @()
    if ($Scopes -is [string]) { $s = @([string]$Scopes) }
    else { $s = @(fncSafeArray $Scopes) }

    $s = @(
        $s |
        ForEach-Object { fncSafeString $_ } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    if ((fncSafeCount $s) -eq 0) { return @("All") }
    if ($s -contains "Shared" -or $s -contains "All") { return @("All") }

    return @($s)
}

function fncDiscoverTests {

    $loadedCount = 0
    $failedCount = 0

    $debugMode = $false
    try {
        if ($global:ProberState -and
            $global:ProberState.PSObject.Properties.Name -contains "Config" -and
            $global:ProberState.Config -and
            $global:ProberState.Config.PSObject.Properties.Name -contains "DEBUG") {

            $debugMode = [bool]$global:ProberState.Config.DEBUG
        }
    } catch {}

    $existingIds = @()
    try {
        if ($global:ProberState -and $global:ProberState.Tests) {
            $existingIds = @(
                fncSafeArray (
                    $global:ProberState.Tests |
                    ForEach-Object { fncSafeString $_.Id }
                )
            )
        }
    } catch {}

    try { if (fncCommandExists "fncLog") { fncLog "INFO" "Starting dynamic test discovery" } } catch {}

    $testsRoot = fncGetTestsRoot

    if ([string]::IsNullOrWhiteSpace([string]$testsRoot) -or -not (Test-Path -LiteralPath $testsRoot)) {
        try { fncPrintMessage ("Tests directory not found: {0}" -f (fncSafeString $testsRoot)) "warning" } catch {}
        return
    }

    $jsonFiles = Get-ChildItem -LiteralPath $testsRoot -Filter "test.json" -File -Recurse -ErrorAction SilentlyContinue

    foreach ($jf in (fncSafeArray $jsonFiles)) {

        $folder   = $jf.Directory.FullName
        $jsonPath = $jf.FullName

        # -----------------------------
        # Load JSON
        # -----------------------------
        $meta = $null
        try {
            $meta = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
        }
        catch {
            try { fncPrintMessage ("Invalid JSON: {0}" -f $jsonPath) "error" } catch {}
            continue
        }

        if (-not $meta) { continue }

        # -----------------------------
        # Required fields
        # -----------------------------
        $id = ""
        $nm = ""
        $fn = ""

        if ($meta.PSObject.Properties.Name -contains "Id")        { $id = fncSafeString $meta.Id }
        if ($meta.PSObject.Properties.Name -contains "Name")      { $nm = fncSafeString $meta.Name }
        if ($meta.PSObject.Properties.Name -contains "Function")  { $fn = fncSafeString $meta.Function }

        if ([string]::IsNullOrWhiteSpace($id) -or
            [string]::IsNullOrWhiteSpace($nm) -or
            [string]::IsNullOrWhiteSpace($fn)) {

            try { fncPrintMessage ("Test metadata missing required fields: {0}" -f $jsonPath) "error" } catch {}
            continue
        }

        # -----------------------------
        # Import Script
        # -----------------------------
        if (-not (fncImportTestScript -FolderPath $folder)) {
            fncNotifyTestModuleFailed $nm "Script import failed" $folder
            $failedCount++
            continue
        }

        if (-not (Get-Command -Name $fn -ErrorAction SilentlyContinue)) {
            try { fncPrintMessage ("Function not found after import: {0} ({1})" -f $fn,$jsonPath) "error" } catch {}
            continue
        }

        # -----------------------------
        # Safe SchemaVersion
        # -----------------------------
        $schema = 1
        if ($meta.PSObject.Properties.Name -contains "SchemaVersion") {
            try { $schema = [int]$meta.SchemaVersion } catch { $schema = 1 }
        }

        # -----------------------------
        # Safe Category
        # -----------------------------
        $cat = "Uncategorised"

        if ($meta.PSObject.Properties.Name -contains "Category") {

            $rawCat = $meta.Category

            if ($rawCat -is [string]) {
                if (-not [string]::IsNullOrWhiteSpace($rawCat)) {
                    $cat = $rawCat
                }
            }
            elseif ($rawCat -is [psobject] -and
                    $rawCat.PSObject.Properties.Name -contains "Primary") {

                $primary = fncSafeString $rawCat.Primary
                if ([string]::IsNullOrWhiteSpace($primary)) {
                    $primary = "Uncategorised"
                }

                $subs = @()
                if ($rawCat.PSObject.Properties.Name -contains "Subcategories") {
                    $subs = @(fncSafeArray $rawCat.Subcategories)
                }

                $cat = [pscustomobject]@{
                    Primary       = $primary
                    Subcategories = $subs
                }
            }
        }

        # -----------------------------
        # Optional properties
        # -----------------------------
        $enabled  = $true
        $reqAdmin = $false
        $desc     = ""
        $mappings = $null
        $refs     = $null

        if ($meta.PSObject.Properties.Name -contains "Enabled")        { try { $enabled  = [bool]$meta.Enabled } catch {} }
        if ($meta.PSObject.Properties.Name -contains "RequiresAdmin")  { try { $reqAdmin = [bool]$meta.RequiresAdmin } catch {} }
        if ($meta.PSObject.Properties.Name -contains "Description")    { try { $desc     = fncSafeString $meta.Description } catch {} }
        if ($meta.PSObject.Properties.Name -contains "Mappings")       { $mappings = $meta.Mappings }
        if ($meta.PSObject.Properties.Name -contains "References")     { $refs     = $meta.References }

        $scopes = fncResolveScopes -Scopes $meta.Scopes

        # -----------------------------
        # Register
        # -----------------------------
        fncRegisterTest `
            -Id $id `
            -Name $nm `
            -Function $fn `
            -Category $cat `
            -Scopes $scopes `
            -Enabled $enabled `
            -RequiresAdmin $reqAdmin `
            -Description $desc `
            -SchemaVersion $schema `
            -Mappings $mappings `
            -References $refs

        $loadedCount++
    }

    try {
        if ($debugMode) {
            fncPrintMessage ("Test Modules Loaded: {0}" -f $loadedCount) "success"
            if ($failedCount -gt 0) {
                fncPrintMessage ("Modules Failed Validation: {0}" -f $failedCount) "warning"
            }
        }
    } catch {}
}

function fncRegisterTests {

    if ($null -eq $global:ProberState) {
        if (fncCommandExists "fncLog") { fncLog "ERROR" "ProberState not initialised before fncRegisterTests" }
        throw "ProberState is not initialised. Call fncBootstrapProberState first."
    }

    $global:ProberState.Tests = @()

    fncDiscoverTests

    if ((fncSafeCount $global:ProberState.Tests) -eq 0) {

        try { if (fncCommandExists "fncLog") { fncLog "WARN" "No tests discovered during registry scan" } } catch {}

        function fncNoOpTest {
            try { fncPrintMessage "No tests discovered." "warning" } catch { Write-Host "No tests discovered." }
        }

        fncRegisterTest `
            -Id "NOOP" `
            -Name "No tests discovered" `
            -Function "fncNoOpTest" `
            -Category "Utilities" `
            -Scopes @("All") `
            -Enabled $true `
            -RequiresAdmin $false
    }

    try {
        fncPrintMessage ("Registered tests: {0}" -f (fncSafeCount $global:ProberState.Tests)) "debug"
        if (fncCommandExists "fncLog") { fncLog "INFO" ("Registered tests: {0}" -f (fncSafeCount $global:ProberState.Tests)) }
    } catch {}
}

function fncGetUniqueCategories {

    param(
        [ValidateSet('All','Workstation','Server','Domain','DMZ','Cloud','SaaS','Container','Network','WebApp')]
        [string]$Scope = "All"
    )

    $tests = fncSafeArray $global:ProberState.Tests
    if ((fncSafeCount $tests) -eq 0) { return @() }

    $cats = @()

    try {

        $cats = @(
            $tests |
            Where-Object {
                $_ -and
                $_.Enabled -eq $true -and
                (
                    $Scope -eq "All" -or
                    @(fncSafeArray $_.Scopes) -contains $Scope
                )
            } |
            ForEach-Object {

                $catObj = $_.Category

                # New structured format
                if ($catObj -is [psobject] -and $catObj.PSObject.Properties.Name -contains "Primary") {

                    $primary = fncSafeString $catObj.Primary

                    if ([string]::IsNullOrWhiteSpace($primary)) {
                        "Uncategorised"
                    }
                    else {
                        $primary
                    }
                }
                else {
                    # Legacy string format
                    $c = fncSafeString $catObj
                    if ([string]::IsNullOrWhiteSpace($c)) { "Uncategorised" }
                    else { $c }
                }
            }
        )

    } catch { $cats = @() }

    return @($cats | Sort-Object -Unique)
}

function fncGetTestsByScope {
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('All','Workstation','Server','Domain','DMZ','Cloud','SaaS','Container','Network','WebApp')]
        [string]$Scope,

        [string]$Category = "",

        [switch]$IncludeDisabled
    )

    try {
        if (fncCommandExists "fncLog") {
            fncLog "DEBUG" ("Querying tests by scope: {0}, Category: {1}" -f $Scope,$Category)
        }
    } catch {}

    $tests = fncSafeArray $global:ProberState.Tests
    if ((fncSafeCount $tests) -eq 0) { return @() }

    # ---------------------------------------------
    # Filter disabled tests (unless requested)
    # ---------------------------------------------
    if (-not $IncludeDisabled) {
        $tests = fncSafeArray (
            $tests | Where-Object {
                $_ -and
                $_.Enabled -eq $true
            }
        )
    }

    # ---------------------------------------------
    # Build effective scope mapping
    # ---------------------------------------------
    $effectiveScopes = switch ($Scope) {

        "All"         { @("All","Workstation","Server","Domain","DMZ","Cloud","SaaS","Container","Network","WebApp") }
        "Workstation" { @("Workstation","Domain","All") }
        "Server"      { @("Server","Domain","All") }
        "Domain"      { @("Domain","All") }
        "DMZ"         { @("DMZ","All") }

        "Cloud"       { @("Cloud","All") }
        "SaaS"        { @("SaaS","Cloud","All") }
        "Container"   { @("Container","Server","Cloud","All") }
        "Network"     { @("Network","DMZ","All") }
        "WebApp"      { @("WebApp","DMZ","Server","Cloud","All") }
    }

    # ---------------------------------------------
    # Scope Filtering
    # ---------------------------------------------
    if ($Scope -ne "All") {

        $tests = fncSafeArray (
            $tests | Where-Object {

                $_ -and
                $_.Scopes -and
                (
                    $_.Scopes -contains "All" -or
                    (@(fncSafeArray $_.Scopes) | Where-Object { $effectiveScopes -contains $_ })
                )
            }
        )
    }

    # ---------------------------------------------
    # Category Filtering (Structured + Legacy Safe)
    # ---------------------------------------------
    if (-not [string]::IsNullOrWhiteSpace($Category)) {

        $tests = fncSafeArray (
            $tests | Where-Object {

                if (-not $_ -or -not $_.Category) { return $false }

                $catObj = $_.Category

                # New structured format
                if ($catObj -is [psobject] -and $catObj.PSObject.Properties.Name -contains "Primary") {
                    (fncSafeString $catObj.Primary) -eq (fncSafeString $Category)
                }
                else {
                    # Legacy string format
                    (fncSafeString $catObj) -eq (fncSafeString $Category)
                }
            }
        )
    }

    return $tests
}

function fncInvokeTestById {
    param(
        [Parameter(Mandatory=$true)][string]$TestId
    )

    try { if (fncCommandExists "fncLog") { fncLog "INFO" ("Invoking test by Id: {0}" -f $TestId) } } catch {}

    $tests = fncSafeArray $global:ProberState.Tests
    $t = @(
        $tests | Where-Object {
            $_ -and
            $_.PSObject.Properties.Name -contains "Id" -and
            (fncSafeString $_.Id) -eq (fncSafeString $TestId)
        }
    ) | Select-Object -First 1

    if ($null -eq $t) {
        try { fncPrintMessage ("Unknown test id: {0}" -f $TestId) "warning" } catch { Write-Host ("Unknown test id: {0}" -f $TestId) }
        try { if (fncCommandExists "fncLog") { fncLog "WARN" ("Unknown test id: {0}" -f $TestId) } } catch {}
        return
    }

    $needsAdmin = $false
    try {
        if ($t.PSObject.Properties.Name -contains "RequiresAdmin") { $needsAdmin = [bool]$t.RequiresAdmin }
    } catch { $needsAdmin = $false }

    if ($needsAdmin) {
        $isAdmin = $false
        try {
            if (fncCommandExists "fncIsAdmin") { $isAdmin = [bool](fncIsAdmin) }
        } catch { $isAdmin = $false }

        if (-not $isAdmin) {
            try { fncPrintMessage ("Test requires Administrator: {0}" -f (fncSafeString $t.Name)) "warning" } catch {}
            try { if (fncCommandExists "fncLog") { fncLog "WARN" ("Admin required for test: {0}" -f (fncSafeString $t.Id)) } } catch {}
            return
        }
    }

    $fn = ""
    try { if ($t.PSObject.Properties.Name -contains "Function") { $fn = fncSafeString $t.Function } } catch { $fn = "" }

    if ([string]::IsNullOrWhiteSpace($fn)) {
        try { fncPrintMessage ("Test has no function mapped: {0}" -f (fncSafeString $t.Name)) "warning" } catch {}
        try { if (fncCommandExists "fncLog") { fncLog "WARN" ("No function mapped for test: {0}" -f (fncSafeString $t.Id)) } } catch {}
        return
    }

    $cmd = Get-Command -Name $fn -ErrorAction SilentlyContinue
    if ($null -eq $cmd) {
        try { fncPrintMessage ("Mapped function not found: {0}" -f $fn) "warning" } catch {}
        try { if (fncCommandExists "fncLog") { fncLog "ERROR" ("Mapped function not found: {0}" -f $fn) } } catch {}
        return
    }

    try { fncPrintMessage ("Running: {0}" -f (fncSafeString $t.Name)) "info" } catch {}

    try {
        & $fn
        try { fncPrintMessage ("Completed: {0}" -f (fncSafeString $t.Name)) "success" } catch {}
        try { if (fncCommandExists "fncLog") { fncLog "INFO" ("Completed test: {0}" -f (fncSafeString $t.Id)) } } catch {}
    }
    catch {
        try { fncPrintMessage ("Test failed: {0}" -f $_.Exception.Message) "error" } catch {}
        try { if (fncCommandExists "fncLog") { fncLogException $_.Exception ("Test failed [{0}]" -f (fncSafeString $t.Id)) } } catch {}
    }
}

Export-ModuleMember -Function @(
    "fncRegisterTest",
    "fncRegisterTests",
    "fncDiscoverTests",
    "fncGetUniqueCategories",
    "fncGetTestsByScope",
    "fncInvokeTestById",
    "fncGetTestsRoot",
    "fncNotifyTestModuleLoaded",
    "fncRescanTestModules"
)
