# ================================================================
# Function: fncGetLolbinElevationCandidates
# Purpose : Identify common LOLBins + check UAC hijack keys / AlwaysInstallElevated
# ================================================================
function fncGetLolbinElevationCandidates {

    fncPrintMessage "Scanning for LOLBins that can potentially elevate (UAC / auto-elevate abuse surface)..." "info"
    fncPrintMessage "Initialising LOLBin elevation surface enumeration." "debug"
    fncPrintMessage "" "plain"

    $lolbins = @(
        @{
            Name           = "fodhelper.exe"
            SubCategory    = "UAC Bypass / AutoElevate"
            Description    = "Auto-elevated binary; classic HKCU ms-settings hijack pattern."
            PathCandidates = @("$env:WINDIR\System32\fodhelper.exe")
            UacHijackReg   = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
            UacDelegateReg = "HKCU:\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute"
        }
        @{
            Name           = "computerdefaults.exe"
            SubCategory    = "UAC Bypass / AutoElevate"
            Description    = "Auto-elevated binary; similar ms-settings hijack pattern."
            PathCandidates = @("$env:WINDIR\System32\computerdefaults.exe")
            UacHijackReg   = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
            UacDelegateReg = "HKCU:\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute"
        }
        @{
            Name           = "eventvwr.exe"
            SubCategory    = "UAC Bypass (legacy)"
            Description    = "Legacy UAC bypass via HKCU mscfile handler."
            PathCandidates = @("$env:WINDIR\System32\eventvwr.exe")
            UacHijackReg   = "HKCU:\Software\Classes\mscfile\shell\open\command"
            UacDelegateReg = $null
        }
        @{
            Name           = "sdclt.exe"
            SubCategory    = "UAC Bypass (legacy)"
            Description    = "Legacy UAC bypass via Folder handler hijack."
            PathCandidates = @("$env:WINDIR\System32\sdclt.exe")
            UacHijackReg   = "HKCU:\Software\Classes\Folder\shell\open\command"
            UacDelegateReg = $null
        }
        @{
            Name           = "slui.exe"
            SubCategory    = "UAC Bypass (legacy)"
            Description    = "Historically abused via handler hijack."
            PathCandidates = @("$env:WINDIR\System32\slui.exe")
            UacHijackReg   = "HKCU:\Software\Classes\exefile\shell\open\command"
            UacDelegateReg = $null
        }
        @{
            Name           = "cmstp.exe"
            SubCategory    = "Signed Binary / Execution"
            Description    = "Signed binary sometimes abused for execution under certain conditions."
            PathCandidates = @("$env:WINDIR\System32\cmstp.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "msiexec.exe"
            SubCategory    = "Installer / Elevated Execution"
            Description    = "Abusable when AlwaysInstallElevated is enabled."
            PathCandidates = @("$env:WINDIR\System32\msiexec.exe", "$env:WINDIR\SysWOW64\msiexec.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "schtasks.exe"
            SubCategory    = "Task Scheduler"
            Description    = "Used for task creation; becomes relevant when high privileges are already available."
            PathCandidates = @("$env:WINDIR\System32\schtasks.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "at.exe"
            SubCategory    = "Task Scheduler (legacy)"
            Description    = "Legacy scheduler binary."
            PathCandidates = @("$env:WINDIR\System32\at.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "runas.exe"
            SubCategory    = "Impersonation / Secondary Logon"
            Description    = "Useful when saved credentials or weak config exists."
            PathCandidates = @("$env:WINDIR\System32\runas.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "regsvr32.exe"
            SubCategory    = "Signed Binary / Execution"
            Description    = "Common LOLBAS; often used post-elevation."
            PathCandidates = @("$env:WINDIR\System32\regsvr32.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "mshta.exe"
            SubCategory    = "Signed Binary / Execution"
            Description    = "Executes HTA/JS in user context; often post-elevation."
            PathCandidates = @("$env:WINDIR\System32\mshta.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "wscript.exe / cscript.exe"
            SubCategory    = "Script Host"
            Description    = "Script hosts; useful once elevated."
            PathCandidates = @("$env:WINDIR\System32\wscript.exe", "$env:WINDIR\System32\cscript.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
    )

    fncPrintMessage ("Total LOLBins defined: {0}" -f $lolbins.Count) "debug"

    # ----------------------------------------------------------
    # Presence-only awareness findings
    # ----------------------------------------------------------
    foreach ($lb in $lolbins) {
        try {

            fncPrintMessage ("Checking LOLBin presence: {0}" -f $lb.Name) "debug"

            $presentPaths = @()

            foreach ($p in fncSafeArray $lb.PathCandidates) {
                if (-not $p) { continue }
                $expanded = [Environment]::ExpandEnvironmentVariables($p)

                fncPrintMessage ("Checking path candidate: {0}" -f $expanded) "debug"

                if (Test-Path -Path $expanded -ErrorAction SilentlyContinue) {
                    $presentPaths += $expanded
                }
            }

            if ($presentPaths.Count -gt 0) {

                fncPrintMessage ("LOLBin present: {0}" -f $lb.Name) "debug"

                Write-Host ("LOLBIN Present: {0}" -f $lb.Name)
                Write-Host ("  Type       : {0}" -f $lb.SubCategory)
                Write-Host ("  Notes      : {0}" -f $lb.Description)
                Write-Host ("  Paths      : {0}" -f ($presentPaths -join ", "))
                fncPrintMessage "" "plain"

                $fingerprint = "LOLBIN_PRESENT|" + $lb.Name
                $tag = fncShortHashTag $fingerprint

                fncAddFinding `
                    -Id ("LOLBIN_PRESENT_$tag") `
                    -Category "Privilege Escalation" `
                    -Title "LOLBin Present" `
                    -Severity "Info" `
                    -Status "Detected" `
                    -Message ("LOLBin present that is commonly associated with elevation tradecraft: {0}" -f $lb.Name) `
                    -Recommendation "No action required by itself; monitor usage and apply application control where appropriate." `
                    -Evidence ("Paths: {0}" -f ($presentPaths -join ", "))
            }
            else {
                fncPrintMessage ("LOLBin not present: {0}" -f $lb.Name) "debug"
            }
        }
        catch {
            fncPrintMessage ("Exception checking LOLBin {0}: {1}" -f $lb.Name,$_.Exception.Message) "debug"
            continue
        }
    }

    # ----------------------------------------------------------
    # UAC hijack registry keys (higher confidence misconfig)
    # ----------------------------------------------------------
    fncPrintMessage "" "plain"
    fncPrintMessage "Checking common UAC hijack registry keys for suspicious presence..." "info"
    fncPrintMessage "Beginning HKCU handler override inspection." "debug"
    fncPrintMessage "" "plain"

    foreach ($lb in ($lolbins | Where-Object { $_.UacHijackReg })) {

        $regPath      = $lb.UacHijackReg
        $delegatePath = $lb.UacDelegateReg

        try {

            fncPrintMessage ("Checking registry path: {0}" -f $regPath) "debug"

            if (-not (Test-Path -Path $regPath)) {
                fncPrintMessage "Registry path not present." "debug"
                continue
            }

            $key = Get-Item -Path $regPath -ErrorAction SilentlyContinue
            $defaultValue = $null

            if ($key) {
                try { $defaultValue = $key.GetValue("") } catch {}
            }

            Write-Host ("Potential UAC hijack key present for {0}: {1}" -f $lb.Name,$regPath)
            Write-Host ("  Default value: {0}" -f (fncSafeString $defaultValue))
            fncPrintMessage "" "plain"

            fncPrintMessage "UAC hijack key identified." "debug"

            $fingerprint = "LOLBIN_UAC_HIJACK|" + $lb.Name + "|" + $regPath
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("LOLBIN_UAC_HIJACKKEY_$tag") `
                -Category "Privilege Escalation" `
                -Title "UAC Hijack Registry Key Present" `
                -Severity "High" `
                -Status "Detected" `
                -Message ("HKCU UAC hijack key for {0} exists - potential UAC bypass configuration." -f $lb.Name) `
                -Recommendation "Remove unexpected HKCU handler overrides and investigate user profile persistence mechanisms." `
                -Evidence ("{0} default='{1}'" -f $regPath,(fncSafeString $defaultValue))

            if ($delegatePath) {

                fncPrintMessage ("Checking DelegateExecute path: {0}" -f $delegatePath) "debug"

                if (Test-Path -Path $delegatePath) {

                    $delegateKey = Get-Item -Path $delegatePath -ErrorAction SilentlyContinue
                    $delegateVal = $null

                    if ($delegateKey) {
                        try { $delegateVal = $delegateKey.GetValue("") } catch {}
                    }

                    Write-Host ("  DelegateExecute present: {0} (Value: '{1}')" -f $delegatePath,(fncSafeString $delegateVal))
                    fncPrintMessage "" "plain"

                    fncPrintMessage "DelegateExecute key identified." "debug"

                    $fingerprint = "LOLBIN_UAC_DELEGATE|" + $lb.Name + "|" + $delegatePath
                    $tag = fncShortHashTag $fingerprint

                    fncAddFinding `
                        -Id ("LOLBIN_UAC_DELEGATEEXECUTE_$tag") `
                        -Category "Privilege Escalation" `
                        -Title "DelegateExecute Key Present" `
                        -Severity "High" `
                        -Status "Detected" `
                        -Message ("DelegateExecute key exists for {0} - common UAC bypass pattern." -f $lb.Name) `
                        -Recommendation "Remove unexpected DelegateExecute keys and investigate persistence." `
                        -Evidence ("{0} default='{1}'" -f $delegatePath,(fncSafeString $delegateVal))
                }
                else {
                    fncPrintMessage "DelegateExecute key not present." "debug"
                }
            }
        }
        catch {
            fncPrintMessage ("Exception evaluating registry hijack path: {0}" -f $_.Exception.Message) "debug"
            continue
        }
    }

    # ----------------------------------------------------------
    # AlwaysInstallElevated (msiexec)
    # ----------------------------------------------------------
    try {

        fncPrintMessage "Checking AlwaysInstallElevated policy keys." "debug"

        $polHKLM     = "HKLM:\Software\Policies\Microsoft\Windows\Installer"
        $polHKCU     = "HKCU:\Software\Policies\Microsoft\Windows\Installer"
        $aiValueName = "AlwaysInstallElevated"

        $aiHKLM = $null
        $aiHKCU = $null

        if (Test-Path $polHKLM) {
            $aiHKLM = (Get-ItemProperty -Path $polHKLM -Name $aiValueName -ErrorAction SilentlyContinue).$aiValueName
        }

        if (Test-Path $polHKCU) {
            $aiHKCU = (Get-ItemProperty -Path $polHKCU -Name $aiValueName -ErrorAction SilentlyContinue).$aiValueName
        }

        Write-Host ("AlwaysInstallElevated (HKLM): {0}" -f (fncSafeString $aiHKLM))
        Write-Host ("AlwaysInstallElevated (HKCU): {0}" -f (fncSafeString $aiHKCU))
        fncPrintMessage "" "plain"

        if ($aiHKLM -eq 1 -and $aiHKCU -eq 1) {

            fncPrintMessage "AlwaysInstallElevated fully enabled." "debug"

            fncAddFinding `
                -Id "ALWAYS_INSTALL_ELEVATED_ENABLED" `
                -Category "Privilege Escalation" `
                -Title "AlwaysInstallElevated Enabled" `
                -Severity "High" `
                -Status "Misconfigured" `
                -Message "AlwaysInstallElevated is enabled in both HKLM and HKCU." `
                -Recommendation "Disable AlwaysInstallElevated in both hives via GPO and validate installer policy." `
                -Evidence "HKLM and HKCU Installer\\AlwaysInstallElevated = 1"
        }
        elseif ($aiHKLM -eq 1 -or $aiHKCU -eq 1) {

            fncPrintMessage "AlwaysInstallElevated partially enabled." "debug"

            fncAddFinding `
                -Id "ALWAYS_INSTALL_ELEVATED_PARTIAL" `
                -Category "Privilege Escalation" `
                -Title "AlwaysInstallElevated Partially Enabled" `
                -Severity "Medium" `
                -Status "Misconfigured" `
                -Message "AlwaysInstallElevated is enabled in only one hive (HKLM or HKCU)." `
                -Recommendation "Ensure policy is disabled consistently across HKLM and HKCU." `
                -Evidence ("HKLM={0}, HKCU={1}" -f (fncSafeString $aiHKLM),(fncSafeString $aiHKCU))
        }
        else {
            fncPrintMessage "AlwaysInstallElevated not enabled." "debug"
        }
    }
    catch {
        fncPrintMessage ("Exception evaluating AlwaysInstallElevated: {0}" -f $_.Exception.Message) "debug"
    }

    fncPrintMessage "LOLBin elevation surface scan complete." "success"
    fncPrintMessage "LOLBin enumeration routine finished." "debug"
}

Export-ModuleMember -Function fncGetLolbinElevationCandidates
