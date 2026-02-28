# ================================================================
# Function: fncGetLolbinElevationCandidates
# Purpose : Identify common LOLBins + check UAC hijack keys / AlwaysInstallElevated + UAC posture
# ================================================================
function fncGetLolbinElevationCandidates {

    fncPrintMessage "Scanning for auto-elevated binaries and UAC bypass surfaces..." "info"
    fncPrintMessage "Initialising auto-elevate and signed-binary abuse surface enumeration." "debug"
    Write-Host ""

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
            Name           = "fsquirt.exe"
            SubCategory    = "UAC Bypass / AutoElevate"
            Description    = "Bluetooth File Transfer wizard; commonly referenced in UAC bypass tradecraft."
            PathCandidates = @("$env:WINDIR\System32\fsquirt.exe")
            UacHijackReg   = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"
            UacDelegateReg = "HKCU:\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute"
        }
        @{
            Name           = "wsreset.exe"
            SubCategory    = "UAC Bypass / AutoElevate"
            Description    = "Windows Store reset utility; abused in some handler/COM-hijack patterns."
            PathCandidates = @("$env:WINDIR\System32\wsreset.exe")
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
            Description    = "Legacy UAC bypass via Folder handler hijack (older builds)."
            PathCandidates = @("$env:WINDIR\System32\sdclt.exe")
            UacHijackReg   = "HKCU:\Software\Classes\Folder\shell\open\command"
            UacDelegateReg = $null
        }
        @{
            Name           = "slui.exe"
            SubCategory    = "UAC Bypass (legacy)"
            Description    = "Historically abused via handler hijack patterns."
            PathCandidates = @("$env:WINDIR\System32\slui.exe")
            UacHijackReg   = "HKCU:\Software\Classes\exefile\shell\open\command"
            UacDelegateReg = $null
        }
        @{
            Name           = "cmstp.exe"
            SubCategory    = "Signed Binary / Execution"
            Description    = "Signed binary sometimes abused for proxy execution under certain conditions."
            PathCandidates = @("$env:WINDIR\System32\cmstp.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "msiexec.exe"
            SubCategory    = "Installer / Elevated Execution"
            Description    = "Relevant when AlwaysInstallElevated is enabled."
            PathCandidates = @("$env:WINDIR\System32\msiexec.exe", "$env:WINDIR\SysWOW64\msiexec.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "schtasks.exe"
            SubCategory    = "Task Scheduler"
            Description    = "Useful once elevated; presence is informational."
            PathCandidates = @("$env:WINDIR\System32\schtasks.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "at.exe"
            SubCategory    = "Task Scheduler (legacy)"
            Description    = "Legacy scheduler binary; presence is informational."
            PathCandidates = @("$env:WINDIR\System32\at.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "runas.exe"
            SubCategory    = "Impersonation / Secondary Logon"
            Description    = "Useful when credentials are available; presence is informational."
            PathCandidates = @("$env:WINDIR\System32\runas.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "regsvr32.exe"
            SubCategory    = "Signed Binary / Execution"
            Description    = "Common LOLBAS; often post-elevation."
            PathCandidates = @("$env:WINDIR\System32\regsvr32.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "mshta.exe"
            SubCategory    = "Signed Binary / Execution"
            Description    = "Executes HTA/JS; often post-elevation."
            PathCandidates = @("$env:WINDIR\System32\mshta.exe")
            UacHijackReg   = $null
            UacDelegateReg = $null
        }
        @{
            Name           = "wscript.exe / cscript.exe"
            SubCategory    = "Script Host"
            Description    = "Script hosts; often post-elevation."
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

            foreach ($p in (fncSafeArray $lb.PathCandidates)) {
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
                Write-Host ""

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
    Write-Host ""
    fncPrintMessage "Checking common UAC hijack registry keys for suspicious presence..." "info"
    fncPrintMessage "Beginning HKCU handler override inspection." "debug"
    Write-Host ""

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
            Write-Host ""

            fncPrintMessage "UAC hijack key identified." "debug"

            $fingerprint = "LOLBIN_UAC_HIJACK|" + $lb.Name + "|" + $regPath
            $tag = fncShortHashTag $fingerprint

            fncAddFinding `
                -Id ("LOLBIN_UAC_HIJACKKEY_$tag") `
                -Category "Privilege Escalation" `
                -Title "UAC Hijack Registry Key Present" `
                -Severity "High" `
                -Status "Detected" `
                -Message ("HKCU handler override for {0} exists (potential UAC bypass surface)." -f $lb.Name) `
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
                    Write-Host ""

                    fncPrintMessage "DelegateExecute key identified." "debug"

                    $fingerprint = "LOLBIN_UAC_DELEGATE|" + $lb.Name + "|" + $delegatePath
                    $tag = fncShortHashTag $fingerprint

                    fncAddFinding `
                        -Id ("LOLBIN_UAC_DELEGATEEXECUTE_$tag") `
                        -Category "Privilege Escalation" `
                        -Title "DelegateExecute Key Present" `
                        -Severity "High" `
                        -Status "Detected" `
                        -Message ("DelegateExecute key exists for {0} (common UAC bypass pattern)." -f $lb.Name) `
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
        Write-Host ""

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

    # ==========================================================
    # UAC Configuration Detection (ConsentPromptBehaviorAdmin)
    # ==========================================================
    try {

        fncPrintMessage "Evaluating UAC configuration..." "info"
        fncPrintMessage "Reading EnableLUA / ConsentPromptBehaviorAdmin / PromptOnSecureDesktop." "debug"
        Write-Host ""

        $uacReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

        $enableLUA                 = $null
        $consentPromptBehavior     = $null
        $promptOnSecureDesktop     = $null

        if (Test-Path $uacReg) {
            $uacProps = Get-ItemProperty -Path $uacReg -ErrorAction SilentlyContinue
            $enableLUA             = $uacProps.EnableLUA
            $consentPromptBehavior = $uacProps.ConsentPromptBehaviorAdmin
            $promptOnSecureDesktop = $uacProps.PromptOnSecureDesktop
        }

        Write-Host ("EnableLUA                  : {0}" -f (fncSafeString $enableLUA))
        Write-Host ("ConsentPromptBehaviorAdmin : {0}" -f (fncSafeString $consentPromptBehavior))
        Write-Host ("PromptOnSecureDesktop      : {0}" -f (fncSafeString $promptOnSecureDesktop))
        Write-Host ""

        # Interpret posture (lightweight; v5-friendly)
        $uacLevel = "Unknown"

        if ($enableLUA -eq 0) {
            $uacLevel = "UAC Disabled"
            fncAddFinding `
                -Id "UAC_DISABLED" `
                -Category "Privilege Escalation" `
                -Title "UAC Disabled (EnableLUA=0)" `
                -Severity "High" `
                -Status "Misconfigured" `
                -Message "User Account Control is disabled on this system." `
                -Recommendation "Enable UAC (EnableLUA=1) via GPO/local policy." `
                -Evidence "EnableLUA=0"
        }
        elseif ($enableLUA -eq 1) {

            switch ($consentPromptBehavior) {

                0 {
                    $uacLevel = "Elevate Without Prompting (Silent Elevation)"
                    fncAddFinding `
                        -Id "UAC_SILENT_ELEVATION" `
                        -Category "Privilege Escalation" `
                        -Title "UAC Silent Elevation Enabled (ConsentPromptBehaviorAdmin=0)" `
                        -Severity "High" `
                        -Status "Misconfigured" `
                        -Message "ConsentPromptBehaviorAdmin=0 (elevates without prompting)." `
                        -Recommendation "Set ConsentPromptBehaviorAdmin to require consent/credentials for elevation." `
                        -Evidence "ConsentPromptBehaviorAdmin=0"
                }

                1 { $uacLevel = "Prompt for Credentials (Secure Desktop)" }
                2 { $uacLevel = "Prompt for Consent (Secure Desktop)" }
                3 { $uacLevel = "Prompt for Credentials" }
                4 { $uacLevel = "Prompt for Consent" }
                5 { $uacLevel = "Default (Consent for non-Windows binaries)" }

                default { $uacLevel = "Custom / Unknown Mode" }
            }
        }

        # Always add a posture finding (Info)
        $fingerprint = "UAC_POSTURE|" + (fncSafeString $enableLUA) + "|" + (fncSafeString $consentPromptBehavior) + "|" + (fncSafeString $promptOnSecureDesktop)
        $tag = fncShortHashTag $fingerprint

        fncAddFinding `
            -Id ("UAC_CONFIGURATION_$tag") `
            -Category "Privilege Escalation" `
            -Title "UAC Configuration Detected" `
            -Severity "Info" `
            -Status "Detected" `
            -Message ("UAC Mode: {0}" -f $uacLevel) `
            -Recommendation "Review UAC posture; higher prompt levels reduce UAC bypass viability and improve elevation controls." `
            -Evidence ("EnableLUA={0}, ConsentPromptBehaviorAdmin={1}, PromptOnSecureDesktop={2}" -f `
                (fncSafeString $enableLUA),
                (fncSafeString $consentPromptBehavior),
                (fncSafeString $promptOnSecureDesktop)
            )

    }
    catch {
        fncPrintMessage ("Exception evaluating UAC configuration: {0}" -f $_.Exception.Message) "debug"
    }

    fncPrintMessage "LOLBin elevation surface scan complete." "success"
    fncPrintMessage "LOLBin enumeration routine finished." "debug"
}

Export-ModuleMember -Function fncGetLolbinElevationCandidates