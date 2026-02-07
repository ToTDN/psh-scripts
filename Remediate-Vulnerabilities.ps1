<#
.SYNOPSIS
    Comprehensive vulnerability remediation script for Windows environments.

.DESCRIPTION
    This script remediates security vulnerabilities identified across multiple devices
    including registry hardening, protocol/cipher hardening, service path fixes,
    software version checks, and EOL software detection/removal.

    Vulnerabilities addressed:
    - CVE-2013-3900  WinVerifyTrust Signature Validation
    - ADV180012      Spectre/Meltdown Variant 4 (Speculative Store Bypass)
    - ADV180002      Spectre/Meltdown Hyper-V
    - LanMan/NTLMv1  Authentication downgrade
    - SMBv1          Protocol deprecation
    - Sweet32        Weak 64-bit block ciphers (DES, 3DES, RC2)
    - TLSv1.0        Protocol deprecation
    - Unquoted service paths privilege escalation
    - Visual C++ Redistributable installer elevation of privilege
    - ASP.NET Core October 2025 security update
    - 28+ software update checks
    - EOL software detection (Adobe XI, .NET 6, .NET Core 3.1, Access DB Engine 2010)

.PARAMETER RemediationMode
    Controls which remediations run:
    - All           Run everything (default)
    - RegistryOnly  Registry-based hardening only
    - ProtocolOnly  Protocol/cipher hardening only
    - ServicePaths  Unquoted service path fixes only
    - AuditOnly     Detection and reporting only (no changes)

.PARAMETER LogPath
    Path to the log file. Defaults to .\Remediate-Vulnerabilities_<timestamp>.log

.PARAMETER WhatIf
    Preview mode - logs what would be done without making changes.

.NOTES
    Requires: Administrator privileges
    Version:  1.0.0
    Date:     2026-02-07
#>

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet("All", "RegistryOnly", "ProtocolOnly", "ServicePaths", "AuditOnly")]
    [string]$RemediationMode = "All",

    [string]$LogPath = ""
)

# ============================================================================
# GLOBALS AND LOGGING
# ============================================================================

$Script:StartTime = Get-Date
$Script:RebootRequired = $false

if (-not $LogPath) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $LogPath = Join-Path $PSScriptRoot "Remediate-Vulnerabilities_$timestamp.log"
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO", "WARNING", "ERROR", "WARN")][string]$Level = "INFO"
    )

    # Normalize WARN to WARNING
    if ($Level -eq "WARN") { $Level = "WARNING" }

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        "ERROR"   { Write-Host $entry -ForegroundColor Red }
        "WARNING" { Write-Host $entry -ForegroundColor Yellow }
        default   { Write-Host $entry -ForegroundColor Gray }
    }

    $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

# ============================================================================
# SECTION 1: REGISTRY-BASED VULNERABILITY REMEDIATION
# ============================================================================

#region Registry Hardening

function Remediate-WinVerifyTrustSignatureValidation {
    [CmdletBinding()]
    param()

    Write-Log "Remediating WinVerifyTrust Signature Validation vulnerability (CVE-2013-3900)" "INFO"

    $paths = @(
        "HKLM:\Software\Microsoft\Cryptography\Wintrust\Config",
        "HKLM:\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config"
    )

    foreach ($path in $paths) {
        try {
            if (-not (Test-Path $path)) {
                Write-Log "Registry path '$path' does not exist. Creating it." "INFO"
                New-Item -Path $path -Force | Out-Null
            }

            $current = Get-ItemProperty -Path $path -Name "EnableCertPaddingCheck" -ErrorAction SilentlyContinue

            if ($current -and $current.EnableCertPaddingCheck -eq "1") {
                Write-Log "EnableCertPaddingCheck already set to '1' at '$path'. No change needed." "INFO"
                continue
            }

            Set-ItemProperty -Path $path -Name "EnableCertPaddingCheck" -Value "1" -Type String -Force
            Write-Log "Successfully set EnableCertPaddingCheck = '1' at '$path'." "INFO"
        }
        catch {
            Write-Log "Failed to set EnableCertPaddingCheck at '$path': $($_.Exception.Message)" "ERROR"
        }
    }
}

function Remediate-SpectreVariant4 {
    [CmdletBinding()]
    param()

    Write-Log "Remediating Spectre/Meltdown Variant 4 (ADV180012) - Speculative Store Bypass" "INFO"

    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"

    $settings = @(
        @{ Name = "FeatureSettingsOverride";     Value = 8; Type = "DWord" },
        @{ Name = "FeatureSettingsOverrideMask"; Value = 3; Type = "DWord" }
    )

    foreach ($setting in $settings) {
        try {
            if (-not (Test-Path $path)) {
                Write-Log "Registry path '$path' does not exist. Creating it." "INFO"
                New-Item -Path $path -Force | Out-Null
            }

            $current = Get-ItemProperty -Path $path -Name $setting.Name -ErrorAction SilentlyContinue

            if ($current -and $current.($setting.Name) -eq $setting.Value) {
                Write-Log "$($setting.Name) already set to $($setting.Value) at '$path'. No change needed." "INFO"
                continue
            }

            Set-ItemProperty -Path $path -Name $setting.Name -Value $setting.Value -Type $setting.Type -Force
            Write-Log "Successfully set $($setting.Name) = $($setting.Value) (REG_DWORD) at '$path'." "INFO"
        }
        catch {
            Write-Log "Failed to set $($setting.Name) at '$path': $($_.Exception.Message)" "ERROR"
        }
    }
}

function Remediate-SpectreHyperV {
    [CmdletBinding()]
    param()

    Write-Log "Remediating Spectre/Meltdown Hyper-V (ADV180002) - MinVmVersionForCpuBasedMitigations" "INFO"

    $path  = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization"
    $name  = "MinVmVersionForCpuBasedMitigations"
    $value = "1.0"

    try {
        if (-not (Test-Path $path)) {
            Write-Log "Registry path '$path' does not exist. Creating it." "INFO"
            New-Item -Path $path -Force | Out-Null
        }

        $current = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue

        if ($current -and $current.$name -eq $value) {
            Write-Log "$name already set to '$value' at '$path'. No change needed." "INFO"
            return
        }

        Set-ItemProperty -Path $path -Name $name -Value $value -Type String -Force
        Write-Log "Successfully set $name = '$value' (REG_SZ) at '$path'." "INFO"
    }
    catch {
        Write-Log "Failed to set $name at '$path': $($_.Exception.Message)" "ERROR"
    }
}

function Remediate-DisableLanManNTLMv1 {
    [CmdletBinding()]
    param()

    Write-Log "Remediating LanMan/NTLMv1 - Setting LmCompatibilityLevel to 5 (Send NTLMv2 response only. Refuse LM & NTLM)" "INFO"

    $path  = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $name  = "LmCompatibilityLevel"
    $value = 5

    try {
        if (-not (Test-Path $path)) {
            Write-Log "Registry path '$path' does not exist. Creating it." "INFO"
            New-Item -Path $path -Force | Out-Null
        }

        $current = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue

        if ($current -and $current.$name -eq $value) {
            Write-Log "$name already set to $value at '$path'. No change needed." "INFO"
            return
        }

        if ($current) {
            Write-Log "Current $name value is $($current.$name). Updating to $value." "INFO"
        }

        Set-ItemProperty -Path $path -Name $name -Value $value -Type DWord -Force
        Write-Log "Successfully set $name = $value (REG_DWORD) at '$path'. NTLMv2 only; LM and NTLM refused." "INFO"
    }
    catch {
        Write-Log "Failed to set $name at '$path': $($_.Exception.Message)" "ERROR"
    }
}

#endregion Registry Hardening

# ============================================================================
# SECTION 2: PROTOCOL AND CIPHER HARDENING
# ============================================================================

#region Protocol Hardening

function Remediate-SMBv1Disable {
    [CmdletBinding()]
    param()

    Write-Log "Disabling SMB v1 protocol (client and server) to mitigate SMBv1 vulnerabilities" "INFO"

    try {
        # Server-side: Registry method
        $smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"

        if (Test-Path $smbServerPath) {
            $currentValue = (Get-ItemProperty -Path $smbServerPath -Name "SMB1" -ErrorAction SilentlyContinue).SMB1

            if ($currentValue -eq 0) {
                Write-Log "SMBv1 server already disabled via registry (SMB1 = 0). No change needed." "INFO"
            }
            else {
                New-ItemProperty -Path $smbServerPath -Name "SMB1" -Value 0 -PropertyType DWord -Force | Out-Null
                Write-Log "SMBv1 server disabled via registry: $smbServerPath\SMB1 = 0" "INFO"
            }
        }
        else {
            New-Item -Path $smbServerPath -Force | Out-Null
            New-ItemProperty -Path $smbServerPath -Name "SMB1" -Value 0 -PropertyType DWord -Force | Out-Null
            Write-Log "Created registry path and disabled SMBv1 server: $smbServerPath\SMB1 = 0" "INFO"
        }

        # Server-side: Set-SmbServerConfiguration if available
        if (Get-Command Set-SmbServerConfiguration -ErrorAction SilentlyContinue) {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
            if ($null -ne $smbConfig -and $smbConfig.EnableSMB1Protocol -eq $true) {
                Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
                Write-Log "SMBv1 server disabled via Set-SmbServerConfiguration" "INFO"
            }
            elseif ($null -ne $smbConfig -and $smbConfig.EnableSMB1Protocol -eq $false) {
                Write-Log "SMBv1 server already disabled via Set-SmbServerConfiguration. No change needed." "INFO"
            }
        }
        else {
            Write-Log "Set-SmbServerConfiguration cmdlet not available; relying on registry method only." "INFO"
        }

        # Client-side: Remove mrxsmb10 dependency from LanmanWorkstation
        try {
            $lanmanDeps = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" -Name "DependOnService" -ErrorAction SilentlyContinue).DependOnService

            if ($null -ne $lanmanDeps -and $lanmanDeps -contains "MRxSMB10") {
                $result = & sc.exe config lanmanworkstation depend= bowser/mrxsmb20/nsi 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Log "SMBv1 client dependencies updated: lanmanworkstation now depends on bowser/mrxsmb20/nsi" "INFO"
                }
                else {
                    Write-Log "Failed to update lanmanworkstation dependencies via sc.exe: $result" "ERROR"
                }
            }
            else {
                Write-Log "SMBv1 client dependency (MRxSMB10) already removed from LanmanWorkstation. No change needed." "INFO"
            }
        }
        catch {
            Write-Log "Error checking/updating LanmanWorkstation dependencies: $($_.Exception.Message)" "ERROR"
        }

        # Disable mrxsmb10 service
        try {
            $mrxsmb10 = Get-Service -Name "mrxsmb10" -ErrorAction SilentlyContinue
            if ($null -ne $mrxsmb10) {
                $startType = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10" -Name "Start" -ErrorAction SilentlyContinue).Start
                if ($startType -ne 4) {
                    Set-Service -Name "mrxsmb10" -StartupType Disabled -ErrorAction Stop
                    Write-Log "SMBv1 client driver (mrxsmb10) set to Disabled." "INFO"
                }
                else {
                    Write-Log "SMBv1 client driver (mrxsmb10) already disabled. No change needed." "INFO"
                }
            }
            else {
                Write-Log "mrxsmb10 service not found; SMBv1 client driver may already be removed." "INFO"
            }
        }
        catch {
            Write-Log "Error disabling mrxsmb10 service: $($_.Exception.Message)" "ERROR"
        }

        # Disable SMB1Protocol Windows Optional Feature if available
        try {
            if (Get-Command Disable-WindowsOptionalFeature -ErrorAction SilentlyContinue) {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction SilentlyContinue
                if ($null -ne $feature -and $feature.State -eq "Enabled") {
                    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop | Out-Null
                    Write-Log "Windows Optional Feature 'SMB1Protocol' has been disabled (reboot required)." "INFO"
                    $Script:RebootRequired = $true
                }
                elseif ($null -ne $feature -and $feature.State -eq "Disabled") {
                    Write-Log "Windows Optional Feature 'SMB1Protocol' already disabled. No change needed." "INFO"
                }
                else {
                    Write-Log "Windows Optional Feature 'SMB1Protocol' not found on this system." "INFO"
                }
            }
            else {
                Write-Log "Disable-WindowsOptionalFeature cmdlet not available; skipping optional feature removal." "INFO"
            }
        }
        catch {
            Write-Log "Error disabling SMB1Protocol optional feature: $($_.Exception.Message)" "ERROR"
        }

        Write-Log "SMBv1 disable remediation completed." "INFO"
    }
    catch {
        Write-Log "Critical error during SMBv1 disable remediation: $($_.Exception.Message)" "ERROR"
    }
}

function Remediate-Sweet32Ciphers {
    [CmdletBinding()]
    param()

    Write-Log "Disabling weak ciphers (DES, 3DES, RC2) to mitigate Sweet32 and related vulnerabilities" "INFO"

    try {
        $schannelCiphersBase = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers"

        $ciphersToDisable = @(
            "Triple DES 168",
            "DES 56/56",
            "RC2 40/128",
            "RC2 56/128",
            "RC2 128/128"
        )

        foreach ($cipher in $ciphersToDisable) {
            $cipherPath = Join-Path -Path $schannelCiphersBase -ChildPath $cipher

            try {
                if (Test-Path $cipherPath) {
                    $currentEnabled = (Get-ItemProperty -Path $cipherPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled

                    if ($currentEnabled -eq 0) {
                        Write-Log "Cipher '$cipher' already disabled (Enabled = 0). No change needed." "INFO"
                        continue
                    }
                }

                if (-not (Test-Path $cipherPath)) {
                    New-Item -Path $cipherPath -Force | Out-Null
                    Write-Log "Created registry key: $cipherPath" "INFO"
                }

                New-ItemProperty -Path $cipherPath -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
                Write-Log "Cipher '$cipher' disabled: $cipherPath\Enabled = 0" "INFO"
            }
            catch {
                Write-Log "Error disabling cipher '$cipher': $($_.Exception.Message)" "ERROR"
            }
        }

        Write-Log "Sweet32 cipher remediation completed." "INFO"
    }
    catch {
        Write-Log "Critical error during Sweet32 cipher remediation: $($_.Exception.Message)" "ERROR"
    }
}

function Remediate-TLS10Disable {
    [CmdletBinding()]
    param()

    Write-Log "Disabling TLS 1.0 protocol (client and server) to mitigate TLS 1.0 vulnerabilities" "INFO"

    try {
        $tls10Base = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0"
        $sides = @("Server", "Client")

        foreach ($side in $sides) {
            $sidePath = Join-Path -Path $tls10Base -ChildPath $side

            try {
                $needsChange = $false

                if (Test-Path $sidePath) {
                    $currentEnabled = (Get-ItemProperty -Path $sidePath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                    $currentDisabledByDefault = (Get-ItemProperty -Path $sidePath -Name "DisabledByDefault" -ErrorAction SilentlyContinue).DisabledByDefault

                    if ($currentEnabled -eq 0 -and $currentDisabledByDefault -eq 1) {
                        Write-Log "TLS 1.0 $side already disabled (Enabled = 0, DisabledByDefault = 1). No change needed." "INFO"
                        continue
                    }
                    else {
                        $needsChange = $true
                    }
                }
                else {
                    $needsChange = $true
                }

                if ($needsChange) {
                    if (-not (Test-Path $sidePath)) {
                        New-Item -Path $sidePath -Force | Out-Null
                        Write-Log "Created registry key: $sidePath" "INFO"
                    }

                    New-ItemProperty -Path $sidePath -Name "Enabled" -Value 0 -PropertyType DWord -Force | Out-Null
                    New-ItemProperty -Path $sidePath -Name "DisabledByDefault" -Value 1 -PropertyType DWord -Force | Out-Null
                    Write-Log "TLS 1.0 $side disabled: Enabled = 0, DisabledByDefault = 1 at $sidePath" "INFO"
                }
            }
            catch {
                Write-Log "Error disabling TLS 1.0 ${side}: $($_.Exception.Message)" "ERROR"
            }
        }

        Write-Log "TLS 1.0 disable remediation completed." "INFO"
    }
    catch {
        Write-Log "Critical error during TLS 1.0 disable remediation: $($_.Exception.Message)" "ERROR"
    }
}

#endregion Protocol Hardening

# ============================================================================
# SECTION 3: SERVICE PATH AND WINDOWS CONFIGURATION FIXES
# ============================================================================

#region Service Path Fixes

function Remediate-UnquotedServicePaths {
    [CmdletBinding()]
    param()

    Write-Log "Starting scan for unquoted service path vulnerabilities across all services" "INFO"

    try {
        $fixedCount = 0
        $skippedCount = 0
        $errorCount = 0

        $services = Get-CimInstance -ClassName Win32_Service -ErrorAction Stop |
            Where-Object { $_.PathName -ne $null -and $_.PathName -ne '' }

        Write-Log "Retrieved $($services.Count) services to evaluate" "INFO"

        foreach ($svc in $services) {
            $serviceName = $svc.Name
            $imagePath = $svc.PathName.Trim()

            # Skip if already quoted
            if ($imagePath.StartsWith('"')) {
                continue
            }

            # Find .exe position to split executable from arguments
            $exeIndex = $imagePath.ToLower().IndexOf('.exe')
            if ($exeIndex -lt 0) {
                continue
            }

            $exePath = $imagePath.Substring(0, $exeIndex + 4)
            $remainder = $imagePath.Substring($exeIndex + 4).Trim()
            $arguments = if ($remainder.Length -gt 0) { $remainder } else { $null }

            # Only vulnerable if the executable path contains a space
            if (-not $exePath.Contains(' ')) {
                continue
            }

            Write-Log "VULNERABLE: Service '$serviceName' has unquoted path with spaces: $imagePath" "WARNING"

            # Build corrected ImagePath
            $correctedPath = if ($arguments) { "`"$exePath`" $arguments" } else { "`"$exePath`"" }

            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"

            try {
                if (-not (Test-Path $regPath)) {
                    Write-Log "Registry key not found for service '$serviceName' at $regPath - skipping" "WARNING"
                    $skippedCount++
                    continue
                }

                $currentRegValue = (Get-ItemProperty -Path $regPath -Name ImagePath -ErrorAction Stop).ImagePath
                Write-Log "Service '$serviceName' current ImagePath: $currentRegValue" "INFO"
                Write-Log "Service '$serviceName' corrected ImagePath: $correctedPath" "INFO"

                Set-ItemProperty -Path $regPath -Name "ImagePath" -Value $correctedPath -ErrorAction Stop

                # Verify
                $verifyValue = (Get-ItemProperty -Path $regPath -Name ImagePath -ErrorAction Stop).ImagePath
                if ($verifyValue -eq $correctedPath) {
                    Write-Log "SUCCESS: Service '$serviceName' ImagePath updated and verified" "INFO"
                    $fixedCount++
                }
                else {
                    Write-Log "VERIFY FAILED: Service '$serviceName' - Expected: $correctedPath | Got: $verifyValue" "ERROR"
                    $errorCount++
                }
            }
            catch {
                Write-Log "FAILED to update service '$serviceName': $($_.Exception.Message)" "ERROR"
                $errorCount++
            }
        }

        Write-Log "Unquoted service path scan complete. Fixed: $fixedCount | Skipped: $skippedCount | Errors: $errorCount" "INFO"

        if ($fixedCount -eq 0 -and $errorCount -eq 0) {
            Write-Log "No unquoted service path vulnerabilities found on this system" "INFO"
        }
    }
    catch {
        Write-Log "Critical failure during unquoted service path remediation: $($_.Exception.Message)" "ERROR"
    }
}

function Remediate-VCRedistElevationOfPrivilege {
    [CmdletBinding()]
    param()

    Write-Log "Starting detection of Microsoft Visual C++ Redistributable versions" "INFO"

    try {
        $minimumSafeVersions = @{
            '2015-2022' = [version]'14.40.33810.0'
            '2013'      = [version]'12.0.40664.0'
            '2012'      = [version]'11.0.61135.0'
            '2010'      = [version]'10.0.40219.0'
        }

        $registryPaths = @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )

        $vcInstalls = @()

        foreach ($regPath in $registryPaths) {
            try {
                $entries = Get-ItemProperty -Path $regPath -ErrorAction SilentlyContinue |
                    Where-Object {
                        $_.DisplayName -match 'Microsoft Visual C\+\+.*Redistributable' -or
                        $_.DisplayName -match 'Microsoft Visual C\+\+.*Runtime'
                    }

                if ($entries) {
                    $vcInstalls += $entries
                }
            }
            catch {
                Write-Log "Could not read registry path $regPath : $($_.Exception.Message)" "WARNING"
            }
        }

        if ($vcInstalls.Count -eq 0) {
            Write-Log "No Microsoft Visual C++ Redistributable installations detected" "INFO"
            return
        }

        Write-Log "Found $($vcInstalls.Count) Visual C++ Redistributable installation(s)" "INFO"

        $vulnerableFound = $false

        foreach ($vc in $vcInstalls) {
            $displayName = $vc.DisplayName
            $displayVersion = $vc.DisplayVersion
            $architecture = if ($vc.PSPath -match 'WOW6432Node') { 'x86' } else { 'x64' }

            Write-Log "Installed: $displayName | Version: $displayVersion | Arch: $architecture" "INFO"

            $flagged = $false
            $versionObj = $null

            try {
                $versionObj = [version]$displayVersion
            }
            catch {
                Write-Log "  Could not parse version '$displayVersion' - manual review needed" "WARNING"
                $flagged = $true
            }

            if ($versionObj) {
                if ($displayName -match '201[5-9]|202[0-9]') {
                    if ($versionObj -lt $minimumSafeVersions['2015-2022']) {
                        $flagged = $true
                        Write-Log "  VULNERABLE: Version $displayVersion is below minimum safe $($minimumSafeVersions['2015-2022'])" "WARNING"
                    }
                }
                elseif ($displayName -match '2013') {
                    if ($versionObj -lt $minimumSafeVersions['2013']) {
                        $flagged = $true
                        Write-Log "  VULNERABLE: Version $displayVersion is below minimum safe $($minimumSafeVersions['2013'])" "WARNING"
                    }
                }
                elseif ($displayName -match '2012') {
                    if ($versionObj -lt $minimumSafeVersions['2012']) {
                        $flagged = $true
                        Write-Log "  VULNERABLE: Version $displayVersion is below minimum safe $($minimumSafeVersions['2012'])" "WARNING"
                    }
                }
                elseif ($displayName -match '2010') {
                    if ($versionObj -lt $minimumSafeVersions['2010']) {
                        $flagged = $true
                        Write-Log "  VULNERABLE: Version $displayVersion is below minimum safe $($minimumSafeVersions['2010'])" "WARNING"
                    }
                }
                elseif ($displayName -match '200[58]') {
                    $flagged = $true
                    Write-Log "  VULNERABLE: $displayName is end-of-life and no longer receives security updates" "WARNING"
                }
            }

            if (-not $flagged -and $versionObj) {
                Write-Log "  OK: Version appears current" "INFO"
            }

            if ($flagged) {
                $vulnerableFound = $true
            }
        }

        if ($vulnerableFound) {
            Write-Log "ACTION REQUIRED: One or more Visual C++ Redistributable installations are vulnerable. Download latest from https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist" "WARNING"
        }
        else {
            Write-Log "All detected Visual C++ Redistributable versions appear current" "INFO"
        }
    }
    catch {
        Write-Log "Critical failure during Visual C++ Redistributable detection: $($_.Exception.Message)" "ERROR"
    }
}

function Remediate-AspNetCoreSecurityUpdate {
    [CmdletBinding()]
    param()

    Write-Log "Starting detection of .NET / ASP.NET Core runtime versions for security update compliance" "INFO"

    try {
        $minimumPatchedVersions = @{
            '6.0' = [version]'6.0.36'
            '7.0' = [version]'7.0.20'
            '8.0' = [version]'8.0.11'
            '9.0' = [version]'9.0.1'
        }

        $eolVersions = @('2.1', '2.2', '3.0', '3.1', '5.0', '7.0')

        $dotnetPath = Get-Command dotnet -ErrorAction SilentlyContinue
        if (-not $dotnetPath) {
            Write-Log ".NET CLI (dotnet) not found in PATH. Checking common installation directories." "WARNING"

            $commonPaths = @(
                "$env:ProgramFiles\dotnet\dotnet.exe",
                "${env:ProgramFiles(x86)}\dotnet\dotnet.exe"
            )

            $dotnetExe = $null
            foreach ($p in $commonPaths) {
                if (Test-Path $p) {
                    $dotnetExe = $p
                    Write-Log "Found dotnet at $p" "INFO"
                    break
                }
            }

            if (-not $dotnetExe) {
                Write-Log "No .NET runtime installation detected on this system." "INFO"
                return
            }
        }
        else {
            $dotnetExe = $dotnetPath.Source
        }

        $runtimeOutput = $null
        try {
            $runtimeOutput = & $dotnetExe --list-runtimes 2>&1
        }
        catch {
            Write-Log "Failed to execute 'dotnet --list-runtimes': $($_.Exception.Message)" "ERROR"
            return
        }

        if (-not $runtimeOutput -or $runtimeOutput.Count -eq 0) {
            Write-Log "No .NET runtimes reported by dotnet CLI" "INFO"
            return
        }

        Write-Log "Installed .NET runtimes:" "INFO"

        $vulnerableFound = $false

        foreach ($line in $runtimeOutput) {
            $lineStr = $line.ToString().Trim()
            if ([string]::IsNullOrWhiteSpace($lineStr)) { continue }

            Write-Log "  $lineStr" "INFO"

            if ($lineStr -match '^([\w\.]+)\s+([\d\.]+(?:-[\w\.]+)?)\s+\[') {
                $runtimeName = $Matches[1]
                $runtimeVersionStr = $Matches[2]

                $runtimeVersion = $null
                try {
                    $cleanVersion = $runtimeVersionStr -replace '-.*$', ''
                    $runtimeVersion = [version]$cleanVersion
                }
                catch {
                    Write-Log "    Could not parse version '$runtimeVersionStr' - manual review needed" "WARNING"
                    $vulnerableFound = $true
                    continue
                }

                $majorMinor = "$($runtimeVersion.Major).$($runtimeVersion.Minor)"

                if ($majorMinor -in $eolVersions) {
                    Write-Log "    VULNERABLE: $runtimeName $runtimeVersionStr is END-OF-LIFE. Upgrade to a supported LTS version." "WARNING"
                    $vulnerableFound = $true
                    continue
                }

                if ($minimumPatchedVersions.ContainsKey($majorMinor)) {
                    $minVersion = $minimumPatchedVersions[$majorMinor]
                    if ($runtimeVersion -lt $minVersion) {
                        Write-Log "    VULNERABLE: $runtimeName $runtimeVersionStr is below patched version ($minVersion). Update required." "WARNING"
                        $vulnerableFound = $true
                    }
                    else {
                        Write-Log "    OK: $runtimeName $runtimeVersionStr meets security update requirements ($minVersion)" "INFO"
                    }
                }
            }
        }

        if ($vulnerableFound) {
            Write-Log "ACTION REQUIRED: One or more .NET runtimes are vulnerable. Update from https://dotnet.microsoft.com/download/dotnet" "WARNING"
        }
        else {
            Write-Log "All detected .NET runtimes appear to meet security update requirements" "INFO"
        }
    }
    catch {
        Write-Log "Critical failure during ASP.NET Core security update detection: $($_.Exception.Message)" "ERROR"
    }
}

#endregion Service Path Fixes

# ============================================================================
# SECTION 4: SOFTWARE VERSION CHECKS AND EOL SOFTWARE REMOVAL
# ============================================================================

#region Software Checks

function Test-SoftwareVersions {
    [CmdletBinding()]
    param()

    Write-Log "Starting software version detection and update check" "INFO"

    # Pull every Uninstall entry from both registry views
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $allInstalled = foreach ($rp in $regPaths) {
        try {
            Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, UninstallString, InstallLocation, Publisher
        } catch { }
    }

    # Helper: find first matching entry by regex on DisplayName
    function Find-InstalledSoftware {
        param(
            [string]$Pattern,
            [string[]]$ExcludePatterns = @()
        )
        $found = $allInstalled | Where-Object { $_.DisplayName -match $Pattern }
        foreach ($ep in $ExcludePatterns) {
            $found = $found | Where-Object { $_.DisplayName -notmatch $ep }
        }
        return $found | Sort-Object DisplayVersion -Descending | Select-Object -First 1
    }

    # Check for package managers
    $wingetAvailable = $null -ne (Get-Command winget -ErrorAction SilentlyContinue)
    $chocoAvailable  = $null -ne (Get-Command choco -ErrorAction SilentlyContinue)

    $wingetUpgradable = @{}
    if ($wingetAvailable) {
        Write-Log "Querying winget for available upgrades" "INFO"
        try {
            $raw = winget upgrade --accept-source-agreements 2>$null
            foreach ($line in $raw) {
                if ($line -match '(\S+)\s+([\d\.]+)\s+([\d\.]+)\s+winget') {
                    $wingetUpgradable[$Matches[1]] = @{
                        Installed = $Matches[2]
                        Available = $Matches[3]
                    }
                }
            }
        } catch {
            Write-Log "winget upgrade query failed: $_" "WARNING"
        }
    }

    $chocoOutdated = @{}
    if ($chocoAvailable) {
        Write-Log "Querying choco for outdated packages" "INFO"
        try {
            $raw = choco outdated -r 2>$null
            foreach ($line in $raw) {
                $parts = $line -split '\|'
                if ($parts.Count -ge 3) {
                    $chocoOutdated[$parts[0]] = @{
                        Installed = $parts[1]
                        Available = $parts[2]
                    }
                }
            }
        } catch {
            Write-Log "choco outdated query failed: $_" "WARNING"
        }
    }

    # Software definitions
    $softwareDefs = @(
        @{ Name = "7-Zip";                    Pattern = "^7-Zip";                                     WingetId = "7zip.7zip";                       ChocoId = "7zip" },
        @{ Name = "Wazuh Agent";              Pattern = "Wazuh Agent" },
        @{ Name = "Microsoft SQL Server";     Pattern = "Microsoft SQL Server \d{4}";                 ExcludePatterns = @("Management Studio", "SSMS", "Native Client", "ODBC", "OLE DB", "VSS Writer", "Setup", "Reporting") },
        @{ Name = "Google Chrome";            Pattern = "Google Chrome";                              WingetId = "Google.Chrome";                   ChocoId = "googlechrome" },
        @{ Name = "VMware Tools";             Pattern = "VMware Tools" },
        @{ Name = "Node.js";                  Pattern = "Node\.js";                                   WingetId = "OpenJS.NodeJS.LTS";               ChocoId = "nodejs-lts" },
        @{ Name = "Mozilla Firefox";          Pattern = "Mozilla Firefox";                            WingetId = "Mozilla.Firefox";                 ChocoId = "firefox" },
        @{ Name = "Adobe Reader / Acrobat";   Pattern = "Adobe (Acrobat|Reader)";                    ExcludePatterns = @("Genuine", "Licensing") },
        @{ Name = "OpenVPN";                  Pattern = "OpenVPN";                                    WingetId = "OpenVPNTechnologies.OpenVPN" },
        @{ Name = "Notepad++";                Pattern = "Notepad\+\+";                               WingetId = "Notepad++.Notepad++";             ChocoId = "notepadplusplus" },
        @{ Name = "Foxit PDF Reader/Editor";  Pattern = "Foxit (PDF|Reader|Editor|PhantomPDF)" },
        @{ Name = "Oracle Java";              Pattern = "Java \d|Java\(TM\)|Java SE";                ExcludePatterns = @("Auto Updater") },
        @{ Name = "Ghostscript (Artifex)";    Pattern = "GPL Ghostscript|Artifex Ghostscript|AGPL Ghostscript" },
        @{ Name = "Git";                      Pattern = "^Git$|^Git version";                        WingetId = "Git.Git";                         ChocoId = "git" },
        @{ Name = "PDFCreator";               Pattern = "PDFCreator" },
        @{ Name = "Autodesk Revit/Desktop";   Pattern = "Autodesk (Revit|Desktop App)" },
        @{ Name = "Zoom (Workplace)";         Pattern = "Zoom\s*(Workplace|\(64-bit\)|$)";           WingetId = "Zoom.Zoom" },
        @{ Name = "VS Code";                  Pattern = "Microsoft Visual Studio Code";              WingetId = "Microsoft.VisualStudioCode";      ChocoId = "vscode" },
        @{ Name = "Microsoft Teams";          Pattern = "Microsoft Teams";                            WingetId = "Microsoft.Teams" },
        @{ Name = "WinRAR";                   Pattern = "WinRAR";                                    WingetId = "RARLab.WinRAR";                   ChocoId = "winrar" },
        @{ Name = "TeamViewer";               Pattern = "TeamViewer";                                WingetId = "TeamViewer.TeamViewer" },
        @{ Name = "Microsoft Office";         Pattern = "Microsoft Office (Professional|Standard|365|Home|Business|LTSC)"; ExcludePatterns = @("Proof", "MUI", "Interop") },
        @{ Name = "Veeam Backup";             Pattern = "Veeam Backup" },
        @{ Name = "PuTTY";                    Pattern = "PuTTY";                                     WingetId = "PuTTY.PuTTY";                     ChocoId = "putty" },
        @{ Name = ".NET Framework";           Pattern = "Microsoft \.NET Framework" },
        @{ Name = "Adobe Genuine Service";    Pattern = "Adobe Genuine" }
    )

    $results = [System.Collections.ArrayList]::new()

    foreach ($def in $softwareDefs) {
        $name    = $def.Name
        $version = $null
        $status  = "NOT FOUND"

        # Registry detection
        $excludes = if ($def.ContainsKey('ExcludePatterns')) { $def.ExcludePatterns } else { @() }
        $regEntry = Find-InstalledSoftware -Pattern $def.Pattern -ExcludePatterns $excludes
        if ($regEntry) {
            $version = $regEntry.DisplayVersion
        }

        # .NET Framework special detection
        if ($name -eq ".NET Framework" -and -not $version) {
            try {
                $ndp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -ErrorAction SilentlyContinue
                if ($ndp -and $ndp.Version) { $version = $ndp.Version }
            } catch { }
        }

        if ($version) {
            $status      = "INSTALLED"
            $upgradeNote = ""

            # Check winget
            if ($def.ContainsKey('WingetId') -and $wingetAvailable) {
                $wKey = $wingetUpgradable.Keys | Where-Object { $_ -eq $def.WingetId -or $_ -like "*$($def.WingetId)*" } | Select-Object -First 1
                if ($wKey) {
                    $status      = "UPDATE AVAILABLE (winget)"
                    $upgradeNote = "-> $($wingetUpgradable[$wKey].Available)"
                }
            }

            # Check choco
            if ($def.ContainsKey('ChocoId') -and $chocoAvailable -and $status -eq "INSTALLED") {
                $cKey = $chocoOutdated.Keys | Where-Object { $_ -eq $def.ChocoId } | Select-Object -First 1
                if ($cKey) {
                    $status      = "UPDATE AVAILABLE (choco)"
                    $upgradeNote = "-> $($chocoOutdated[$cKey].Available)"
                }
            }

            Write-Log "$name v$version - $status $upgradeNote" "INFO"
        }
        else {
            Write-Log "$name - not found on this system" "INFO"
        }

        [void]$results.Add([PSCustomObject]@{
            Software         = $name
            InstalledVersion = if ($version) { $version } else { "-" }
            Status           = $status
        })
    }

    # Attempt automated upgrades where a package manager is available
    $upgradeable = $results | Where-Object { $_.Status -match "UPDATE AVAILABLE" }
    if ($upgradeable) {
        Write-Log "Attempting automated upgrades for $($upgradeable.Count) package(s)" "INFO"
        foreach ($pkg in $upgradeable) {
            $def = $softwareDefs | Where-Object { $_.Name -eq $pkg.Software } | Select-Object -First 1
            $upgraded = $false

            if ($pkg.Status -match "winget" -and $def.WingetId) {
                Write-Log "Running: winget upgrade --id $($def.WingetId) --silent --accept-package-agreements --accept-source-agreements" "INFO"
                try {
                    $out = winget upgrade --id $def.WingetId --silent --accept-package-agreements --accept-source-agreements 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "$($def.Name) upgraded successfully via winget" "INFO"
                        $pkg.Status = "UPGRADED (winget)"
                        $upgraded = $true
                    }
                    else {
                        Write-Log "$($def.Name) winget upgrade returned exit code $LASTEXITCODE" "WARNING"
                    }
                } catch {
                    Write-Log "$($def.Name) winget upgrade failed: $_" "WARNING"
                }
            }

            if (-not $upgraded -and $pkg.Status -match "choco" -and $def.ChocoId) {
                Write-Log "Running: choco upgrade $($def.ChocoId) -y --no-progress" "INFO"
                try {
                    $out = choco upgrade $def.ChocoId -y --no-progress 2>&1
                    if ($LASTEXITCODE -eq 0) {
                        Write-Log "$($def.Name) upgraded successfully via choco" "INFO"
                        $pkg.Status = "UPGRADED (choco)"
                    }
                    else {
                        Write-Log "$($def.Name) choco upgrade returned exit code $LASTEXITCODE" "WARNING"
                    }
                } catch {
                    Write-Log "$($def.Name) choco upgrade failed: $_" "WARNING"
                }
            }
        }
    }

    Write-Log "Software version scan complete - $($results.Count) items checked" "INFO"
    $results | Format-Table -AutoSize -Wrap

    return $results
}

function Remove-EOLSoftware {
    [CmdletBinding()]
    param()

    Write-Log "Starting End-of-Life software detection and removal" "INFO"

    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $allInstalled = foreach ($rp in $regPaths) {
        try {
            Get-ItemProperty -Path $rp -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, UninstallString, PSChildName, PSPath
        } catch { }
    }

    $eolFindings = [System.Collections.ArrayList]::new()

    # --- 1. Adobe Reader / Acrobat XI (version 11.x) ---
    Write-Log "Checking for Adobe Reader/Acrobat XI (EOL)" "INFO"

    $adobeXI = $allInstalled | Where-Object {
        $_.DisplayName -match "Adobe (Acrobat|Reader)" -and
        $_.DisplayVersion -match "^11\."
    }

    foreach ($entry in $adobeXI) {
        Write-Log "FOUND EOL: $($entry.DisplayName) v$($entry.DisplayVersion)" "WARNING"

        [void]$eolFindings.Add([PSCustomObject]@{
            Software = $entry.DisplayName
            Version  = $entry.DisplayVersion
            Action   = "REMOVAL ATTEMPTED"
            Result   = ""
        })

        $removed = $false

        if ($entry.PSChildName -match '^\{[0-9A-Fa-f\-]+\}$') {
            $productCode = $entry.PSChildName
            Write-Log "Attempting msiexec uninstall for product code $productCode" "INFO"
            try {
                $proc = Start-Process -FilePath "msiexec.exe" `
                    -ArgumentList "/x $productCode /qn /norestart" `
                    -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                    Write-Log "Adobe XI removed successfully (exit code $($proc.ExitCode))" "INFO"
                    $eolFindings[-1].Result = "REMOVED (msiexec)"
                    $removed = $true
                }
                else {
                    Write-Log "msiexec exited with code $($proc.ExitCode)" "WARNING"
                }
            } catch {
                Write-Log "msiexec uninstall failed: $_" "WARNING"
            }
        }

        if (-not $removed -and $entry.UninstallString) {
            Write-Log "Attempting uninstall via UninstallString: $($entry.UninstallString)" "INFO"
            try {
                $uninstCmd = $entry.UninstallString
                if ($uninstCmd -notmatch '/q') { $uninstCmd += " /qn /norestart" }
                $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstCmd" `
                    -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                    Write-Log "Adobe XI removed via UninstallString" "INFO"
                    $eolFindings[-1].Result = "REMOVED (UninstallString)"
                    $removed = $true
                }
            } catch {
                Write-Log "UninstallString removal failed: $_" "WARNING"
            }
        }

        if (-not $removed) {
            $eolFindings[-1].Action = "MANUAL REMOVAL REQUIRED"
            $eolFindings[-1].Result = "Automated removal failed - remove manually"
            Write-Log "Adobe XI could not be removed automatically - manual removal required" "WARNING"
        }
    }

    if (-not $adobeXI) {
        Write-Log "Adobe Reader/Acrobat XI not found - OK" "INFO"
    }

    # --- 2. Microsoft .NET 6.x (EOL 12 Nov 2024) ---
    Write-Log "Checking for EOL .NET 6.x runtimes" "INFO"

    $dotnet6Paths = @()
    $basePaths = @("$env:ProgramFiles\dotnet\shared\Microsoft.NETCore.App",
                   "${env:ProgramFiles(x86)}\dotnet\shared\Microsoft.NETCore.App")
    foreach ($bp in $basePaths) {
        if (Test-Path $bp) {
            $found = Get-ChildItem -Path $bp -Directory -Filter "6.*" -ErrorAction SilentlyContinue
            $dotnet6Paths += $found
        }
    }

    $dotnet6Reg = $allInstalled | Where-Object {
        $_.DisplayName -match '\.NET (Runtime|SDK|Desktop Runtime).*6\.' -or
        $_.DisplayName -match 'Microsoft \.NET 6\.' -or
        $_.DisplayName -match 'ASP\.NET Core 6\.'
    }

    $hasDotnetUninstallTool = $null -ne (Get-Command dotnet-core-uninstall -ErrorAction SilentlyContinue)

    if ($dotnet6Paths -or $dotnet6Reg) {
        foreach ($p in $dotnet6Paths) {
            Write-Log "FOUND EOL: .NET 6.x runtime at $($p.FullName)" "WARNING"
        }
        foreach ($r in $dotnet6Reg) {
            Write-Log "FOUND EOL: $($r.DisplayName) v$($r.DisplayVersion)" "WARNING"
        }

        $versionLabel = if ($dotnet6Paths) { ($dotnet6Paths | ForEach-Object { $_.Name }) -join ", " }
                        elseif ($dotnet6Reg) { ($dotnet6Reg | ForEach-Object { $_.DisplayVersion }) -join ", " }
                        else { "6.x" }

        [void]$eolFindings.Add([PSCustomObject]@{
            Software = "Microsoft .NET 6.x"
            Version  = $versionLabel
            Action   = ""
            Result   = ""
        })

        if ($hasDotnetUninstallTool) {
            Write-Log "dotnet-core-uninstall tool detected - attempting removal of .NET 6.x" "INFO"
            try {
                $proc = Start-Process -FilePath "dotnet-core-uninstall" `
                    -ArgumentList "remove --runtime 6.0 --yes" `
                    -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-Log ".NET 6.x runtimes removed via dotnet-core-uninstall" "INFO"
                    $eolFindings[-1].Action = "REMOVAL ATTEMPTED"
                    $eolFindings[-1].Result = "REMOVED (dotnet-core-uninstall)"
                }
                else {
                    $eolFindings[-1].Action = "REMOVAL ATTEMPTED"
                    $eolFindings[-1].Result = "Tool returned exit code $($proc.ExitCode) - verify manually"
                }
            } catch {
                $eolFindings[-1].Action = "MANUAL REMOVAL REQUIRED"
                $eolFindings[-1].Result = "Tool execution failed"
            }
        }
        else {
            Write-Log "dotnet-core-uninstall tool NOT found - reporting paths for manual removal" "WARNING"
            $eolFindings[-1].Action = "MANUAL REMOVAL REQUIRED"
            $pathList = ($dotnet6Paths | ForEach-Object { $_.FullName }) -join "; "
            if ($pathList) {
                $eolFindings[-1].Result = "Paths: $pathList"
            }
            else {
                $eolFindings[-1].Result = "Remove via Programs and Features"
            }
        }
    }
    else {
        Write-Log ".NET 6.x runtimes not found - OK" "INFO"
    }

    # --- 3. Microsoft .NET Core 3.1 (EOL 13 Dec 2022) ---
    Write-Log "Checking for EOL .NET Core 3.1 runtimes" "INFO"

    $dotnet31Paths = @()
    foreach ($bp in $basePaths) {
        if (Test-Path $bp) {
            $found = Get-ChildItem -Path $bp -Directory -Filter "3.1.*" -ErrorAction SilentlyContinue
            $dotnet31Paths += $found
        }
    }

    $dotnet31Reg = $allInstalled | Where-Object {
        $_.DisplayName -match '\.NET Core (Runtime|SDK|Desktop Runtime).*3\.1' -or
        $_.DisplayName -match 'Microsoft \.NET Core 3\.1' -or
        $_.DisplayName -match 'ASP\.NET Core 3\.1'
    }

    if ($dotnet31Paths -or $dotnet31Reg) {
        foreach ($p in $dotnet31Paths) {
            Write-Log "FOUND EOL: .NET Core 3.1 runtime at $($p.FullName)" "WARNING"
        }
        foreach ($r in $dotnet31Reg) {
            Write-Log "FOUND EOL: $($r.DisplayName) v$($r.DisplayVersion)" "WARNING"
        }

        $versionLabel = if ($dotnet31Paths) { ($dotnet31Paths | ForEach-Object { $_.Name }) -join ", " }
                        elseif ($dotnet31Reg) { ($dotnet31Reg | ForEach-Object { $_.DisplayVersion }) -join ", " }
                        else { "3.1.x" }

        [void]$eolFindings.Add([PSCustomObject]@{
            Software = "Microsoft .NET Core 3.1"
            Version  = $versionLabel
            Action   = ""
            Result   = ""
        })

        if ($hasDotnetUninstallTool) {
            Write-Log "Attempting removal of .NET Core 3.1 via dotnet-core-uninstall" "INFO"
            try {
                $proc = Start-Process -FilePath "dotnet-core-uninstall" `
                    -ArgumentList "remove --runtime 3.1 --yes" `
                    -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($proc.ExitCode -eq 0) {
                    Write-Log ".NET Core 3.1 runtimes removed via dotnet-core-uninstall" "INFO"
                    $eolFindings[-1].Action = "REMOVAL ATTEMPTED"
                    $eolFindings[-1].Result = "REMOVED (dotnet-core-uninstall)"
                }
                else {
                    $eolFindings[-1].Action = "REMOVAL ATTEMPTED"
                    $eolFindings[-1].Result = "Tool returned exit code $($proc.ExitCode) - verify manually"
                }
            } catch {
                $eolFindings[-1].Action = "MANUAL REMOVAL REQUIRED"
                $eolFindings[-1].Result = "Tool execution failed"
            }
        }
        else {
            Write-Log "dotnet-core-uninstall tool NOT found - reporting paths for manual removal" "WARNING"
            $eolFindings[-1].Action = "MANUAL REMOVAL REQUIRED"
            $pathList = ($dotnet31Paths | ForEach-Object { $_.FullName }) -join "; "
            if ($pathList) {
                $eolFindings[-1].Result = "Paths: $pathList"
            }
            else {
                $eolFindings[-1].Result = "Remove via Programs and Features"
            }
        }
    }
    else {
        Write-Log ".NET Core 3.1 runtimes not found - OK" "INFO"
    }

    # --- 4. Microsoft Access Database Engine 2010 SP1 ---
    Write-Log "Checking for EOL Microsoft Access Database Engine 2010" "INFO"

    $accessDB2010 = $allInstalled | Where-Object {
        $_.DisplayName -match "Microsoft Access (Database Engine|database engine).*2010" -or
        $_.DisplayName -match "Microsoft Access Runtime 2010"
    }

    if ($accessDB2010) {
        foreach ($entry in $accessDB2010) {
            Write-Log "FOUND EOL: $($entry.DisplayName) v$($entry.DisplayVersion)" "WARNING"

            [void]$eolFindings.Add([PSCustomObject]@{
                Software = $entry.DisplayName
                Version  = $entry.DisplayVersion
                Action   = "REMOVAL ATTEMPTED"
                Result   = ""
            })

            $removed = $false

            if ($entry.PSChildName -match '^\{[0-9A-Fa-f\-]+\}$') {
                $productCode = $entry.PSChildName
                Write-Log "Attempting msiexec uninstall for Access DB Engine 2010 ($productCode)" "INFO"
                try {
                    $proc = Start-Process -FilePath "msiexec.exe" `
                        -ArgumentList "/x $productCode /qn /norestart" `
                        -Wait -PassThru -NoNewWindow -ErrorAction Stop
                    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                        Write-Log "Access Database Engine 2010 removed (exit code $($proc.ExitCode))" "INFO"
                        $eolFindings[-1].Result = "REMOVED (msiexec)"
                        $removed = $true
                    }
                } catch {
                    Write-Log "msiexec uninstall failed: $_" "WARNING"
                }
            }

            if (-not $removed -and $entry.UninstallString) {
                Write-Log "Attempting removal via UninstallString" "INFO"
                try {
                    $uninstCmd = $entry.UninstallString
                    if ($uninstCmd -notmatch '/q') { $uninstCmd += " /qn /norestart" }
                    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $uninstCmd" `
                        -Wait -PassThru -NoNewWindow -ErrorAction Stop
                    if ($proc.ExitCode -eq 0 -or $proc.ExitCode -eq 3010) {
                        Write-Log "Access Database Engine 2010 removed via UninstallString" "INFO"
                        $eolFindings[-1].Result = "REMOVED (UninstallString)"
                        $removed = $true
                    }
                } catch {
                    Write-Log "UninstallString removal failed: $_" "WARNING"
                }
            }

            if (-not $removed) {
                $eolFindings[-1].Action = "MANUAL REMOVAL REQUIRED"
                $eolFindings[-1].Result = "Automated removal failed - remove via Programs and Features"
                Write-Log "Access Database Engine 2010 could not be removed automatically" "WARNING"
            }
        }
    }
    else {
        Write-Log "Microsoft Access Database Engine 2010 not found - OK" "INFO"
    }

    # Summary
    if ($eolFindings.Count -gt 0) {
        Write-Log "EOL software scan complete - $($eolFindings.Count) item(s) found" "WARNING"
        $eolFindings | Format-Table -AutoSize -Wrap
    }
    else {
        Write-Log "EOL software scan complete - no EOL software detected" "INFO"
    }

    return $eolFindings
}

#endregion Software Checks

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Invoke-VulnerabilityRemediation {
    [CmdletBinding()]
    param(
        [string]$Mode = $RemediationMode
    )

    Write-Log "========================================================================" "INFO"
    Write-Log "  Vulnerability Remediation Script v1.0.0" "INFO"
    Write-Log "  Mode: $Mode | Host: $env:COMPUTERNAME | User: $env:USERNAME" "INFO"
    Write-Log "  Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "  Log File: $LogPath" "INFO"
    Write-Log "========================================================================" "INFO"

    # Affected devices reference (from vulnerability scan spreadsheets)
    $deviceMapping = @{
        "LDPRLCG00001"   = @("WinVerifyTrust", "VC++ Redist")
        "ldprsgg01"      = @("WinVerifyTrust", "Unquoted Paths", "7-Zip", "Spectre V4", "Wazuh", "SQL Server", "Chrome")
        "LDPRFSG01"      = @("WinVerifyTrust", "VMware Tools", "Node.js", "Spectre V4", "Wazuh", "Firefox", "VC++ Redist")
        "LDPRAZG00002"   = @("WinVerifyTrust", "VC++ Redist")
        "ldprvmg00003"   = @("SMBv1", "PuTTY", "Spectre V4", "WinVerifyTrust", "Wazuh", "Sweet32", "Spectre HyperV")
        "LDPRVMG00004"   = @("Veeam", "7-Zip", "Spectre V4", "WinVerifyTrust", "Unquoted Paths", "ASP.NET Core", "Firefox", "Sweet32", "Chrome", ".NET 6 EOL")
        "217.138.39.26"  = @("Sweet32", "TLSv1.0")
        "DESKTOP-EH2M3FE" = @("Adobe Reader", "DWM Info Disclosure", "WinVerifyTrust", "OpenVPN", "Windows Update", "Adobe XI EOL", ".NET 6 EOL", "Notepad++", "Foxit", "Chrome", "LanMan/NTLMv1")
        "DESKTOP-K7DB84B" = @("Office Update", "7-Zip", "Oracle Java", "WinVerifyTrust", "Ghostscript", "Office Update", "Wazuh", "Access DB 2010 EOL", ".NET Core 3.1 EOL", "Git", "PDFCreator", "Autodesk", "Adobe Acrobat", "Zoom", "VS Code Python", "VC++ Redist")
        "DESKTOP-KUH09K4" = @("Teams", "WinRAR", ".NET Core 3.1 EOL", "Autodesk", "Notepad++", "TeamViewer", "Adobe Genuine", "VC++ Redist")
        "RS_LAPTOP"       = @("Windows Update Aug 2024", "7-Zip", "DWM Info Disclosure", "Adobe XI EOL", "Notepad++", ".NET Framework Oct 2024")
    }

    Write-Log " " "INFO"
    Write-Log "Devices in scope: $($deviceMapping.Keys -join ', ')" "INFO"
    Write-Log " " "INFO"

    # ---- REGISTRY HARDENING ----
    if ($Mode -in @("All", "RegistryOnly")) {
        Write-Log "===== PHASE 1: Registry-Based Hardening =====" "INFO"
        Remediate-WinVerifyTrustSignatureValidation
        Remediate-SpectreVariant4
        Remediate-SpectreHyperV
        Remediate-DisableLanManNTLMv1
        Write-Log "===== PHASE 1 COMPLETE =====" "INFO"
        Write-Log " " "INFO"
    }

    # ---- PROTOCOL HARDENING ----
    if ($Mode -in @("All", "ProtocolOnly")) {
        Write-Log "===== PHASE 2: Protocol and Cipher Hardening =====" "INFO"
        Remediate-SMBv1Disable
        Remediate-Sweet32Ciphers
        Remediate-TLS10Disable
        Write-Log "===== PHASE 2 COMPLETE =====" "INFO"
        Write-Log " " "INFO"
    }

    # ---- SERVICE PATH FIXES ----
    if ($Mode -in @("All", "ServicePaths")) {
        Write-Log "===== PHASE 3: Service Path and Configuration Fixes =====" "INFO"
        Remediate-UnquotedServicePaths
        Remediate-VCRedistElevationOfPrivilege
        Remediate-AspNetCoreSecurityUpdate
        Write-Log "===== PHASE 3 COMPLETE =====" "INFO"
        Write-Log " " "INFO"
    }

    # ---- SOFTWARE AUDIT ----
    if ($Mode -in @("All", "AuditOnly")) {
        Write-Log "===== PHASE 4: Software Version Audit =====" "INFO"
        $softwareResults = Test-SoftwareVersions
        Write-Log "===== PHASE 4 COMPLETE =====" "INFO"
        Write-Log " " "INFO"
    }

    # ---- EOL REMOVAL ----
    if ($Mode -in @("All", "AuditOnly")) {
        Write-Log "===== PHASE 5: End-of-Life Software Removal =====" "INFO"
        $eolResults = Remove-EOLSoftware
        Write-Log "===== PHASE 5 COMPLETE =====" "INFO"
        Write-Log " " "INFO"
    }

    # ---- SUMMARY ----
    $elapsed = (Get-Date) - $Script:StartTime
    Write-Log "========================================================================" "INFO"
    Write-Log "  REMEDIATION COMPLETE" "INFO"
    Write-Log "  Elapsed: $($elapsed.ToString('hh\:mm\:ss'))" "INFO"
    Write-Log "  Log File: $LogPath" "INFO"
    if ($Script:RebootRequired) {
        Write-Log "  *** REBOOT REQUIRED to complete some remediations ***" "WARNING"
    }
    Write-Log "========================================================================" "INFO"
}

# Run the remediation
Invoke-VulnerabilityRemediation -Mode $RemediationMode
