# Create log file
$logFile = "C:\temp\openshell_install.log"
Start-Transcript -Path $logFile -Force

function Set-IntuneStartButton {
    # Create OpenShell custom button directory
    $customButtonPath = "$env:ProgramFiles\Open-Shell\Customized"
    if (-not (Test-Path $customButtonPath)) {
        New-Item -Path $customButtonPath -ItemType Directory -Force | Out-Null
    }

    # Download Intune logo
    $intuneLogoUrl = "https://raw.githubusercontent.com/microsoft/Intune-Resource-Access/master/src/assets/Intune.png"
    $logoPath = "$customButtonPath\intune_button.png"
    
    try {
        Invoke-WebRequest -Uri $intuneLogoUrl -OutFile $logoPath
        Write-Host "Intune logo downloaded successfully"
        
        # Configure custom button in registry
        $buttonPath = "HKCU:\Software\OpenShell\StartMenu\Settings"
        if (-not (Test-Path $buttonPath)) {
            New-Item -Path $buttonPath -Force | Out-Null
        }

        # Set custom button configuration
        $buttonSettings = @{
            "StartButtonType" = 2  # Custom image
            "CustomButtonFile" = $logoPath
            "CustomButtonColor" = 0xFFFFFF  # White background
        }

        foreach ($setting in $buttonSettings.GetEnumerator()) {
            if ($setting.Name -eq "CustomButtonFile") {
                New-ItemProperty -Path $buttonPath -Name $setting.Key -Value $setting.Value -PropertyType STRING -Force | Out-Null
            } else {
                New-ItemProperty -Path $buttonPath -Name $setting.Key -Value $setting.Value -PropertyType DWORD -Force | Out-Null
            }
        }
    } catch {
        Write-Warning "Failed to set custom start button: $_"
        # Fallback to Windows 7 style if custom button fails
        New-ItemProperty -Path $buttonPath -Name "StartButtonType" -Value 1 -PropertyType DWORD -Force | Out-Null
    }
}

try {
    # Check if running as admin
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator"
    }

    # Create temp directory if it doesn't exist
    if (-not (Test-Path "C:\temp")) {
        New-Item -ItemType Directory -Path "C:\temp"
    }

    # Download Open Shell
    $openShellUrl = "https://github.com/Open-Shell/Open-Shell-Menu/releases/download/v4.4.191/OpenShellSetup_4_4_191.exe"
    $installerPath = "C:\temp\OpenShellSetup.exe"

    Write-Host "Downloading Open Shell..."
    Invoke-WebRequest -Uri $openShellUrl -OutFile $installerPath

    # Install Open Shell silently
    Write-Host "Installing Open Shell..."
    $process = Start-Process -FilePath $installerPath -ArgumentList "/quiet", "/norestart" -NoNewWindow -PassThru -Wait

    if ($process.ExitCode -ne 0) {
        throw "Installation failed with exit code: $($process.ExitCode)"
    }

    # Wait for installation to complete
    Start-Sleep -Seconds 10

    # Configure Windows 7 style settings
    $registryPath = "HKCU:\Software\OpenShell\StartMenu"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }

    # Set Windows 7 style configuration
    $dwordSettings = @{
        "SkinW7"            = 1
        "ShiftWin"          = 1
        "CustomColors"      = 0
        "MainMenuAnimation" = 0  # Disable animation
        "MenuShadow"        = 1
        "EnableAccessibility" = 1
        "SearchBox"         = 1
        "SearchTrack"       = 1
        "WindowsMenu"       = 1
        "AllProgramsMetro"  = 0
        "RecentMetro"       = 0
        "MaxRecentPrograms" = 15
        "GlassOverride"     = 1
        "GlassColor"        = 0
        "BorderW7"          = 1
        "CascadeButtons"    = 1
        "MainMenuPopupDelay" = 0  # Remove main menu delay
        "SubMenuPopupDelay" = 0   # Remove submenu delay
        "MouseClick"        = 0
        "ShiftClick"        = 0
        "PinnedPrograms"    = 1
        "RecentPrograms"    = 1
        "StartScreenShortcut" = 0
        "MenuDelay"         = 0   # Additional delay setting
        "AnimationSpeed"    = 0   # Fastest animation
        "MenuSpeed"         = 0   # Instant menu display
        "ShowDelay"         = 0   # Remove hover delay
        "HideDelay"         = 0   # Remove menu hiding delay
    }

    $stringSettings = @{
        "SkinVariationW7"   = "Windows 7"
    }

    foreach ($setting in $dwordSettings.GetEnumerator()) {
        New-ItemProperty -Path $registryPath -Name $setting.Key -Value $setting.Value -PropertyType DWORD -Force | Out-Null
    }

    foreach ($setting in $stringSettings.GetEnumerator()) {
        New-ItemProperty -Path $registryPath -Name $setting.Key -Value $setting.Value -PropertyType String -Force | Out-Null
    }

    # Create Windows 7 start button configuration
    $buttonPath = "HKCU:\Software\OpenShell\StartMenu\Settings"
    if (-not (Test-Path $buttonPath)) {
        New-Item -Path $buttonPath -Force | Out-Null
    }

    New-ItemProperty -Path $buttonPath -Name "StartButtonType" -Value 1 -PropertyType DWORD -Force | Out-Null
    
    # Add Intune branding
    Write-Host "Configuring Intune branding..."
    Set-IntuneStartButton

    Write-Host "Installation and configuration completed successfully. Please log off and back on for changes to take effect."

} catch {
    Write-Error "Error occurred: $_"
    exit 1
} finally {
    # Cleanup
    if (Test-Path $installerPath) {
        Remove-Item -Path $installerPath -Force
    }
    Stop-Transcript
}
