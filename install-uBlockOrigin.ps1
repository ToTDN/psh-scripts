# Create log file
$logFile = "C:\temp\ublock_install.log"
Start-Transcript -Path $logFile -Force

$extensionData = @{
    Chrome  = @{
        StoreURL = "https://chrome.google.com/webstore/detail/ublock-origin/cjpalhdlnbpafiamejdnhcphjbkeiagm"
        ExtID    = "cjpalhdlnbpafiamejdnhcphjbkeiagm"
    }
    Edge    = @{
        StoreURL = "https://microsoftedge.microsoft.com/addons/detail/ublock-origin/odfafepnkmbhccpbejgmiehpchacaeak"
        ExtID    = "odfafepnkmbhccpbejgmiehpchacaeak"
    }
    Firefox = @{
        StoreURL = "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin"
        ExtID    = "uBlock0@raymondhill.net"
    }
}

function Test-BrowserInstalled {
    param (
        [string]$BrowserName
    )
    
    $paths = @{
        Chrome  = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        Edge    = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        Firefox = "C:\Program Files\Mozilla Firefox\firefox.exe"
    }
    
    return Test-Path -Path $paths[$BrowserName]
}

function Install-ChromeExtension {
    param (
        [string]$ExtensionID
    )
    $registryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }
    $entries = Get-ItemProperty -Path $registryPath
    $nextIndex = 1
    if ($entries.PSObject.Properties.Name -match '^\d+$') {
        $nextIndex = ([int[]]$entries.PSObject.Properties.Name | Measure-Object -Maximum).Maximum + 1
    }
    New-ItemProperty -Path $registryPath -Name $nextIndex -Value "$ExtensionID;https://clients2.google.com/service/update2/crx" -PropertyType STRING -Force
}

function Install-EdgeExtension {
    param (
        [string]$ExtensionID
    )
    
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
    
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force
    }
    
    $entries = Get-ItemProperty -Path $registryPath
    $nextIndex = 1
    if ($entries.PSObject.Properties.Name -match '^\d+$') {
        $nextIndex = ([int[]]$entries.PSObject.Properties.Name | Measure-Object -Maximum).Maximum + 1
    }
    
    New-ItemProperty -Path $registryPath -Name $nextIndex -Value "$ExtensionID;https://edge.microsoft.com/extensionwebstorebase/v1/crx" -PropertyType STRING -Force
}

function Install-FirefoxExtension {
    param (
        [string]$ExtensionID
    )
    
    $policiesPath = "C:\Program Files\Mozilla Firefox\distribution"
    $policiesFile = "$policiesPath\policies.json"
    
    if (-not (Test-Path $policiesPath)) {
        New-Item -Path $policiesPath -ItemType Directory -Force
    }
    
    $policy = @{
        policies = @{
            Extensions = @{
                Install = @("https://addons.mozilla.org/firefox/downloads/latest/ublock-origin")
            }
        }
    }
    
    $policy | ConvertTo-Json -Depth 10 | Set-Content $policiesFile
}

try {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator"
    }

    if (Test-BrowserInstalled -BrowserName "Chrome") {
        Write-Host "Installing uBlock Origin for Chrome..."
        Install-ChromeExtension -ExtensionID $extensionData.Chrome.ExtID
    }

    if (Test-BrowserInstalled -BrowserName "Edge") {
        Write-Host "Installing uBlock Origin for Edge..."
        Install-EdgeExtension -ExtensionID $extensionData.Edge.ExtID
    }

    if (Test-BrowserInstalled -BrowserName "Firefox") {
        Write-Host "Installing uBlock Origin for Firefox..."
        Install-FirefoxExtension -ExtensionID $extensionData.Firefox.ExtID
    }

    Write-Host "Installation completed successfully"
} catch {
    Write-Error "Error occurred: $_"
    exit 1
} finally {
    Stop-Transcript
}
