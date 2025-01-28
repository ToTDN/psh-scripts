[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ServerUrl = "https://vaultwarden.vitalytics.co.uk"
)

$logFile = "C:\temp\bitwarden_install.log"
Start-Transcript -Path $logFile -Force

Write-Host "Using Bitwarden server: $ServerUrl"

$extensionData = @{
    Chrome  = @{
        ExtID    = "nngceckbapebfimnlniiiahkandclblb"
    }
    Edge    = @{
        ExtID    = "jbkfoedolllekgbhcbcoahefnbanhhlh"
    }
    Firefox = @{
        ExtID    = "bitwarden-password-manager@bitwarden.com"
    }
}

function Test-BrowserInstalled {
    param ([string]$BrowserName)
    
    $paths = @{
        Chrome  = "C:\Program Files\Google\Chrome\Application\chrome.exe"
        Edge    = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        Firefox = "C:\Program Files\Mozilla Firefox\firefox.exe"
    }
    
    return Test-Path -Path $paths[$BrowserName]
}

function Install-ChromeExtension {
    param ([string]$ExtensionID)
    
    $registryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    
    # Get existing properties and find next available index
    $entries = (Get-Item -Path $registryPath).Property
    $nextIndex = 1
    if ($entries) {
        $existingIndices = $entries | ForEach-Object { [int]$_ }
        if ($existingIndices) {
            $nextIndex = ($existingIndices | Measure-Object -Maximum).Maximum + 1
        }
    }
    
    New-ItemProperty -Path $registryPath -Name $nextIndex -Value "$ExtensionID;https://clients2.google.com/service/update2/crx" -PropertyType STRING -Force
}

function Install-EdgeExtension {
    param ([string]$ExtensionID)
    
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    
    # Get existing properties and find next available index
    $entries = (Get-Item -Path $registryPath).Property
    $nextIndex = 1
    if ($entries) {
        $existingIndices = $entries | ForEach-Object { [int]$_ }
        if ($existingIndices) {
            $nextIndex = ($existingIndices | Measure-Object -Maximum).Maximum + 1
        }
    }
    
    New-ItemProperty -Path $registryPath -Name $nextIndex -Value "$ExtensionID;https://edge.microsoft.com/extensionwebstorebase/v1/crx" -PropertyType STRING -Force
}

function Install-FirefoxExtension {
    param ([string]$ExtensionID)
    
    $policiesPath = "C:\Program Files\Mozilla Firefox\distribution"
    $policiesFile = "$policiesPath\policies.json"
    
    if (-not (Test-Path $policiesPath)) {
        New-Item -Path $policiesPath -ItemType Directory -Force | Out-Null
    }
    
    $policy = @{
        policies = @{
            Extensions = @{
                Install = @("https://addons.mozilla.org/firefox/downloads/latest/bitwarden-password-manager")
            }
        }
    }
    
    $policy | ConvertTo-Json -Depth 10 | Set-Content $policiesFile
}

function Set-BitwardenEnvironmentConfig {
    param ([string]$ServerUrl)
    
    $appDataPath = [Environment]::GetFolderPath('ApplicationData')
    $configPath = "$appDataPath\Bitwarden\data.json"
    
    if (Test-Path $configPath) {
        try {
            $config = Get-Content $configPath | ConvertFrom-Json
            
            if (-not $config.environmentUrls) {
                $config | Add-Member -Name "environmentUrls" -Value @{
                    base = $ServerUrl
                    api = "$ServerUrl/api"
                    identity = "$ServerUrl/identity"
                    webVault = "$ServerUrl"
                    icons = "$ServerUrl/icons"
                    notifications = "$ServerUrl/notifications"
                    events = "$ServerUrl/events"
                } -MemberType NoteProperty
            } else {
                $config.environmentUrls.base = $ServerUrl
                $config.environmentUrls.api = "$ServerUrl/api"
                $config.environmentUrls.identity = "$ServerUrl/identity"
                $config.environmentUrls.webVault = "$ServerUrl"
                $config.environmentUrls.icons = "$ServerUrl/icons"
                $config.environmentUrls.notifications = "$ServerUrl/notifications"
                $config.environmentUrls.events = "$ServerUrl/events"
            }
            
            $config | ConvertTo-Json -Depth 10 | Set-Content $configPath
            Write-Host "Desktop client configuration updated successfully"
        } catch {
            Write-Warning "Failed to update desktop client configuration: $_"
        }
    } else {
        Write-Warning "Bitwarden desktop configuration file not found. It will be created when the application first runs."
    }
    
    $browsers = @{
        Chrome = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$($extensionData.Chrome.ExtID)"
        Edge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$($extensionData.Edge.ExtID)"
    }
    
    foreach ($browser in $browsers.GetEnumerator()) {
        if (-not (Test-Path $browser.Value)) {
            New-Item -Path $browser.Value -Force | Out-Null
        }
        
        $policy = @{
            environment = @{
                base_url = $ServerUrl
            }
        }
        
        New-ItemProperty -Path $browser.Value -Name "policy" -Value ($policy | ConvertTo-Json -Compress) -PropertyType STRING -Force
    }
    
    $firefoxPoliciesPath = "C:\Program Files\Mozilla Firefox\distribution\policies.json"
    if (Test-Path $firefoxPoliciesPath) {
        $policies = Get-Content $firefoxPoliciesPath | ConvertFrom-Json
        if (-not $policies.policies.PSObject.Properties["3rdparty"]) {
            $policies.policies | Add-Member -Name "3rdparty" -Value @{} -MemberType NoteProperty
        }
        $policies.policies."3rdparty" | Add-Member -Name "Extensions" -Value @{
            "bitwarden-password-manager@bitwarden.com" = @{
                environment = @{
                    base_url = $ServerUrl
                }
            }
        } -MemberType NoteProperty -Force
        $policies | ConvertTo-Json -Depth 10 | Set-Content $firefoxPoliciesPath
    }
}

function Disable-BuiltInPasswordManagers {
    $chromeRegistryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
    if (-not (Test-Path $chromeRegistryPath)) {
        New-Item -Path $chromeRegistryPath -Force | Out-Null
    }
    New-ItemProperty -Path $chromeRegistryPath -Name "PasswordManagerEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null

    $edgeRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    if (-not (Test-Path $edgeRegistryPath)) {
        New-Item -Path $edgeRegistryPath -Force | Out-Null
    }
    New-ItemProperty -Path $edgeRegistryPath -Name "PasswordManagerEnabled" -Value 0 -PropertyType DWORD -Force | Out-Null

    $firefoxPoliciesPath = "C:\Program Files\Mozilla Firefox\distribution\policies.json"
    if (Test-Path $firefoxPoliciesPath) {
        $policies = Get-Content $firefoxPoliciesPath | ConvertFrom-Json
        
        if (-not $policies.policies.PSObject.Properties["PasswordManager"]) {
            $policies.policies | Add-Member -Name "PasswordManager" -Value @{
                Enabled = $false
            } -MemberType NoteProperty
        } else {
            $policies.policies.PasswordManager.Enabled = $false
        }
        
        $policies | ConvertTo-Json -Depth 10 | Set-Content $firefoxPoliciesPath
    } else {
        $policies = @{
            policies = @{
                PasswordManager = @{
                    Enabled = $false
                }
            }
        }
        if (-not (Test-Path (Split-Path $firefoxPoliciesPath))) {
            New-Item -Path (Split-Path $firefoxPoliciesPath) -ItemType Directory -Force | Out-Null
        }
        $policies | ConvertTo-Json -Depth 10 | Set-Content $firefoxPoliciesPath
    }

    Write-Host "Built-in password managers have been disabled for Chrome, Edge, and Firefox"
}

try {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run as Administrator"
    }

    Write-Host "Disabling built-in browser password managers..."
    Disable-BuiltInPasswordManagers

    Write-Host "Installing Bitwarden Desktop Client..."
    winget install -e --id Bitwarden.Bitwarden --silent

    Start-Sleep -Seconds 10

    foreach ($browser in @("Chrome", "Edge", "Firefox")) {
        if (Test-BrowserInstalled -BrowserName $browser) {
            Write-Host "Installing Bitwarden for $browser..."
            & "Install-${browser}Extension" -ExtensionID $extensionData.$browser.ExtID
        }
    }

    Write-Host "Configuring custom server URL: $ServerUrl"
    Set-BitwardenEnvironmentConfig -ServerUrl $ServerUrl

    Write-Host "Installation and configuration completed successfully"
} catch {
    Write-Error "Error occurred: $_"
    exit 1
} finally {
    Stop-Transcript
}
