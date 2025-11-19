<#
.SYNOPSIS
    Links on-premises Active Directory users to Entra AD (Azure AD) users.

.DESCRIPTION
    This script matches on-premises AD users with Entra AD users using UPN and sets the
    OnPremisesImmutableId to establish the link. It handles both users and groups.
    All prerequisites are automatically installed.

.PARAMETER DomainController
    Optional. Specify a domain controller to query. If not specified, uses the default DC.

.PARAMETER Scope
    Specifies what to sync. Valid values: 'Users', 'Groups', 'Both'. Default is 'Both'.

.PARAMETER WhatIf
    Shows what would happen if the script runs without making actual changes.

.EXAMPLE
    .\Sync-ADToEntraUsers.ps1 -Scope Both
    Syncs both users and groups from on-premises AD to Entra AD.

.EXAMPLE
    .\Sync-ADToEntraUsers.ps1 -Scope Users -WhatIf
    Shows what user changes would be made without actually making them.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [string]$DomainController,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Users', 'Groups', 'Both')]
    [string]$Scope = 'Both',

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# Set error action preference
$ErrorActionPreference = 'Stop'

# Initialize logging
$LogPath = Join-Path $PSScriptRoot "Sync-ADToEntra-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error', 'Success')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"

    # Color coding for console output
    switch ($Level) {
        'Error'   { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Success' { Write-Host $logMessage -ForegroundColor Green }
        default   { Write-Host $logMessage }
    }

    # Write to log file
    Add-Content -Path $LogPath -Value $logMessage
}

function Install-RequiredModules {
    <#
    .SYNOPSIS
        Installs and imports all required PowerShell modules.
    #>

    Write-Log "Checking and installing required modules..." -Level Info

    # Check if running as administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdmin) {
        Write-Log "WARNING: Not running as administrator. Module installation may fail." -Level Warning
        Write-Log "Consider running this script as administrator for automatic module installation." -Level Warning
    }

    # Set PSGallery as trusted repository
    try {
        $gallery = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
        if ($gallery.InstallationPolicy -ne 'Trusted') {
            Write-Log "Setting PSGallery as trusted repository..." -Level Info
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Could not set PSGallery as trusted: $($_.Exception.Message)" -Level Warning
    }

    # Required modules
    $requiredModules = @(
        @{
            Name = 'ActiveDirectory'
            Description = 'On-premises Active Directory management'
            IsWindowsFeature = $true
        },
        @{
            Name = 'Microsoft.Graph.Authentication'
            Description = 'Microsoft Graph authentication'
            IsWindowsFeature = $false
        },
        @{
            Name = 'Microsoft.Graph.Users'
            Description = 'Microsoft Graph users management'
            IsWindowsFeature = $false
        },
        @{
            Name = 'Microsoft.Graph.Groups'
            Description = 'Microsoft Graph groups management'
            IsWindowsFeature = $false
        }
    )

    foreach ($module in $requiredModules) {
        Write-Log "Checking module: $($module.Name)..." -Level Info

        $installed = Get-Module -ListAvailable -Name $module.Name

        if (-not $installed) {
            Write-Log "Module $($module.Name) not found. Installing..." -Level Info

            try {
                if ($module.IsWindowsFeature -and $IsWindows) {
                    # Install RSAT tools for Active Directory
                    Write-Log "Installing Active Directory RSAT tools..." -Level Info

                    if (Get-Command Add-WindowsCapability -ErrorAction SilentlyContinue) {
                        # Windows 10/11 or Server 2016+
                        Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online -ErrorAction Stop
                    }
                    elseif (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
                        # Windows Server
                        Install-WindowsFeature RSAT-AD-PowerShell -ErrorAction Stop
                    }
                    else {
                        Write-Log "Cannot install ActiveDirectory module automatically. Please install RSAT tools manually." -Level Error
                        throw "ActiveDirectory module installation failed"
                    }
                }
                else {
                    # Install from PowerShell Gallery
                    Install-Module -Name $module.Name -Scope CurrentUser -AllowClobber -Force -ErrorAction Stop
                }

                Write-Log "Successfully installed $($module.Name)" -Level Success
            }
            catch {
                Write-Log "Failed to install $($module.Name): $($_.Exception.Message)" -Level Error
                throw
            }
        }
        else {
            Write-Log "Module $($module.Name) is already installed" -Level Success
        }

        # Import the module
        try {
            Import-Module $module.Name -ErrorAction Stop
            Write-Log "Successfully imported $($module.Name)" -Level Success
        }
        catch {
            Write-Log "Failed to import $($module.Name): $($_.Exception.Message)" -Level Error
            throw
        }
    }

    Write-Log "All required modules are installed and imported" -Level Success
}

function Connect-ToMicrosoftGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph with required permissions.
    #>

    Write-Log "Connecting to Microsoft Graph..." -Level Info

    # Required permissions
    $requiredScopes = @(
        'User.ReadWrite.All',
        'Group.ReadWrite.All',
        'Directory.ReadWrite.All'
    )

    try {
        # Check if already connected
        $context = Get-MgContext -ErrorAction SilentlyContinue

        if ($context) {
            Write-Log "Already connected to Microsoft Graph as $($context.Account)" -Level Info

            # Check if we have required scopes
            $hasAllScopes = $true
            foreach ($scope in $requiredScopes) {
                if ($context.Scopes -notcontains $scope) {
                    $hasAllScopes = $false
                    break
                }
            }

            if (-not $hasAllScopes) {
                Write-Log "Current connection doesn't have all required scopes. Reconnecting..." -Level Warning
                Disconnect-MgGraph -ErrorAction SilentlyContinue
                Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
            }
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
        }

        $context = Get-MgContext
        Write-Log "Successfully connected to Microsoft Graph (Tenant: $($context.TenantId))" -Level Success

        return $true
    }
    catch {
        Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Convert-ADGuidToImmutableId {
    <#
    .SYNOPSIS
        Converts AD ObjectGUID to OnPremisesImmutableId format.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [guid]$ObjectGuid
    )

    # Convert GUID to byte array and then to Base64 string
    $immutableId = [System.Convert]::ToBase64String($ObjectGuid.ToByteArray())
    return $immutableId
}

function Sync-ADUsersToEntra {
    <#
    .SYNOPSIS
        Syncs on-premises AD users to Entra AD.
    #>

    Write-Log "Starting user synchronization..." -Level Info

    # Get on-premises AD users
    Write-Log "Retrieving on-premises AD users..." -Level Info

    $adParams = @{
        Filter = 'Enabled -eq $true'
        Properties = @('ObjectGUID', 'UserPrincipalName', 'DisplayName', 'mail', 'SamAccountName')
    }

    if ($DomainController) {
        $adParams.Server = $DomainController
    }

    try {
        $adUsers = Get-ADUser @adParams
        Write-Log "Found $($adUsers.Count) enabled users in on-premises AD" -Level Info
    }
    catch {
        Write-Log "Failed to retrieve AD users: $($_.Exception.Message)" -Level Error
        throw
    }

    # Statistics
    $stats = @{
        Total = $adUsers.Count
        Matched = 0
        Updated = 0
        AlreadyLinked = 0
        NotFound = 0
        Failed = 0
    }

    # Process each AD user
    foreach ($adUser in $adUsers) {
        $upn = $adUser.UserPrincipalName

        if ([string]::IsNullOrWhiteSpace($upn)) {
            Write-Log "Skipping user $($adUser.SamAccountName) - no UPN defined" -Level Warning
            $stats.Failed++
            continue
        }

        Write-Log "Processing user: $upn" -Level Info

        try {
            # Convert AD ObjectGUID to ImmutableId
            $immutableId = Convert-ADGuidToImmutableId -ObjectGuid $adUser.ObjectGUID

            # Find corresponding Entra AD user
            $entraUser = Get-MgUser -Filter "userPrincipalName eq '$upn'" -ErrorAction SilentlyContinue

            if (-not $entraUser) {
                Write-Log "  User not found in Entra AD: $upn" -Level Warning
                $stats.NotFound++
                continue
            }

            $stats.Matched++

            # Check if already linked
            if ($entraUser.OnPremisesImmutableId -eq $immutableId) {
                Write-Log "  User already linked correctly: $upn" -Level Info
                $stats.AlreadyLinked++
                continue
            }

            # Update the OnPremisesImmutableId
            if ($WhatIf) {
                Write-Log "  [WHATIF] Would update OnPremisesImmutableId for: $upn" -Level Info
                Write-Log "  [WHATIF] Current: $($entraUser.OnPremisesImmutableId)" -Level Info
                Write-Log "  [WHATIF] New: $immutableId" -Level Info
                $stats.Updated++
            }
            else {
                Update-MgUser -UserId $entraUser.Id -OnPremisesImmutableId $immutableId -ErrorAction Stop
                Write-Log "  Successfully linked user: $upn" -Level Success
                $stats.Updated++
            }
        }
        catch {
            Write-Log "  Failed to process user $upn : $($_.Exception.Message)" -Level Error
            $stats.Failed++
        }
    }

    # Report statistics
    Write-Log "`n===== USER SYNC STATISTICS =====" -Level Info
    Write-Log "Total AD Users: $($stats.Total)" -Level Info
    Write-Log "Matched in Entra: $($stats.Matched)" -Level Info
    Write-Log "Already Linked: $($stats.AlreadyLinked)" -Level Success
    Write-Log "Updated: $($stats.Updated)" -Level Success
    Write-Log "Not Found: $($stats.NotFound)" -Level Warning
    Write-Log "Failed: $($stats.Failed)" -Level Error
    Write-Log "================================`n" -Level Info
}

function Sync-ADGroupsToEntra {
    <#
    .SYNOPSIS
        Syncs on-premises AD groups to Entra AD.
    #>

    Write-Log "Starting group synchronization..." -Level Info

    # Get on-premises AD groups
    Write-Log "Retrieving on-premises AD groups..." -Level Info

    $adParams = @{
        Filter = '*'
        Properties = @('ObjectGUID', 'mail', 'DisplayName', 'SamAccountName')
    }

    if ($DomainController) {
        $adParams.Server = $DomainController
    }

    try {
        $adGroups = Get-ADGroup @adParams
        Write-Log "Found $($adGroups.Count) groups in on-premises AD" -Level Info
    }
    catch {
        Write-Log "Failed to retrieve AD groups: $($_.Exception.Message)" -Level Error
        throw
    }

    # Statistics
    $stats = @{
        Total = $adGroups.Count
        Matched = 0
        Updated = 0
        AlreadyLinked = 0
        NotFound = 0
        Failed = 0
    }

    # Process each AD group
    foreach ($adGroup in $adGroups) {
        # Try to match by mail address or display name
        $groupIdentifier = if ($adGroup.mail) { $adGroup.mail } else { $adGroup.DisplayName }

        if ([string]::IsNullOrWhiteSpace($groupIdentifier)) {
            Write-Log "Skipping group $($adGroup.SamAccountName) - no mail or display name" -Level Warning
            $stats.Failed++
            continue
        }

        Write-Log "Processing group: $groupIdentifier" -Level Info

        try {
            # Convert AD ObjectGUID to ImmutableId
            $immutableId = Convert-ADGuidToImmutableId -ObjectGuid $adGroup.ObjectGUID

            # Find corresponding Entra AD group by mail or display name
            $filter = if ($adGroup.mail) {
                "mail eq '$($adGroup.mail)'"
            } else {
                "displayName eq '$($adGroup.DisplayName)'"
            }

            $entraGroup = Get-MgGroup -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1

            if (-not $entraGroup) {
                Write-Log "  Group not found in Entra AD: $groupIdentifier" -Level Warning
                $stats.NotFound++
                continue
            }

            $stats.Matched++

            # Check if already linked
            if ($entraGroup.OnPremisesImmutableId -eq $immutableId) {
                Write-Log "  Group already linked correctly: $groupIdentifier" -Level Info
                $stats.AlreadyLinked++
                continue
            }

            # Update the OnPremisesImmutableId
            if ($WhatIf) {
                Write-Log "  [WHATIF] Would update OnPremisesImmutableId for: $groupIdentifier" -Level Info
                Write-Log "  [WHATIF] Current: $($entraGroup.OnPremisesImmutableId)" -Level Info
                Write-Log "  [WHATIF] New: $immutableId" -Level Info
                $stats.Updated++
            }
            else {
                Update-MgGroup -GroupId $entraGroup.Id -OnPremisesImmutableId $immutableId -ErrorAction Stop
                Write-Log "  Successfully linked group: $groupIdentifier" -Level Success
                $stats.Updated++
            }
        }
        catch {
            Write-Log "  Failed to process group $groupIdentifier : $($_.Exception.Message)" -Level Error
            $stats.Failed++
        }
    }

    # Report statistics
    Write-Log "`n===== GROUP SYNC STATISTICS =====" -Level Info
    Write-Log "Total AD Groups: $($stats.Total)" -Level Info
    Write-Log "Matched in Entra: $($stats.Matched)" -Level Info
    Write-Log "Already Linked: $($stats.AlreadyLinked)" -Level Success
    Write-Log "Updated: $($stats.Updated)" -Level Success
    Write-Log "Not Found: $($stats.NotFound)" -Level Warning
    Write-Log "Failed: $($stats.Failed)" -Level Error
    Write-Log "==================================`n" -Level Info
}

# ===== MAIN SCRIPT EXECUTION =====

try {
    Write-Log "===== AD to Entra AD User Sync Script Started =====" -Level Info
    Write-Log "Log file: $LogPath" -Level Info

    if ($WhatIf) {
        Write-Log "Running in WHATIF mode - no changes will be made" -Level Warning
    }

    # Step 1: Install required modules
    Install-RequiredModules

    # Step 2: Connect to Microsoft Graph
    $connected = Connect-ToMicrosoftGraph

    if (-not $connected) {
        throw "Failed to connect to Microsoft Graph. Exiting."
    }

    # Step 3: Sync users
    if ($Scope -eq 'Users' -or $Scope -eq 'Both') {
        Sync-ADUsersToEntra
    }

    # Step 4: Sync groups
    if ($Scope -eq 'Groups' -or $Scope -eq 'Both') {
        Sync-ADGroupsToEntra
    }

    Write-Log "===== Script Completed Successfully =====" -Level Success
    Write-Log "Log file saved to: $LogPath" -Level Info
}
catch {
    Write-Log "===== Script Failed =====" -Level Error
    Write-Log "Error: $($_.Exception.Message)" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error
    exit 1
}
finally {
    # Cleanup
    Write-Log "Disconnecting from Microsoft Graph..." -Level Info
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
