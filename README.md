# AD to Entra AD User Sync Script

This PowerShell script links on-premises Active Directory users and groups to Entra AD (Azure AD) by matching UPN and setting the OnPremisesImmutableId.

## Features

- **Automatic prerequisite installation**: Installs all required PowerShell modules
- **User synchronization**: Matches on-prem AD users to Entra AD users via UPN
- **Group synchronization**: Matches on-prem AD groups to Entra AD groups
- **ImmutableId linking**: Sets OnPremisesImmutableId to establish the link
- **Comprehensive logging**: Creates detailed log files for each run
- **WhatIf support**: Preview changes before applying them
- **Error handling**: Robust error handling with detailed error reporting

## Prerequisites

### System Requirements
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator privileges (recommended for automatic module installation)
- Access to on-premises Active Directory
- Appropriate permissions in Entra AD (Azure AD)

### Required Permissions

**On-Premises AD:**
- Read access to Active Directory users and groups

**Entra AD (Azure AD):**
- User.ReadWrite.All
- Group.ReadWrite.All
- Directory.ReadWrite.All

The script will prompt for authentication when connecting to Microsoft Graph.

### Modules (Auto-Installed)

The script automatically installs these modules if not present:
- `ActiveDirectory` - On-premises AD management
- `Microsoft.Graph.Authentication` - Microsoft Graph authentication
- `Microsoft.Graph.Users` - User management in Entra AD
- `Microsoft.Graph.Groups` - Group management in Entra AD

## Usage

### Basic Usage

Sync both users and groups:
```powershell
.\Sync-ADToEntraUsers.ps1
```

### Sync Only Users
```powershell
.\Sync-ADToEntraUsers.ps1 -Scope Users
```

### Sync Only Groups
```powershell
.\Sync-ADToEntraUsers.ps1 -Scope Groups
```

### Preview Changes (WhatIf)
```powershell
.\Sync-ADToEntraUsers.ps1 -WhatIf
```

### Specify Domain Controller
```powershell
.\Sync-ADToEntraUsers.ps1 -DomainController "dc01.contoso.com"
```

## Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `DomainController` | String | No | Auto | Specify a domain controller to query |
| `Scope` | String | No | Both | What to sync: 'Users', 'Groups', or 'Both' |
| `WhatIf` | Switch | No | False | Preview changes without applying them |

## How It Works

### User Synchronization

1. **Retrieves on-premises AD users**: Gets all enabled users from Active Directory
2. **Converts ObjectGUID**: Converts AD ObjectGUID to Base64 format (ImmutableId)
3. **Matches by UPN**: Finds corresponding Entra AD user by UserPrincipalName
4. **Sets ImmutableId**: Updates OnPremisesImmutableId in Entra AD to link the accounts

### Group Synchronization

1. **Retrieves on-premises AD groups**: Gets all groups from Active Directory
2. **Converts ObjectGUID**: Converts AD ObjectGUID to Base64 format
3. **Matches by mail or display name**: Finds corresponding Entra AD group
4. **Sets ImmutableId**: Updates OnPremisesImmutableId in Entra AD to link the groups

### ImmutableId Format

The OnPremisesImmutableId is the Base64-encoded representation of the on-premises AD ObjectGUID. This establishes a permanent link between the on-premises and cloud objects.

## Output

### Console Output

The script provides color-coded console output:
- **Green**: Success messages
- **Yellow**: Warnings
- **Red**: Errors
- **White**: Informational messages

### Log Files

Each run creates a timestamped log file:
```
Sync-ADToEntra-YYYYMMDD-HHMMSS.log
```

The log file contains:
- Timestamp for each operation
- Detailed progress information
- Error messages and stack traces
- Summary statistics

### Statistics Report

After completion, you'll see a report like this:

```
===== USER SYNC STATISTICS =====
Total AD Users: 150
Matched in Entra: 145
Already Linked: 120
Updated: 25
Not Found: 5
Failed: 0
================================

===== GROUP SYNC STATISTICS =====
Total AD Groups: 50
Matched in Entra: 45
Already Linked: 40
Updated: 5
Not Found: 5
Failed: 0
==================================
```

## Important Notes

### Before Running

1. **Test with WhatIf first**: Always run with `-WhatIf` parameter first to preview changes
2. **Backup**: Consider backing up your Entra AD configuration
3. **Pilot group**: Test with a small pilot group before running on all users
4. **Permissions**: Ensure you have appropriate permissions in both environments

### Limitations

- **Enabled users only**: By default, only syncs enabled AD users (can be modified in script)
- **UPN must match**: Users must have identical UPNs in both AD and Entra AD
- **Groups match by mail or display name**: Groups are matched by mail address (preferred) or display name
- **No deletion**: Script does not delete any objects, only links existing ones

### Troubleshooting

**"ActiveDirectory module not found"**
- Run PowerShell as Administrator
- Install RSAT tools: `Add-WindowsCapability -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 -Online`

**"Failed to connect to Microsoft Graph"**
- Ensure you have admin consent for required permissions
- Check your internet connection
- Verify your account has appropriate Entra AD roles (User Administrator or Global Administrator)

**"User not found in Entra AD"**
- Verify the UPN matches exactly between on-prem AD and Entra AD
- Check if the user exists in Entra AD
- Ensure the user is not a cloud-only account

**"Access denied" errors**
- Verify you have the required permissions in Entra AD
- Re-authenticate to Microsoft Graph with appropriate scopes
- Check if Conditional Access policies are blocking access

## Security Considerations

- **Credential storage**: Script does not store credentials; uses interactive authentication
- **Audit logging**: All operations are logged to a file
- **Minimal permissions**: Request only the necessary permissions
- **WhatIf mode**: Use for safe testing without making changes

## Examples

### Example 1: Full Sync with Preview
```powershell
# First, preview what would happen
.\Sync-ADToEntraUsers.ps1 -WhatIf

# If satisfied, run the actual sync
.\Sync-ADToEntraUsers.ps1
```

### Example 2: Sync Users Only from Specific DC
```powershell
.\Sync-ADToEntraUsers.ps1 -Scope Users -DomainController "dc01.contoso.com"
```

### Example 3: Sync Groups Only
```powershell
.\Sync-ADToEntraUsers.ps1 -Scope Groups
```

## Script Workflow

```
Start
  ↓
Install/Import Required Modules
  ↓
Connect to Microsoft Graph
  ↓
┌─────────────────┐
│ Users Requested?│
└────────┬────────┘
         ↓ Yes
  Get AD Users
         ↓
  For each user:
    - Convert ObjectGUID to ImmutableId
    - Find matching Entra user by UPN
    - Update OnPremisesImmutableId
         ↓
  Report Statistics
         ↓
┌─────────────────┐
│Groups Requested?│
└────────┬────────┘
         ↓ Yes
  Get AD Groups
         ↓
  For each group:
    - Convert ObjectGUID to ImmutableId
    - Find matching Entra group
    - Update OnPremisesImmutableId
         ↓
  Report Statistics
         ↓
Disconnect from Microsoft Graph
  ↓
End
```

## Support

For issues, questions, or contributions, please refer to the repository's issue tracker.

## License

This script is provided as-is without warranty. Use at your own risk.
