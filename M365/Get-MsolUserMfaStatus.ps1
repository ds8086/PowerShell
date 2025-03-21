Function Get-MsolUserMfaStatus {
<#
.SYNOPSIS
Retrieves MFA status of Microsoft Online (M365) users.

.DESCRIPTION
Retrieves MFA status of Microsoft Online (M365) users.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2023.11.29 by DS :: First revision.
    V02: 2023.11.30 by DS :: Updated $SelectParams to include 'ObjectId'.
    V03: 2024.12.24 by DS :: Fixed issues identified by VS Code.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER EnabledFilter
Parameter for specifying the 'enabled state' of Microsoft Online users to query and return. Valid values are 'All', 'EnabledOnly', and 'DisabledOnly'. The default value is 'EnabledOnly'.

.EXAMPLE
Get-MsolUserMfaStatus
Will connect to Microsoft Online services and retrieve the MFA status for all enabled users.

.EXAMPLE
Get-MsolUserMfaStatus -EnabledFilter 'All'
Will connect to Microsoft Online services and retrieve the MFA status for all users, both enabled and disabled.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
	[ValidateSet("All", "EnabledOnly", "DisabledOnly")]
    [string]$EnabledFilter = "EnabledOnly"
)

# Define and import required modules
$RequiredModules = "MSOnline"
foreach ($rm in $RequiredModules) {
    Try {
        If (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    Catch {
        Write-Host "FAILURE: Required module '$rm' could not be imported!" -ForegroundColor Red
        Break
    }
}

# Connect to MSOL service if not already
If (!(Get-MsolAccountSku -ErrorAction SilentlyContinue)) {
    Try {
        Connect-MsolService -ErrorAction Stop
    }
    Catch {
        Write-Host "FAILURE: Connection to MSOL service not successful!" -ForegroundColor Red
        Break
    }
}

# Microsoft online users
$MsolUsers = Get-MsolUser -EnabledFilter $EnabledFilter -All

# All Microsoft online role members where role name contains 'administrator'
$AdminAcct = (Get-MsolRole | Where-Object {$_.Name -like "*Administrator*"} | ForEach-Object {Get-MsolRoleMember -RoleObjectId $_.ObjectId}).ObjectId | Select-Object -Unique

# Splat table for 'Select-Object' below
$SelectParams = @{ 
    'Property'= @(
        'DisplayName',`
        'ObjectId',`
        @{N="Disabled";E={$_.BlockCredential}},`
        'UserPrincipalName',`
        @{N="Administrator";E={ If ($AdminAcct -contains $_.ObjectId) {$True} Else {$False} }},`
        @{N="MfaEnabled";E={ If ($_.StrongAuthenticationMethods) {$True} Else {$False} }},`
        @{N="MfaMethod";E={
            switch (($_.StrongAuthenticationMethods | Where-Object {$_.IsDefault -eq $True}).MethodType) {
                "OneWaySMS" { "SMS Token" }
                "TwoWayVoiceMobile" { "Phone call verification" }
                "PhoneAppOTP" { "Hardware token or authenticator app" }
                "PhoneAppNotification" { "Authenticator app" }
            }
        }},`
        @{N="MfaEnforced";E={ If ($_.StrongAuthenticationRequirements) {$True} Else {$False} }}
    )
}

# Output
$MsolUsers | Select-Object @SelectParams

}