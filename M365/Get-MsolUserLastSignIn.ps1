Function Get-MsolUserLastSignIn {
<#
.SYNOPSIS
Retrieves AzureAD last sign in info for user(s)>

.DESCRIPTION
Retrieves AzureAD last sign in info for user(s)>

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2024.02.14 by DS :: First revision.
    V02: 2024.12.24 by DS :: Fixed issues identified by VS Code.
    V03: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ 'Microsoft.Graph' module

.PARAMETER Identity
The UserPrincipalName of the Microsoft Online user which will have last sign in info retrieved.

.PARAMETER All
Switched parameter which when specified, retrieves last sign in info for all Microsoft Online users.

.EXAMPLE
Get-MsolUserLastSignIn -Identity James.Kirk@contoso.com
Will retrieve last sign in information for the user 'James.Kirk@contoso.com'

.EXAMPLE
Get-MsolUserLastSignIn -All | Export-Csv -Path .\AAD_SignIns.csv -NoTypeInformation
Will retrieve sign in information for all Microsoft Online users and export the data to a CSV in the current working directory.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$Identity = $Null,
    [Parameter(Mandatory=$False)]
    [Switch]$All = $False
)

# Prompt for 'Identity' if it is $null and -All not specified
If ($Identity -eq $Null -and $All -eq $False) {
    $Identity = Read-Host "Identity"
}

# Define and import required modules
$RequiredModules = "Microsoft.Graph.Authentication","Microsoft.Graph.Users"
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

# Connect to Microsoft Graph (MG) if not already
$Context = Get-MgContext
If (!$Context) {
    Write-Warning "Not connected to Microsoft Graph"
    Try {
        Connect-MgGraph -NoWelcome -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All"
    }
    Catch {
        Write-Host "FAILURE: Unable to connect to Microsoft Graph!" -ForegroundColor Red
    }
}
ElseIf ($Context.Scopes -notcontains "User.Read.All" -or $Context.Scopes -notcontains "Directory.Read.All" -or $Context.Scopes -notcontains "AuditLog.Read.All") {
    Write-Warning "Required Microsoft Graph scopes are missing, reconnecting"
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Try {
        Connect-MgGraph -NoWelcome -Scopes "User.Read.All","Directory.Read.All","AuditLog.Read.All"
    }
    Catch {
        Write-Host "FAILURE: Unable to connect to Microsoft Graph!" -ForegroundColor Red
    }
}

# Time zone variables used in output
$TimeZone = Get-TimeZone
$TzOffset = $TimeZone.DisplayName.Split(' ') | Select-Object -First 1

# Populate $GraphUsers based on if -All switch is used
switch ($All) {
    $False {
        $GraphUsers = Get-MgUser -Filter "UserPrincipalName eq '$($Identity)'" -Property Id,UserPrincipalName,AccountEnabled,SignInActivity
    }
    $True {
        Write-Warning "'-All' specified. This may take several minutes to complete depending on the number of users in the Microsoft Online instance."
        $GraphUsers = Get-MgUser -All -Property Id,UserPrincipalName,AccountEnabled,SignInActivity
    }
}

# Determine LastSignIn attributes for $GraphUsers
$i = 0
$Results = foreach ($gu in $GraphUsers) {
    If ($GraphUsers.Count -ne 1) {
        $i++
        Write-Progress "Determining LastSignIn for '$($gu.UserPrincipalName)'" -PercentComplete ($i / $GraphUsers.Count * 100)
    }
        
    $signins = New-Object -TypeName System.Collections.ArrayList
    $signins.Add($gu.SignInActivity.LastSignInDateTime) | Out-Null
    $signins.Add($gu.SignInActivity.LastNonInteractiveSignInDateTime) | Out-Null

    $gu | Select-Object `
        Id,`
        UserPrincipalName,`
        AccountEnabled,`
        @{N="LastSignIn(UTC)";E={$signins | Sort-Object -Descending | Select-Object -First 1}},`
        @{N="LastSignIn$TzOffset";E={($signins | Sort-Object -Descending | Select-Object -First 1).AddHours($TimeZone.BaseUtcOffset.Hours)}}
}

# Output results
If ($Results) {
    $Results
}
Else {
    Write-Warning "No results! Is $Identity a valid UserPrincipalName?"
}

}