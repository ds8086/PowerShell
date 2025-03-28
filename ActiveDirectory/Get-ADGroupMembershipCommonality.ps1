Function Get-ADGroupMembershipCommonality {
<#
.SYNOPSIS
Determines AD group membership commonality for all users in the specified organizational unit.

.DESCRIPTION
Determines AD group membership commonality for all users in the specified organizational unit.

.NOTES
Authors: 
    DS & JS
Notes:
    Revision 03
Revision:
    V01: 2023.11.03 by DS :: First revision.
    V02: 2023.11.22 by DS :: Efficiency overhaul after blue sky session w/ JS.
    V03: 2025.03.10 by DS :: Fixed spacing in parameter block. Updated comments and spacing.
Call From:
    PowerShell v4 or higher w/ ActiveDirectory module

.PARAMETER OrganizationalUnit
The name of the targeted organizational unit.

.PARAMETER Server
Optional paramater which, if specified, defines the domain or domain controller from which to retrieve AD group membership commonality.

.PARAMETER MinimumPercentage
Optional parameter which, if specified, dictates the minimum commonality percentage an AD group must meet for users in the organizational unit in order to be returned in the results. The default value is 0.

.EXAMPLE
Get-ADGroupMembershipCommonality -OrganizationalUnit 'OU=Users,OU=Finance,DC=contoso,DC=local'
Will return the group membership commonality percentages for all groups which users in the 'OU=Users,OU=Finance,DC=contoso,DC=local' organizational unit are a member of.

.EXAMPLE
Get-ADGroupMembershipCommonality -OrganizationalUnit 'OU=Users,OU=Finance,DC=contoso,DC=local' -MinimumPercentage 75
Will return the group membership commonality percentages for all groups which users in the 'OU=Users,OU=Finance,DC=contoso,DC=local' organizational unit are a member of, but only if at least 75% of users are members of the group.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('OU')]
    [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$OrganizationalUnit,

    [Parameter(Mandatory=$false,Position=1)]
    [string]$Server = $env:USERDNSDOMAIN,

    [Parameter(Mandatory=$false,Position=2)]
    [ValidateScript({$_ -le 100})]
    [int]$MinimumPercentage = 0
)

# Define and import required modules
$RequiredModules = "ActiveDirectory"
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

# Ensure that OU exists
Try {
    $ou = Get-ADOrganizationalUnit -Server $Server -Identity $OrganizationalUnit -ErrorAction Stop
    $Users = Get-ADUser -Filter * -SearchBase $ou -Server $Server -Properties MemberOf
}
Catch {
    Write-Host "FAILURE: AD organizational unit '$OrganizationalUnit' could not be found on '$Server'" -ForegroundColor Red
    Break
}

If ($Users) {
    $Users.MemberOf | Group-Object | Select-Object Count,@{N="Percentage";E={$_.Count / $Users.Count * 100}},Name | Where-Object {$_.Percentage -gt $MinimumPercentage}
}

# No AD users exist in the OU
Else {
    Write-Warning "No AD users exist in '$($ou.DistinguishedName)'"
}

}