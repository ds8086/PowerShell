Function Find-AvailableSamAccountName {
<#
.SYNOPSIS
Finds available SamAccountName.

.DESCRIPTION
Finds available SamAccountName based on 'GivenName' and 'Surname' values.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2025.05.22 by DS :: First polished version for GitHub.
Call From:
    PowerShell v5.1+ w/ ActiveDirectory module

.PARAMETER GivenName
The given (first) name of the user.

.PARAMETER Surname
The surname (last name) of the user.

.PARAMETER Server
Optional parameter to specify the domain or domain controller for AD operations.

.EXAMPLE
Find-AvailableSamAccountName -GivenName James -Surname Kirk
Will search AD for the first available SamAccountName based on the naming convention of first letter of Givenname and complete Surname (jkirk). Should the "first choice" be unavailable, subsequent letters from the GivenName will be added as required (jakirk > jamkirk > etc.)

.EXAMPLE
Import-Csv .\user_list.csv | % { Find-AvailableSamAccountName -GivenName $_.GivenName -Surname $_.Surname }
Will search AD for the first available SamAccountName for each user liseted in the two column (GivenName and Surname) CSV file.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True, Position=0)]
    [string]$GivenName,

    [Parameter(Mandatory=$True, Position=1)]
    [string]$Surname,

    [Parameter(Mandatory=$False, Position=2)]
    [string]$Server = $(Get-ADDomain -Identity $env:USERDOMAIN).PDCEmulator
)

# Remove non-alphabet characters
$gn = $GivenName -replace "[^a-zA-Z]"
$sn = $Surname -replace "[^a-zA-Z]"

# Varible to hold total number of options
[int32]$o = $gn.Length
[int32]$i = 0

Do {
    $i++
    $sam = "$($gn.Substring(0,$i))$sn"

    If ($sam.Length -gt 20) {
        $sam = $sam.SubString(0,20)
    }

    $u = Get-ADUser -LDAPFilter "(SamAccountName=$sam)" -Server $Server
} Until ((!($u)) -or $i -eq $o)

If ($u) {
    Write-Warning "Unable to find available SamAccountName for '$($GivenName) $($Surname)'"
}
ElseIf (!($u)) {
    "" | Select-Object @{N="GivenName";E={$GivenName}},@{N="Surname";E={$Surname}},@{N="SamAccountName";E={$sam}}
}

}