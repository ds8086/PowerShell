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
    Revision 04
Revision:
    V01: 2025.05.22 by DS :: First polished version for GitHub.
    V02: 2025.08.02 by DS :: Required modules logic.
    V03: 2025.12.11 by DS :: Cleaned up header and statement capitalization.
    V04: 2025.12.12 by DS :: Minor change to required modules. Line lengths.
Call From:
    PowerShell v5.1+ w/ ActiveDirectory module

.INPUTS
None

.OUTPUTS
None

.PARAMETER GivenName
The given (first) name of the user.

.PARAMETER Surname
The surname (last) name of the user.

.PARAMETER Server
Optional parameter to specify the domain or domain controller for AD operations.

.EXAMPLE
Find-AvailableSamAccountName -GivenName James -Surname Kirk
Find available SamAccountName using naming convention; first letter of GivenName and complete Surname (jkirk).

.EXAMPLE
Import-Csv .\user_list.csv | % { Find-AvailableSamAccountName -GivenName $_.GivenName -Surname $_.Surname }
Find available SamAccountName for each user listed in the two column (GivenName and Surname) CSV file.
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

# Define and import required modules
$RequiredModules = "ActiveDirectory"
foreach ($rm in $RequiredModules) {
    try {
        if (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    catch {
        throw
    }
}

# Remove non-alphabet characters
$gn = $GivenName -replace "[^a-zA-Z]"
$sn = $Surname -replace "[^a-zA-Z]"

# Varible to hold total number of options
[int32]$o = $gn.Length
[int32]$i = 0

do {
    $i++
    $sam = "$($gn.Substring(0,$i))$sn"

    if ($sam.Length -gt 20) {
        $sam = $sam.SubString(0,20)
    }

    $u = Get-ADUser -LDAPFilter "(SamAccountName=$sam)" -Server $Server
}
until (
    (!($u)) -or $i -eq $o
)

if ($u) {
    Write-Warning "Unable to find available SamAccountName for '$($GivenName) $($Surname)'"
}
elseif (!($u)) {
    "" | Select-Object @{N="GivenName";E={$GivenName}},@{N="Surname";E={$Surname}},@{N="SamAccountName";E={$sam}}
}

}