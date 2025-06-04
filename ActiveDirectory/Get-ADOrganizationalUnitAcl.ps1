﻿Function Get-ADOrganizationalUnitAcl {
<#
.SYNOPSIS
Retrieves AD organizational unit ACLs.

.DESCRIPTION
Retrieves AD organizational unit ACLs. 'IdentityReference' and 'ExcludeInherited' parameters can be specified to filter results.

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2022.03.15 by DS :: First revision.
    V02: 2022.04.07 by DS :: Fixed typo in script header.
    V03: 2022.04.16 by DS :: Fixed problems reported by VS Code.
    V04: 2022.06.01 by DS :: Added -Server and -Credential parameters.
    V05: 2025.05.22 by DS :: Dust blown off for GitHub.
Call From:
    PowerShell v5.1+ w/ ActiveDirectory module

.PARAMETER IdentityReference
Filter results to display ACLs for only the specified IdentityReference (user or group).

.PARAMETER ExcludeInherited
Switched parameter specifing that inherited permissions be excluded from results.

.PARAMETER Server
The server which will be queried for AD organizational unit ACLs.

.PARAMETER Credential
Optional parameter to specify credential used in making connection to AD server.

.EXAMPLE
Get-ADOrganizationalUnitAcl
Will return *all* Organizational Unit ACLs for the entire domain.

.EXAMPLE
Get-ADOrganizationalUnitAcl -IdentityReference "HelpDesk"
Will return Organizational Unit ACLs which have an IdentityReference like "*HelpDesk*"

.EXAMPLE
Get-ADOrganizationalUnitAcl -IdentityReference "HelpDesk" -ExcludeInherited
Will return Organizational Unit ACLs with permission that are not inherited and have an IdentityReference like "*HelpDesk*"
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    $IdentityReference = "*",

    [Parameter(Mandatory=$False,Position=1)]
    $Server = "$((Get-ADDomain).PDCEmulator)",

    [Parameter(Mandatory=$False,Position=2)]
    [AllowNull()]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory=$False)]
    [Switch]$ExcludeInherited = $False
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

# Define domain and OU 'base' for search
$Domain = Get-ADDomain -Server $Server

# Create parameter hash table based on $Credential being $null or specified
Switch($Credential) { 
    $null {
        $InvokeParams = @{
            'ComputerName' = "$($Domain.PDCEmulator)";
            'ErrorAction' = 'Stop';
        }
    }
    Default {
        $InvokeParams = @{
            'ComputerName' = "$($Domain.PDCEmulator)";
            'ErrorAction' = 'Stop';
            'Credential' = $Credential;
        }
    }
}

Try {
    $ACLs = Invoke-Command @InvokeParams -ScriptBlock {
        Import-Module ActiveDirectory
        $OUs = Get-ChildItem -Path "AD:\$($using:Domain.DistinguishedName)" -Recurse | Where-Object {$_.ObjectClass -eq "organizationalUnit"}
        foreach ($ou in $OUs) {
            (Get-Acl -Path "AD:\$($ou.distinguishedName)").Access | Select-Object @{Name="OrganizationalUnit";Expression={"$($ou.distinguishedName)"}},*
        }
    }
}
Catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
    Write-Host "FAILURE: Invalid credentials for connecting to '$($Domain.PDCEmulator)'" -ForegroundColor Red
}

If ($ACLs) {
    
    # Return ACLs filtered on $IdentityReference
    If (!$ExcludeInherited) {
        $ACLs | Where-Object {$_.IdentityReference -like "*$IdentityReference*"} | Select-Object `
            @{N="Server";E={$Domain.PDCEmulator}},*
    }
    
    # Return ACLs filtered on $IdentityReference omitting inherited ACLs
    Else {
        $ACLs | Where-Object {$_.IdentityReference -like "*$IdentityReference*" -and $_.IsInherited -eq $False} | Select-Object `
            @{N="Server";E={$Domain.PDCEmulator}},*
    }
}

}