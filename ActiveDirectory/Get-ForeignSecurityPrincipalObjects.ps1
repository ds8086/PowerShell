Function Get-ForeignSecurityPrincipalObjects {
<#
.SYNOPSIS
Retrieves and attempts to translate AD foreignSecurityPrincipal objects.

.DESCRIPTION
Retrieves and attempts to translate AD foreignSecurityPrincipal objects from the domain of the currently logged on user.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2025.01.24 by DS :: First revision.
    V02: 2025.03.10 by DS :: Updated comments.
    V03: 2025.03.22 by DS :: Updated 'RequiredModules' logic.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.EXAMPLE
Get-ForeignSecurityPrincipalObjects
Will retrieve and attempt to translate foreignSecurityPrincipal objects from the domain of the currently logged on user.
#>

[CmdletBinding()]
param ()

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

# Get target domain
Try {
    $User_Domain = Get-ADDomain -Identity $env:USERDOMAIN -ErrorAction Stop
}
Catch {
    Throw $Error[0]
    Break
}

# Check if user is a Domain Admin
$Current_User = Get-ADUser -Server $User_Domain.DNSRoot -Identity $env:USERNAME
$Domain_Admin = Get-ADGroupMember -Identity "$($User_Domain.DomainSID)-512" -Recursive
If ($Domain_Admin.SID.Value -notcontains $Current_User.SID.Value) {
    Write-Warning "Currently logged on user '$($env:USERDOMAIN)\$($env:USERNAME)' is not a member of 'Domain Admins'"
    Write-Warning "The 'Created' and 'MemberOf' attributes of results may not be accurate"
}

# Domains from AD trusts
$Foreign_Domains = (Get-ADTrust -Server $User_Domain.DNSRoot -Filter *).Target | ForEach-Object {
    Try {
        Get-ADDomain -Identity $_ -ErrorAction Stop | Select-Object @{N="ForeignDomain";E={$_.DnsRoot}},DomainSID
    }
    Catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-Warning $_
        Write-Warning "Unable to contact trusted domain. Some foreignSecurityPrincipal objects may not be translated"
    }
}

# foreignSecurityPrincipal objects
$foreignSecurityPrincipals = Get-ADObject -Filter {ObjectClass -eq 'foreignSecurityPrincipal'} -Properties * -Server $User_Domain.DNSRoot

# Array for results
$Results = New-Object -TypeName System.Collections.ArrayList

# 'Main' foreach loop against foreignSecurityPrincipal objects
$i = 0
Foreach ($fsp in $foreignSecurityPrincipals) {
    $i++
    Write-Progress "Processing $($fsp.Name)" -PercentComplete ($i / $foreignSecurityPrincipals.Count * 100)

    # Variable and properties for individual result
    $res = "" | Select-Object 'DistinguishedName','Name','Created','MemberOf','Domain','SamAccountName'
    $res.DistinguishedName = $fsp.DistinguishedName
    $res.Name = $fsp.Name
    $res.Created = $fsp.Created
    $res.MemberOf = $fsp.MemberOf

    switch ($fsp.ObjectSid.AccountDomainSid.Value) {
        
        # fsp does not have a domain SID indicating a well-known object (NT Authority\...)
        $null {
            $res.Domain = [string]::new('N/A')
            $res.SamAccountName = ([System.Security.Principal.SecurityIdentifier] $fsp.Name).Translate([System.Security.Principal.NTAccount]).Value
        }

        # fsp has a domain SID contained within $Foreign_Domains
        {$Foreign_Domains.DomainSid.Value -contains $_} {
            $res.Domain = ($Foreign_Domains | Where-Object {$_.DomainSID.Value -eq $fsp.ObjectSid.AccountDomainSid.Value}).ForeignDomain
            Try {
                $res.SamAccountName = ([System.Security.Principal.SecurityIdentifier] $fsp.Name).Translate([System.Security.Principal.NTAccount]).Value.Split('\') | Select-Object -Last 1
            }
            Catch {
                $res.SamAccountName = [string]::new('Unknown')
            }
        }

        # fsp has a domain SID from a domain which could not be contacted
        Default {
            $res.Domain = [string]::new('Unknown')
            $res.SamAccountName = [string]::new('Unknown')
        }
    }
    
    # Add individual result to array of results
    $Results.Add($res) | Out-Null
}

# Output results
$Results

}