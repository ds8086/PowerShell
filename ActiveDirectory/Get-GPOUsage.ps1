Function Get-GPOUsage {
<#
.SYNOPSIS
Generates a report of all GPOs in AD.

.DESCRIPTION
Generates a report of all GPOs in AD and lists where each GPO is linked. GPO links are checked for at the domain, site and OU level.

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2018.12.31 by DS :: First revision.
    V02: 2023.07.18 by DS :: Removed '#Requires -Module ActiveDirectory' and added logic for required modules.
    V03: 2023.08.01 by DS :: Removed '-Orphaned' switch and updated script header.
    V04: 2024.12.24 by DS :: Resolved issues identified by VS Code.
    V05: 2025.03.10 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.PARAMETER Orphaned
Switched parameter that will display only GPOs that are not linked to any AD object (Domain, site, or OU)

.EXAMPLE
Get-GPOUsage | Format-Table -Autosize
Will generate a report of all GPOs and locations where they are linked (if any) and format the results as an autosized table.

.EXAMPLE
Get-GPOUsage | Export-Csv -Path .\GPOs.csv
Will generate a report of GPOs and export the results to a CSV named 'GPOs.csv' in the current working directory.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    $Domain = $(Get-ADDomain)
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

# Array to hold GPO link data
$Links = New-Object -TypeName System.Collections.ArrayList

# All GPOs in the domain
$All = Get-GPO -All -Domain $Domain.DNSRoot

# GPOs linked to top level of Domain
$Links = (`
    (Get-ADObject -Server $Domain.DNSRoot -Identity ($Domain).DistinguishedName -Properties gPLink).gPLink.Replace('[','').Split(']').Split(';') | Where-Object {$_ -like "LDAP://*"}`
).Replace('LDAP://','') | Select-Object @{N="ADObject";E={[string]::new("$($Domain.DistinguishedName)")}},@{N="GPOObject";E={$_}}

# GPOs linked to sites in AD
$Sites =  Get-ADObject -Server $Domain.DNSRoot -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE -Server $Domain.DNSRoot).configurationNamingContext)" -SearchScope OneLevel -Properties Name,DistinguishedName,gPLink |
Select-Object Name,DistinguishedName,gPLink
$i = 0
$Links += foreach ($site in ($Sites | Where-Object {$null -ne $_.gPLink})) {
    $i++
    Write-Progress "Determining GPOs linked to $($site.DistinguishedName)" -PercentComplete ($i / $Sites.Count * 100) -ErrorAction SilentlyContinue
    $sitegpos = (($site | Select-Object -ExpandProperty gPLink).Replace('[','').Split(']').Split(';') | `
    Where-Object {$_ -like "LDAP://*"}).Replace('LDAP://','')
    foreach ($s in $sitegpos) {
        $s | Select-Object @{N="ADObject";E={[string]::new("$($site.DistinguishedName)")}},@{N="GPOObject";E={$_}}
    }
}

# GPOs linked to OUs in AD
$OUs = Get-ADOrganizationalUnit -Server $Domain.DNSRoot -Filter * -Properties DistinguishedName,LinkedGroupPolicyObjects
$i = 0
$Links += foreach ($ou in $OUs) {
    $i++
    Write-Progress "Determining GPOs linked to $($ou.DistinguishedName)" -PercentComplete ($i / $OUs.Count * 100) -ErrorAction SilentlyContinue
    $gpos = $ou | Select-Object -ExpandProperty LinkedGroupPolicyObjects
    foreach ($g in $gpos) {
        $g | Select-Object `
            @{N="ADObject";E={$ou.DistinguishedName}},`
            @{N="GPOObject";E={$_}}
    }
}

# Determine where each GPO in $All is linked (if at all)
$i = 0
$Report = foreach ($a in $All) {
    $i++
    Write-Progress "Determining where $($a.DisplayName) is linked" -PercentComplete ($i / $All.Count * 100)
    If ($Links.GPOObject -contains $a.Path) {
        Write-Verbose "$($a.Displayname) is linked to AD"
        $Links | Where-Object {$_.GPOObject -eq "$($a.Path)"} | Select-Object `
            @{N="Path";E={$a.Path}},`
            @{N="DisplayName";E={$a.DisplayName}},`
            @{N="GpoStatus";E={$a.GpoStatus}},`
            @{N="WmiFilter";E={($a.WmiFilter).Name}},`
            @{N="Description";E={$a.Description}},`
            @{N="ADObject";E={$_.ADObject}}
    }
    ElseIf ($Links.GPOObject -notcontains $a.Path) {
        Write-Verbose "$($a.Displayname) is not linked to AD"
        $a | Select-Object `
            Path,`
            DisplayName,`
            GpoStatus,`
            @{N="WmiFilter";E={($a.WmiFilter).Name}},`
            Description,`
            @{N="ADObject";E={[string]::new("NONE")}}
    }
}

$Report

}