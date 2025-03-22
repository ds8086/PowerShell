Function Get-ADSchemaObjects {
<#
.SYNOPSIS
Retrieves list of AD schema objects and corresponding GUIDs
.DESCRIPTION
Retrieves list of AD schema objects and corresponding GUIDs from specified server/domain or USERDOMAIN if not specified
.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2023.01.17 by DS :: First revision.
    V02: 2025.03.22 by DS :: Updated for GitHub.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module.

.PARAMETER Server
Name of the server or server from which AD schema objects will be returned

.EXAMPLE
Get-ADSchemaObjects -Server contoso.com
Will return all AD schema objects and GUIDs for the 'contoso.com' domain

.EXAMPLE
Get-ADSchemaObjects
Will return all AD schema objects and GUIDs from the domain of the currently logged on user
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [Alias('Domain')]
    [string]$Server = $env:USERDOMAIN
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

# Schema naming context
$schemaNamingContext = (Get-ADRootDSE -Server $Server).schemaNamingContext

# Filters for AD object search
$class = "(objectclass=classschema)"
$attribute = "(objectclass=attributeSchema)"

# AD objects (classSchema)
$Objects = Get-ADObject -Server $Server -LDAPFilter $class -Properties LdapDisplayName,SchemaIdGuid,objectClass -SearchBase $schemaNamingContext | `
    Select-Object LdapDisplayName,SchemaIdGuid,objectClass

# AD objects (attributeSchema)
$Objects += Get-ADObject -Server $Server -LDAPFilter $attribute -Properties LdapDisplayName,SchemaIdGuid,objectClass -SearchBase $schemaNamingContext | `
    Select-Object LdapDisplayName,SchemaIdGuid,objectClass

# Determine Schema GUID for each object in AD Schema
$i = 0
$SchemaData = foreach ($obj in $Objects) {
    $i++
    Write-Progress "Processing $($obj.ldapdisplayname)" -PercentComplete ($i / $Objects.Count *100)
    "" | Select-Object @{N="LdapDisplayName";E={$obj.ldapdisplayname}},@{N="SchemaGuid";E={$([System.Guid]$obj.schemaidguid)}}
}

# Output results
$SchemaData

}