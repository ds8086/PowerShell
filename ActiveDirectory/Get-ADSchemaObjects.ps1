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
    Revision 05
Revision:
    V01: 2023.01.17 by DS :: First revision.
    V02: 2025.03.22 by DS :: Updated for GitHub.
    V03: 2025.05.16 by DS :: Include ObjectID (attributeID & governsID). Calculate GUID during 'Select-Object' (faster).
    V04: 2025.12.11 by DS :: Cleaned up header and statement capitalization.
    V05: 2025.12.12 by DS :: Minor change to required modules. Line lengths.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module.

.INPUTS
None

.OUTPUTS
None

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
    try {
        if (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    catch {
        throw
    }
}

# Schema naming context
$schemaNamingContext = (Get-ADRootDSE -Server $Server).schemaNamingContext

# AD objects (classSchema)
$classSchema = @{
    'Server' = $Server
    'LDAPFilter' = '(objectclass=classschema)'
    'Properties' = @(
        'LdapDisplayName',
        'SchemaIdGuid',
        'objectClass',
        'governsID'
    )
    'SearchBase' = $schemaNamingContext
}
$Objects = Get-ADObject @classSchema | Select-Object LdapDisplayName,
    @{N="Guid";E={[System.Guid]$_.SchemaIdGuid}},
    'objectClass',
    @{N="ObjectID";E={$_.governsID}}

# AD objects (attributeSchema)
$attributeSchema = @{
    'Server' = $Server
    'LDAPFilter' = '(objectclass=attributeSchema)'
    'Properties' = @(
        'LdapDisplayName',
        'SchemaIdGuid',
        'objectClass',
        'attributeID'
    )
    'SearchBase' = $schemaNamingContext
}
$Objects += Get-ADObject @attributeSchema | Select-Object LdapDisplayName,
    @{N="Guid";E={[System.Guid]$_.SchemaIdGuid}},
    'objectClass',
    @{N="ObjectID";E={$_.attributeID}}

# Output
$Objects
}