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
Function Get-ADOrganizationalUnitAcl {
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
Function Get-ADReplicationLastStats {
<#
.SYNOPSIS
Retrieves last AD replication attempt, result, and success for domain controllers.

.DESCRIPTION
Retrieves last Active Directory replication attempt, result, and success for domain controllers for domain controllers in the forest, or domain.

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2022.03.23 by DS :: First revision.
    V02: 2023.06.09 by DS :: Minor overhaul. Changed $Object parameter to $Scope, added $EnumerationServer parameter.
    V03: 2023.07.18 by DS :: Removed '#Requires -Module ActiveDirectory' and added logic for required modules.
    V04: 2024.12.24 by DS :: Resolved issues identified by VS Code, cleaned up param block spacing.
    V05: 2025.03.10 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.PARAMETER Object
The object for which to retrieve last AD replication stats, either 'Forest' (default) or 'Domain'.

.PARAMETER EnumerationServer
The server (domain controller) or domain name to query replication stats from. The default value is the DNS root of the currently logged on user's domain.

.EXAMPLE
Get-ADReplicationLastStats -Object Forest -EnumerationServer contoso.com
Retrieves last AD replication attempt, result, and success for global catalogs in the AD forest 'contoso.com'.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
	[ValidateSet("Forest", "Domain")]
    $Scope = "Forest",

    [Parameter(Mandatory=$False,Position=1)]
    [Alias('DomainName')]
    $EnumerationServer = "$((Get-ADDomain).DNSRoot)"
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

# Define $ScopeObject based on value of $Scope
switch ($Scope) {
    {$_ -eq "Forest"} {$ScopeObj = Get-ADForest -Identity $EnumerationServer}
    {$_ -eq "Domain"} {$ScopeObj = Get-ADDomain -Identity $EnumerationServer}
}

# Splat table for Select-Object (Results)
$ResSelect = @{
    'Property' = @(
        @{N="Server";E={$gc}},`
        @{N="Partner";E={$($GlobalCatalogs | Where-Object {$r.Partner -like "*$($_.Hostname)*"}).GlobalCatalog}},`
        'PartnerType',`
        @{N="LastAttempt";E={$_.LastReplicationAttempt}},`
        @{N="LastResult";E={$_.LastReplicationResult}},`
        @{N="LastSuccess";E={$_.LastReplicationSuccess}}
    )
}

# Splat table for Select-Object (No results)
$NonSelect = @{
    'Property' = @(
        @{N="Server";E={$gc}},`
        @{N="Partner";E={[string]::new('None')}},`
        @{N="PartnerType";E={[string]::new('None')}},`
        @{N="LastAttempt";E={[string]::new('None')}},`
        @{N="LastResult";E={[string]::new('None')}},`
        @{N="LastSuccess";E={[string]::new('None')}}
    )
}

# Splat table for Select-Object (Error)
$ErrSelect = @{
    'Property' = @(
        @{N="Server";E={$gc}},`
        @{N="Partner";E={[string]::new('Error')}},`
        @{N="PartnerType";E={[string]::new('Error')}},`
        @{N="LastAttempt";E={[string]::new('Error')}},`
        @{N="LastResult";E={[string]::new('Error')}},`
        @{N="LastSuccess";E={[string]::new('Error')}}
    )
}

# Global catalogs (FQDNs and hostnames)
$GlobalCatalogs = $ScopeObj.GlobalCatalogs | Select-Object @{N="GlobalCatalog";E={$_}},@{N="Hostname";E={$_.Replace(".$($ScopeObj.Name)",'')}}

# 'Main' foreach loop to gather AD replication partner metadata from each global catalog
$i = 0
$Replication = foreach ($gc in $GlobalCatalogs.GlobalCatalog) {
    $i++
    Write-Progress "Retrieving AD replication partner metadata from $gc" -PercentComplete ($i / $GlobalCatalogs.Count * 100)

    Try {
        $rep = $null
        $rep = Get-ADReplicationPartnerMetadata -Scope Server -Target $gc -ErrorAction Stop

        If ($rep) {
            foreach ($r in $rep) {
                $r | Select-Object @ResSelect
            }
        }
        Else {
            Write-Warning "'$gc' has no AD replication partner metadata"
            $gc | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Host "FAILURE: '$gc' connection not successful!" -ForegroundColor Red
        $gc | Select-Object @ErrSelect
    }
}

# Output results
$Replication

}
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
    V03: 2025.05.16 by DS :: Updated to include ObjectID (attributeID & governsID). Guid now calculated during 'Select-Object' (faster).
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
$Objects = Get-ADObject -Server $Server -LDAPFilter $class -Properties LdapDisplayName,SchemaIdGuid,objectClass,governsID -SearchBase $schemaNamingContext | `
    Select-Object LdapDisplayName,@{N="Guid";E={[System.Guid]$_.SchemaIdGuid}},objectClass,@{N="ObjectID";E={$_.governsID}}

# AD objects (attributeSchema)
$Objects += Get-ADObject -Server $Server -LDAPFilter $attribute -Properties LdapDisplayName,SchemaIdGuid,objectClass,attributeID -SearchBase $schemaNamingContext | `
    Select-Object LdapDisplayName,@{N="Guid";E={[System.Guid]$_.SchemaIdGuid}},objectClass,@{N="ObjectID";E={$_.attributeID}}

# Output
$Objects
}
Function Get-ADWindowsServer {
<#
.SYNOPSIS
Retrieves information about Windows server(s) via Get-ADComputer cmdlet.

.DESCRIPTION
Retrieves information about Windows server(s) via Get-ADComputer cmdlet.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2023.07.18 by DS :: First revision after splitting from deprecated 'Get-ServerDetails' cmdlet.
    V02: 2023.07.19 by DS :: Updated script to make better use of splat tables for properties definitions.
    V03: 2025.03.10 by DS :: Fixed spacing in parameter block. Updated comments and spacing.

.PARAMETER Identity
The name of the Windows server(s) for which information will be retrieved from Active Directory. Parameter accepts wildcard (*).

.PARAMETER IncludeClusterObjects
Switched parameter which, when specified, will include Windows server cluster objects in results.

.PARAMETER SkipDnsResolution
Switched parameter which, when specified, will skip DNS resolution for Windows server(s) matching the spcified identity.

.PARAMETER Domain
The name of the domain or domain controller to use when performing the AD query.

.PARAMETER Credential
Optional parameter used for specifying alternate credentials for performing the AD query.

.EXAMPLE
Get-ADWindowsServer -Identity FileSrv*
Will retrieve information from AD for all Windows server(s) with name matching 'FileSrv*'.

.EXAMPLE
Get-ADWindowsServer -Identity FileSrv* -IncludeClusterObjects
Will retrieve information from AD for all Windows server(s) with name matching 'FileSrv*'. Windows server cluster objects will be included in results.

.EXAMPLE
Get-ADWindowsServer -Identity FileSrv* -SkipDnsResolution
Will retrieve information from AD for all Windows server(s) with name matching 'FileSrv*'. DNS resolution will not be attempted. Helpful for excluding duplicate results due to multiple DNS records.

.EXAMPLE
Get-ADWindowsServer -Identity FileSrv* -Domain 'contoso.com' -Credential (Get-Credential)
Will retrieve information from AD for all Windows server(s) with name matching 'FileSrv*' from the 'contoso.com' domain. Credentials for the AD query will be gathered during execution.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    $Identity = "*",

    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    [pscredential]$Credential,

    [Parameter(Mandatory=$False,Position=2)]
    $Domain = $((Get-ADForest).RootDomain),

    [Parameter(Mandatory=$False)]
    [switch]$IncludeClusterObjects = $False,
    
    [Parameter(Mandatory=$False)]
    [switch]$SkipDnsResolution = $False
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

# Define $Filter based on switched paramter value 'IncludeClusterObjects'
Switch ($IncludeClusterObjects) {
    {$_ -eq $false} {
        $Filter = "Name -like `"$Identity`" -and OperatingSystem -like `"Windows Server*`" -and servicePrincipalName -notlike `"MS*Cluster*`""
    }
    {$_ -eq $true} {
        $Filter = "Name -like `"$Identity`" -and OperatingSystem -like `"Windows Server*`""
    }
}

# Define properties for 'Get-ADComputer' query below based on if $Credential is used
If ($Credential -eq $null) {
    $ADProperties = @{
        'Properties' = 'Name','OperatingSystem','Enabled','Description','DistinguishedName','LastLogonDate'
        'Server' = $Domain
        'Filter' = $Filter
    }
}
Else {
    $ADProperties = @{
        'Properties' = 'Name','OperatingSystem','Enabled','Description','DistinguishedName','LastLogonDate'
        'Server' = $Domain
        'Filter' = $Filter
        'Credential' = $Credential
    }
}

# Properties to include when returning results
$SelectParams = @{
    'Property' = `
        'Name',`
        @{Name="OperatingSystem";Expression={($_.OperatingSystem).ToString().Replace('Windows Server ','')}},`
        'Enabled',`
        'Description',`
        'DistinguishedName',`
        'LastLogonDate',`
        'IPAddress'
}

# Retrieve Windows servers using @ADProperties
$Servers = Get-ADComputer @ADProperties | Select-Object @SelectParams

# Switch based on -SkipDnsResolution
Switch ($SkipDnsResolution) {
    
    # '-SkipDnsResolution' is not specified, attempt DNS resolution for each AD server
    {$_ -eq $False} {
        foreach ($s in $Servers) {
            $DnsResolution = Resolve-DnsName $s.Name -Server $Domain -ErrorAction SilentlyContinue
            If ($null -eq $DnsResolution) {
                $s.IPAddress = [string]::new("Not Found")
                $s | Select-Object @SelectParams
            }
            Else {
                foreach ($dr in $DnsResolution) {
                    $s.IPAddress = $dr.IPAddress
                    $s | Select-Object @SelectParams
                }
            }
        }
    }
    
    # '-SkipDnsResolution' is specified, return information from AD without DNS resolution
    {$_ -eq $true} {
        $Servers | Select-Object @SelectParams -ExcludeProperty IPAddress
    }
}

}
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
Function New-ADOrganizationalUnitDelegation {
<#
.SYNOPSIS
Delegates access over specific AD objects within a specified OU to the specified group

.DESCRIPTION
Delegates access over specific AD objects within a specified OU to the specified group

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2022.09.22 by DS :: First revision.
    V02: 2023.06.06 by DS :: Updated documentation and cleaned up spacing.
    V03: 2023.07.18 by DS :: Removed '#Requires -Module ActiveDirectory' and added logic for required modules.
    V04: 2024.08.13 by DS :: Fixed typo in cmdlet name and script header.
    V05: 2025.03.10 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.PARAMETER OrganizationalUnit
The 'DistinguishedName' of the AD Organizational Unit where access will be delegated. The 'DistinguishedName' of the domain root may also be used.

.PARAMETER Group
The AD Group to which access will be delegated. AD group can be specified via SamAccountName, DistinguishedName, ObjectGUID or SID.

.PARAMETER ADObject
The AD 'object' to which the specified group will have delegated access. Valid options are: 'Users', 'Computers', 'Groups', 'OUs', 'GPLinks', and 'PasswordAndLockouts'

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingUsers,DC=contoso,DC=com" -Group HelpDesk -ADObject Users
Will delegate access over AD User objects in the "OU=AccountingUsers,DC=contoso,DC=com" OU, to the AD group 'HelpDesk'. Users in the 'HelpDesk' group can create/delete AD User objects in the OU and have 'FullControl' permissions on existing AD User objects within the OU and sub-OUs.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingUsers,DC=contoso,DC=com" -Group HelpDesk -ADObject PasswordAndLockouts
Will delegate access over AD User objects in the "OU=AccountingUsers,DC=contoso,DC=com" OU, to the AD group 'HelpDesk'. Users in the 'HelpDesk' group can reset passwords of AD User objects and unlock accounts of AD User objects in the OU and sub-OUs.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingGroups,DC=contoso,DC=com" -Group HelpDesk -ADObject Groups
Will delegate access over AD Group objects in the "OU=AccountingGroups,DC=contoso,DC=com" OU, to the AD group 'HelpDesk'. Users in the 'HelpDesk' group can create/delete AD Group objects in the OU and have 'FullControl' permissions on existing AD Group objects within the OU and sub-OUs.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingComputers,DC=contoso,DC=com" -Group DesktopTeam -ADObject GPLinks
Will delegate access over GPLinks in the "OU=AccountingComputers,DC=contoso,DC=com" OU, to the AD group 'DesktopTeam'. Users in the 'DesktopTeam' group can link/enforce existing GPOs to the OU and sub-OUs, however new GPOs cannot be be created by the 'DesktopTeam' group.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingComputers,DC=contoso,DC=com" -Group DesktopTeam -ADObject Computers
Will delegate access over AD Computer objects in the "OU=AccountingComputers,DC=contoso,DC=com" OU, to the AD group 'DesktopTeam'. Users in the 'DesktopTeam' group can create/delete AD Computer objects in the OU and have 'FullControl' permissions on existing AD Computer objects within the OU and sub-OUs.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('OU')]
    $OrganizationalUnit,

    [Parameter(Mandatory=$True,Position=1)]
    $Group,

    [Parameter(Mandatory=$True,Position=2)]
    [ValidateScript({$_.Count -eq 1})]
    [ValidateSet("Users", "Computers", "Groups", "OUs", "GPLinks", "PasswordAndLockouts")]
    $ADObject
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

# Set location to 'AD:\'
Try {
    Set-Location "AD:\" -ErrorAction Stop
}
Catch {
    Write-Host "FAILURE: Could not set location to 'AD:\'!" -ForegroundColor Red
    Break
}

# Ensure that both the specified Group exists
Try {
    Write-Verbose "Checking for AD Group '$Group'"
    $G = Get-ADGroup -Identity $Group -ErrorAction Stop
}
Catch {
    Write-Host "ERROR: Specified AD group '$Group' was not found" -ForegroundColor Red
    Break
}

# Ensure that specified OU exists, retrieve existing ACL if it does
Write-Verbose "Checking for AD Organizational Unit '$OrganizationalUnit'"
If (!(Test-Path $OrganizationalUnit -ErrorAction Stop)) {
    Write-Host "ERROR: Specified AD Organizational Unit '$OrganizationalUnit' was not found" -ForegroundColor Red
    Break
}
Else {
    $ACL = Get-Acl -Path $OrganizationalUnit -ErrorAction Stop
}

# Subfunctions named after the 'ADObject' parameter
Function Users {

# ACE: Full control over descendent user objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete user objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function Computers {

# ACE: Full control over descendent computer objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete computer objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function Groups {

# ACE: Full control over descendent group objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete group objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function OUs {

# ACE: Full control over descendent OU objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aa5-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete OU objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967aa5-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function GPLinks {

# ACE: Ability to read & write the 'gPOtions' attribute
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to read & write the 'GP-Link' attribute
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function PasswordAndLockouts {

# ACE: Ability to read & write the 'Lockout-Time' attribute on 'Users'
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "28630ebf-41d5-11d1-a9c1-0000f80367c1"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to read & write the 'Pwd-Last-Set' attribute on 'Users'
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "bf967a0a-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Grant the extended right 'Reset Password' on 'Users'
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ExtendedRight"
$AccessControlType = "Allow"
$ObjectType = "00299570-246d-11d0-a768-00aa006e0529"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}

# Call the subfunction specified by '-ADObject' parameter
Write-Verbose "Creating ACEs to grant '$Group' delegated access over '$ADObject' in AD OU '$OrganizationalUnit'"
& $ADObject

# Set the new ACL (with added ACEs) on the AD OU
Write-Verbose "Setting updated ACL on AD OU '$OrganizationalUnit'"
Set-Acl -AclObject $ACL -Path $OrganizationalUnit

}
Function New-X500ObjectId {
<#
.SYNOPSIS
Generates a new X500 Object ID (OID).

.DESCRIPTION
Generates a new X500 Object ID (OID) used for creation of AD schema attribute objects.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2025.05.15 by DS :: First iteration.
Call From:
    PowerShell v5.1+

.PARAMETER Prefix
The prefix for the X500 Object ID (OID). The Default value is '1.2.840.113556.1.8000.2554'.

.EXAMPLE
New-X500ObjectId
Will generate a new X500 Object ID (OID) used for the creation of AD schema attribute objects.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$Prefix = '1.2.840.113556.1.8000.2554'
)

$Guid = [System.Guid]::NewGuid().ToString()
$Uint = @()
$Subs = @(
    @(0,4),
    @(4,4),
    @(9,4),
    @(14,4),
    @(19,4),
    @(24,6),
    @(30,6)
)

foreach ($s in $Subs) {
    $Uint += [uint64]::Parse($Guid.Substring($s[0], $s[1]), "AllowHexSpecifier")
}

$Oid = [String]::Format("{0}.{1}.{2}.{3}.{4}.{5}.{6}.{7}",$Prefix,$Uint[0],$Uint[1],$Uint[2],$Uint[3],$Uint[4],$Uint[5],$Uint[6])
$Oid

}