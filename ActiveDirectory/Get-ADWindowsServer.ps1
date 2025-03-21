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