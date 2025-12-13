Function Get-ADRidCount {
<#
.SYNOPSIS
Determines RID count information for specified domain.

.DESCRIPTION
Determines RID count information for specified domain. Inspired by the Microsoft blog post below.
https://techcommunity.microsoft.com/blog/askds/managing-rid-pool-depletion/399736

.NOTES
Authors: 
    DS & JS
Notes:
    Revision 04
Revision:
    V01: 2025.08.01 by DS :: First revision.
    V02: 2025.08.02 by DS :: Required modules logic (good catch JS).
    V03: 2025.12.11 by DS :: Cleaned up header and statement capitalization.
    V04: 2025.12.12 by DS :: Minor change to required modules. Line lengths.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.INPUTS
None

.OUTPUTS
None

.PARAMETER DomainName
The domain name (either FQDN or NetBIOS) to query. The default value is $env:USERDNSDOMAIN.

.EXAMPLE
Get-ADRidCount
Queries the user's current domain for RID count information.

.EXAMPLE
Get-ADRidCount -DomainName 'contoso.com'
Queries the 'contoso.com' domain for RID count information.

.EXAMPLE
$LogEntry = @{
    'LogName' = 'System'
    'Source' = 'SAM'
    'EventId' = 42069
    'EntryType' = 'Information'
    'Message' = "RIDs remaining: $((Get-ADRidCount).RIDsRemaining)"
}
Write-EventLog @LogEntry
Writes an event log entry containing the remaining number of RIDs.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False, Position=0)]
    [string]$DomainName = $env:USERDNSDOMAIN
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

try {
    $Domain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
}
catch {
    throw
}

# Splat table for Get-ADObject cmdlet below
$ADObject = @{
    'Identity' = "cn=rid manager$,cn=system,$($Domain.distinguishedName)"
    'Property' = 'ridavailablepool'
    'Server' = "$($Domain.RIDMaster)"
}

$ridavailablepool = (Get-ADObject @ADObject).ridavailablepool
[int32]$totalSIDS = $($ridavailablepool) / ([math]::Pow(2,32))
[int64]$temp64val = $totalSIDS * ([math]::Pow(2,32)) 
[int32]$currentRIDPoolCount = $($ridavailablepool) - $temp64val

"" | Select-Object @{N="DomainName";E={$DomainName}},
    @{N="RIDMaster";E={$Domain.RIDMaster}},
    @{N="RIDsIssued";E={$currentRIDPoolCount}},
    @{N="RIDsRemaining";E={$totalSIDS - $currentRIDPoolCount}}

}