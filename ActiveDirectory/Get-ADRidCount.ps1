Function Get-ADRidCount {
<#
.SYNOPSIS
Determines RID count information for specified domain.

.DESCRIPTION
Determines RID count information for specified domain. Inspired by the Microsoft blog post below, updated with error handling and better output.
https://techcommunity.microsoft.com/blog/askds/managing-rid-pool-depletion/399736

.NOTES
Authors: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2025.08.01 by DS :: First revision.
    V02: 2025.08.02 by DS :: Required modules logic (good catch JS).
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.PARAMETER DomainName
The domain name (either FQDN or NetBIOS) to query. The default value is $env:USERDNSDOMAIN.

.EXAMPLE
Get-ADRidCount
Queries the user's current domain for RID count information.

.EXAMPLE
Get-ADRidCount -DomainName 'contoso.com'
Queries the 'contoso.com' domain for RID count information.

.EXAMPLE
Write-EventLog -LogName System -Source SAM -EventId 42069 -EntryType Information -Message "RIDs remaining: $((Get-ADRidCount).RIDsRemaining)"
Writes an event log entry containing the remaining number of RIDs. Good for tracking RID usage over time if you have a SIEM...
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False, Position=0)]
    [string]$DomainName = $env:USERDNSDOMAIN
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

Try {
    $Domain = Get-ADDomain -Identity $DomainName
}
Catch {
    Throw "Unable to determine distinguishedName of domain '$DomainName'"
    Break
}

$ridavailablepool = (Get-ADObject "cn=rid manager$,cn=system,$($Domain.distinguishedName)" -Property ridavailablepool -Server $Domain.RIDMaster).ridavailablepool
[int32]$totalSIDS = $($ridavailablepool) / ([math]::Pow(2,32))
[int64]$temp64val = $totalSIDS * ([math]::Pow(2,32)) 
[int32]$currentRIDPoolCount = $($ridavailablepool) - $temp64val

"" | Select-Object `
    @{N="DomainName";E={$DomainName}},`
    @{N="RIDMaster";E={$Domain.RIDMaster}},`
    @{N="RIDsIssued";E={$currentRIDPoolCount}},`
    @{N="RIDsRemaining";E={$totalSIDS - $currentRIDPoolCount}}

} 