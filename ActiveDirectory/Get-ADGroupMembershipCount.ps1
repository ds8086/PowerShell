Function Get-ADGroupMembershipCount {
<#
.SYNOPSIS
Retrieves group membership count for specified AD user.

.DESCRIPTION
Retrieves group membership count for specified AD user.

.NOTES
Author:
    DS
Notes:
    Revision 02
Revision:
    V01: 2024.04.12 by DS :: Rough draft revision.
    V02: 2025.11.20 by DS :: Polished for GitHub.
Call From:
    PowerShell v4 or higher w/ ActiveDirectory module

.PARAMETER Identity
The identity (samAccountName, UserPrincipleName, DN) of AD user.

.PARAMETER Server
The domain or domain controller for AD queries.

.PARAMETER NoLimit
Switched parameter which, when specified, queries all group memberships for AD user past the realistic usable limit of 1000.

.EXAMPLE
Get-ADGroupMembershipCount -Identity 'JKirk' -Server 'dc01.contoso.com'
Retrieves the group membership count for AD user 'JKirk' from server 'dc01.contoso.com'.

.EXAMPLE
Get-ADGroupMembershipCount -Identity 'JKirk' -Server 'contoso.com' -NoLimit
Retrieves the group membership count for AD user 'JKirk' from domain 'contoso.com' past the realistic usable limit of 1000 groups.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$Identity = $env:USERNAME,

    [Parameter(Mandatory=$False,Position=1)]
    [string]$Server = $env:USERDOMAIN,

    [Parameter(Mandatory=$False)]
    [switch]$NoLimit = $false
)

# Arrays to hold queued and result AD groups
$Queued = New-Object -TypeName System.Collections.ArrayList
$Result = New-Object -TypeName System.Collections.ArrayList

# AD user and its group membership
Try {
    $ADUser = Get-ADUser -Server $Server -Identity $Identity -Properties MemberOf, PrimaryGroup -ErrorAction Stop
    $membership = $ADUser.MemberOf
    $membership += $ADUser.PrimaryGroup
}
Catch {
    throw
}

# Add direct membership to queued
foreach ($m in $membership) {
    $Queued.Add($m) | Out-Null
}

# Add two dummy entries to queued array (allows dynamic resizing)
$Queued.Add('0') | Out-Null
$Queued.Add('1') | Out-Null

# Main process on queued AD groups
$i = 0
Do {
    foreach ( $q in $Queued ) {
        
        # Break at 1000 groups unless 'NoLimit' is specified
        If ($Result.Count -eq 1000) {
            If ($NoLimit -eq $False) {
                Write-Warning "User '$Identity' has too many Group SIDs! Run again with '-NoLimit'."
                break
            }
        }

        if ($q -notin 0,1) {
            $i++
            
            # Determine if group is itself a member of groups
            $parentGroups = $null
            $parentGroups = (Get-ADGroup -Server $Server -Identity $q -Properties MemberOf).MemberOf
            
            # Add any parent groups to the dynamic array of queued groups
            If ($parentGroups) {
                Write-Verbose "Group '$q' is a member of $($parentGroups.Count) parent group(s)"
                foreach ($pg in $parentGroups) {
                    If ( ($Queued -notcontains $pg) -and ($Result -notcontains $pg) ) {
                        $Queued += $pg
                    }
                }
            }
            
            # Add group to results if not already present
            If ($Result -notcontains $q) {
                $result.Add($q) | Out-Null
            }
            
            # Remove group from queue
            $Queued = $Queued | Where-Object {$_ -ne $q}

            # Output progress
            Write-Verbose "Current queue...: $($Queued.Count - 2)"
            Write-Verbose "Group count.....: $($Result.Count)"
        }
    }
}
Until (
    ($Queued.Count -eq 2) -or ($Result.Count -eq 1000)
)

# Results
$Select = @{
    'Property' = @(
        @{Name="Server";Expression={$Server}},
        'SamAccountName',
        'DistinguishedName',
        @{Name="Groups";Expression={$Result.Count}}
    )
}
$ADUser | Select-Object @Select

}