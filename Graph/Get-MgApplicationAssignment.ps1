#Requires -Version 7
#Requires -Modules Microsoft.Graph.Applications, Microsoft.Graph.Authentication, Microsoft.Graph.Users
Function Get-MgApplicationAssignment {
    <#
.SYNOPSIS
Retrieves Entra application assignments

.DESCRIPTION
Retrieves Entra application assignments

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.11.03 by DS :: First revision.
Call From:
    PowerShell v7+ w/ Microsoft.Graph modules

.PARAMETER PrincipalType
The app assignment principal types to return. Valid values are 'All', 'Group', and 'User. Default is 'All'.

.PARAMETER AccountEnabled
Only returns app assignments where enabled user accounts are assigned (directly or via a group).

.EXAMPLE
Get-MgApplicationAssignment
Retrieves all Entra application assignments.

.EXAMPLE
Get-MgApplicationAssignment -PrincipalType 'User' -AccountEnabled
Retrieves Entra applications assigned directly to users where the user account is enabled.

.EXAMPLE
Get-MgApplicationAssignment -PrincipalType 'Group'
Retrieves Entra application assignments for groups.
#>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False, Position = 0)]
        [ValidateSet('All', 'Group', 'User')]
        [string]$PrincipalType = 'All',

        [Parameter(Mandatory = $False)]
        [switch]$AccountEnabled = $False
    )

    # Get-MgUser parameters
    $param = @{
        'All'              = $true
        'ConsistencyLevel' = 'eventual'
        'ErrorAction'      = 'Stop'
    }
    if ($AccountEnabled) {
        $param.Add('Filter', 'accountEnabled eq true')
    }

    # retrieve users (connect to graph if not already)
    try {
        $users = Get-MgUser @param
    }
    catch {
        if ($Error[0].Exception.Message -eq 'Authentication needed. Please call Connect-MgGraph.') {
            try {
                Connect-MgGraph -NoWelcome
                $users = Get-MgUser @param
            }
            catch {
                throw $Error[0]
            }
        }
    }

    # app role assignments
    $i = 0
    $assignments = foreach ($u in $users) {
        $i++
        Write-Progress "Processing user '$($u.DisplayName)'" -PercentComplete ($i / $users.Count * 100)

        $splat = @{
            'Property' = @(
                @{ N = 'DisplayName'; E = { $u.DisplayName } },
                @{ N = 'Id'; E = { $u.Id } },
                @{ N = 'UserPrincipalName'; E = { $u.UserPrincipalName } },
                @{ N = 'PrincipalDisplayName'; E = { $_.PrincipalDisplayName } },
                @{ N = 'PrincipalId'; E = { $_.PrincipalId } },
                @{ N = 'PrincipalType'; E = { $_.PrincipalType } },
                @{ N = 'ResourceDisplayName'; E = { $_.ResourceDisplayName } },
                @{ N = 'ResourceId'; E = { $_.ResourceId } }
            )
        }
        try {
            Get-MgUserAppRoleAssignment -UserId $u.Id -ErrorAction Stop | Select-Object @splat
        }
        catch {
            throw $Error[0].Exception.Message
        }
    }

    # output based on 'PrincipalType' value
    switch ($PrincipalType) {
        
        # user and group assignments
        { $_ -eq 'All' } {
            $assignments
        }

        # group assignments (deduplicated)
        { $_ -eq 'Group' } {

            $splat = @{
                'First'    = 1
                'Property' = @(
                    @{ N = 'PrincipalDisplayName'; E = { $_.PrincipalDisplayName } },
                    @{ N = 'PrincipalId'; E = { $_.PrincipalId } },
                    @{ N = 'PrincipalType'; E = { $_.PrincipalType } },
                    @{ N = 'ResourceDisplayName'; E = { $_.ResourceDisplayName } },
                    @{ N = 'ResourceId'; E = { $_.ResourceId } }
                )
            }
            
            # unique groups
            $groups = (
                $assignments | Where-Object { $_.PrincipalType -eq 'Group' }
            ).PrincipalId | Select-Object -Unique

            # deduplicate app <--> group assignment list
            $i = 0
            $group_assignments = foreach ($g in $groups) {
                $i++
                Write-Progress "Processing group '$g'" -PercentComplete ($i / $groups.Count * 100) -Id 1

                $apps = $null
                $apps = (
                    $assignments | Where-Object { $_.PrincipalId -eq $g }
                ).ResourceId | Select-Object -Unique

                $ii = 0
                foreach ($a in $apps) {
                    try {
                        $ii++
                        Write-Progress "Processing app '$a'" -PercentComplete ($ii / $apps.Count * 100) -ParentId 1
                    }
                    catch {}

                    $assignments | Where-Object {
                        $_.ResourceId -eq $a -and $_.PrincipalId -eq $g
                    } | Select-Object @splat
                }
            }

            # deduplicated app <--> group assignments output
            $group_assignments
        }

        # user assignments
        { $_ -eq 'User' } {
            $assignments | Where-Object {
                $_.PrincipalType -eq 'User'
            }
        }
    }
}