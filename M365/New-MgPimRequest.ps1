#Requires -Version 7
#Requires -Module Microsoft.Graph.Authentication, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Users
Function New-MgPimRequest {
    <#
.SYNOPSIS
Create a PIM role activation request.

.DESCRIPTION
Create a PIM role activation request.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2026.04.03 by DS :: First working iteration.
    V02: 2026.04.07 by DS :: Updated required modules.
Call From:
    PowerShell v7 w/ Microsoft.Graph modules

.INPUTS
None

.OUTPUTS
None

.PARAMETER Hours
The number of hours for the PIM role request.

.PARAMETER Role
The role(s) included in the PIM role activation request.

.PARAMETER Justification
Justification for the PIM role activation request.

.EXAMPLE
New-MgPimRequest -Hours 8 -Role 'Global Administrator' -Justification 'Admin tasks'
Creates a new 'Global Administrator' PIM role activation request with duration of 8 hours.
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False, Position = 0)]
        [ValidateSet(1, 2, 3, 4, 5, 6, 7, 8)]
        [int]$Hours = 1,

        [Parameter(Mandatory = $False, Position = 1)]
        [string[]]$Role = 'Global Administrator',
    
        [Parameter(Mandatory = $False, Position = 2)]
        [AllowEmptyString()]
        [string]$Justification = '<NULL>'
    )

    # Microsoft Graph connection    
    $Scopes = @{
        'ErrorAction' = 'Stop'
        'Scopes'      = @(
            'RoleAssignmentSchedule.ReadWrite.Directory',
            'RoleManagement.ReadWrite.Directory',
            'RoleAssignmentSchedule.Remove.Directory'
        )
    }
    try {
        Write-Verbose "Connect to Microsoft graph"
        Connect-MgGraph @Scopes
    }
    catch {
        throw
    }

    # Context and user
    $AccountId = (Get-MgUser -UserId $(Get-MgContext).Account).Id

    # Get all available roles
    $AllRoles_Splat = @{
        'ExpandProperty' = 'RoleDefinition'
        'All'            = $true
        'Filter'         = "principalId eq '$AccountId'"
    }
    $AllRoles = Get-MgRoleManagementDirectoryRoleEligibilitySchedule @AllRoles_Splat

    # Requested roles
    $ReqRoles = foreach ($r in $Role) {
        $AllRoles | Where-Object { $_.RoleDefinition.DisplayName -eq "$Role" }
    }

    # No valid roles
    if (!($ReqRoles)) {
        Write-Warning 'No eligible PIM roles found, nothing to do!'
    }

    foreach ($rr in $ReqRoles) {
    
        # Parameters for role activation
        $params = @{
            'Action'           = "selfActivate"
            'PrincipalId'      = $rr.PrincipalId
            'RoleDefinitionId' = $rr.RoleDefinitionId
            'DirectoryScopeId' = $rr.DirectoryScopeId
            'Justification'    = $Justification
            'ScheduleInfo'     = @{
                'StartDateTime' = Get-Date
                'Expiration'    = @{
                    'Type'     = "AfterDuration"
                    'Duration' = "PT$($Hours)H"
                }
            }
        }

        # Activate the role
        New-MgRoleManagementDirectoryRoleAssignmentScheduleRequest -BodyParameter $params
    }
}