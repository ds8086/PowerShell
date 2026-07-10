Function Get-MgGuestUserState {
    <#
.SYNOPSIS
Retrieve Entra guest user states.

.DESCRIPTION
Retrieve Entra guest user states.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.07.10 by DS :: First working iteration.
Call From:
    PowerShell v7 w/ Microsoft.Graph modules

.INPUTS
None

.OUTPUTS
None

.PARAMETER SearchString
Search string for Entra guest user mail. Default value is *.

.EXAMPLE
Get-MgGuestUserState
Retrieve all Entra guest user states.

.EXAMPLE
Get-MgGuestUserState -SearchString 'starfleet.gov'
Retrieve all Entra guest user states searching for 'starfleet.gov'.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [string]$SearchString = "*"
    )

    # Get-MgUser parameters
    $param = @{
        'ErrorAction' = 'Stop'
        'Filter'      = "userType eq 'Guest'"
        'Property'    = @(
            'DisplayName',
            'Mail',
            'ExternalUserState',
            'CreatedDateTime',
            'ExternalUserStateChangeDateTime'
        )
    }

    # retrieve users, attempting MG Graph connection if needed
    try {
        $guestUsers = Get-MgUser @param
    }
    catch {
        if ($Error[0].Exception.Message -eq 'Authentication needed. Please call Connect-MgGraph.') {
            try {
                Connect-MgGraph -Scopes "User.Read.All" -ErrorAction Stop
                $guestUsers = Get-MgUser @param
            }
            catch {
                throw
            }
        }
    }

    # output
    $guestUsers | Where-Object { $_.Mail -like "*$SearchString*" } | Select-Object -Property $param.Property
}