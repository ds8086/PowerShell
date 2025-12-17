Function Set-LDAPSigningLoggingState {
<#
.SYNOPSIS
Set the state of LDAP signing logging.

.DESCRIPTION
Sets the state (enabled or disabled) for LDAP signing logging. Note: This logging is *not* enabled by default.

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2023.03.08 by DS :: First revision.
    V02: 2023.04.17 by DS :: Added 'EventLogSize' parameter and logic.
    V03: 2025.11.19 by DS :: Minor overhaul for GitHub. Removed 'EventLogSize' parameter (not honored?).
    V04: 2025.12.11 by DS :: Cleaned up header and statement capitalization.
    V05: 2025.12.16 by DS :: Line lengths.
Call From:
    PowerShell v4 or higher

.INPUTS
None

.OUTPUTS
None

.PARAMETER State
The desired state of LDAP signing logging on the localhost. Valid values are 'Enabled' (2) or 'Disabled' (0).

.EXAMPLE
Set-LDAPSigningLoggingState -State Enabled
Enables LDAP signing logging on the localhost.

.LINK
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd941849(v=ws.10)
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
	[ValidateSet("Enabled", "Disabled", "0", "2")]
    [string]$State
)

switch ($State) {
    {$_ -eq "Enabled"} {$Value = 2}
    {$_ -eq "Disabled"} {$Value = 0}
    Default {$Value = $State}
}

$params = @{
    'Path' = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
    'Name' = '16 LDAP Interface Events'
    'Value' = $Value
    'ErrorAction' = 'Stop'
}

try {
    Set-ItemProperty @params
}
catch {
    $url = 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd941849(v=ws.10)'
    Write-Warning "Refer to '$url'"
    throw $Error[0].Exception.Message
}

}