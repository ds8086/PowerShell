Function Get-LDAPSigningLoggingState {
<#
.SYNOPSIS
Retrieve current state of LDAP signing logging.

.DESCRIPTION
Retrieve current state of LDAP signing logging. Note: This logging is *not* enabled by default.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2023.03.08 by DS :: First revision.
    V02: 2025.11.19 by DS :: Minor overhaul for GitHub.
    V03: 2025.12.11 by DS :: Cleaned up header and statement capitalization.
Call From:
    PowerShell v4 or higher

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Get-LDAPSigningLoggingState
Retrieves current LDAP signing logging state (enabled or disabled) from the localhost.

.LINK
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd941849(v=ws.10)
#>
[CmdletBinding()]
param ()

$params = @{
    'Path' = 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics'
    'Name' = '16 LDAP Interface Events'
    'ErrorAction' = 'Stop'
}
$select = @{
    'Property' = @(
        @{
            Name="PSComputerName";
            Expression={$env:COMPUTERNAME}
        },
        @{
            Name="DebugLogging";
            Expression={
                switch($_.'16 LDAP Interface Events'){
                    0 {[string]::new('disabled')}
                    2 {[string]::new('enabled')}
                    Default {[string]::new('unknown')}
                }
            }
        }
    )
}

try {
    Get-ItemProperty @params | Select-Object @select
}
catch {
    Write-Warning "Refer to 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd941849(v=ws.10)'"
    throw $Error[0].Exception.Message
}

}