Function Get-LDAPSigningEvents {
<#
.SYNOPSIS
Retrieve event ID 2889 directory service log entries.

.DESCRIPTION
Retrieve event ID 2889 directory service log entries. Note: This logging is *not* enabled by default.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2023.03.08 by DS :: First revision.
    V02: 2025.11.19 by DS :: Minor overhaul for GitHub.
Call From:
    PowerShell v4 or higher

.PARAMETER MaxEvents
Optional parameter to specify the number of most recent events in directory services log to search for event ID 2889 log entries. The default value is 5000.

.EXAMPLE
Get-LDAPSigningEvents
Retrieves events with ID 2889 from directory services log on localhost.

.LINK
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-r2-and-2008/dd941849(v=ws.10)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [long]$MaxEvents = 5000
)

If ($MaxEvents -gt 5000) {
    Write-Warning "Retrieving more than 5000 events is not recommended and greatly increases script execution time"
}

$params = @{
    'ProviderName' = 'Microsoft-Windows-ActiveDirectory_DomainService'
    'MaxEvents' = $MaxEvents
}
$select = @{
    'Property' = @(
        @{
            Name = 'PSComputerName';
            Expression = {$env:COMPUTERNAME}
        },
        'TimeCreated',
        @{
            Name = 'ClientIP';
            Expression = {$message[1]}
        },
        @{
            Name = 'Identity';
            Expression = {$message[3]}
        },
        @{
            Name = 'BindingType';
            Expression = {$message[5]}
        }
    )
}

$WinEvent = Get-WinEvent @params | Where-Object {$_.Id -eq 2889}
If ($WinEvent) {
	foreach ($we in $WinEvent) {
		$i++
		Write-Progress "Parsing events..." -PercentComplete ($i / $WinEvent.Count * 100)
		
		$message = $null
		$message = $we.Message.split([System.Environment]::NewLine) | Where-Object {$_ -ne "" -and $_ -ne " " -and $_ -notlike "The following client performed a SASL*"}
			
		$we | Select-Object @select
	}
}
Else {
    Write-Warning "No 2889 event log entries"
}

}