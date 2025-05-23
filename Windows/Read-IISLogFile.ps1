Function Read-IISLogFile {
<#
.SYNOPSIS
Reads the specified IIS log file, adds the 'local' time for log entries, and converts log to a CSV.

.DESCRIPTION
Reads the specified IIS log file, adds the 'local' time for log entries, and converts log to a CSV.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2023.07.26 by DS :: First revision
    V02: 2024.12.24 by DS :: Fixed issues identified by VS Code, cleaned up param block spacing.
    V03: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    Windows PowerShell v5.1 or higher

.PARAMETER Path
The path to the IIS log file.

.PARAMETER Credential
Optional parameter for alternate credentials used in accessing the IIS log file.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log'
Will read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and output the results to the default output.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log' -Credential (Get-Credential)
Will prompt for credentials at exeuction and use them to read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and output the results to the default output.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log' | Out-GridView
Will read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and output the results to grid view.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log' | Export-CSV .\19991231.csv -NoTypeInformation
Will read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and export the results to a CSV file named '19991231.csv' in the current directory.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
	[ValidateScript({Test-Path $_})]
    [string]$Path,

    [Parameter(Mandatory=$False,Position=1)]
    [pscredential]$Credential = $null
)

# Determine $ContentParams for 'Get-Content' below
switch ($Credential) {
    {$_ -ne $null} {
        $ContentParams = @{
            'Path' = $Path
            'Credential' = $Credential
        }
    }
    {$_ -eq $null} {
        $ContentParams = @{
            'Path' = $Path
        }
    }
}

# Determine local timezone
$tz = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date))

# Get log and determine header
$Log = Get-Content @ContentParams
$Header = ($Log[3]).Replace('#Fields: ','').Split(' ')

# Convert log to CSV using header and add local time
$Csv = ConvertFrom-Csv -Delimiter " " -InputObject $Log -Header $Header
$Csv | Select-Object @{N="datetime(UTC$($tz.Hours))";E={([datetime]::Parse($_.date + " " + $_.time)).AddHours($tz.Hours)}},*

}