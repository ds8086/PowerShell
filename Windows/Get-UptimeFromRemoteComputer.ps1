Function Get-UptimeFromRemoteComputer {
<#
.SYNOPSIS
Retrieves system uptime for specified computer(s).

.DESCRIPTION
Retrieves system uptime for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2017.11.02 by DS :: First working itteration.
    V02: 2018.12.28 by DS :: Added 'Credential' parameter and improved parameter block.
    V03: 2023.05.16 by DS :: Major script rewrite using template for 'Get-WmiObject' based cmdlets.
    V04: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' from $ComputerName parameter.
    V05: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
    V07: 2025.06.03 by DS :: Updated function name and documentation.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which uptime information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-UptimeFromRemoteComputer -ComputerName FileServer01
Will return uptime information for computer FileServer01.

.EXAMPLE
Get-UptimeFromRemoteComputer -ComputerName FileServer01,FileServer02
Will return uptime information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-UptimeFromRemoteComputer -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve uptime information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName,

    [Parameter(Mandatory=$false,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory=$false)]
    [switch]$NoProgress = $false
)

# Splat table for 'Get-WmiObject' parameters
switch ($Credential) {
    {$_ -ne $null} {
        $WmiParams = @{
	        'ComputerName' = ""
	        'Credential' = $Credential
            'Class' = 'win32_OperatingSystem'
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'win32_OperatingSystem'
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="LastBootUp";E={$_.ConvertToDateTime($_.LastBootUpTime)}}
        @{N="Uptime";E={(Get-Date) - ($_.ConvertToDateTime($_.LastBootUpTime))}}
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="LastBootUp";E={[string]::new("None")}},`
        @{N="Uptime";E={[string]::new("None")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="LastBootUp";E={[string]::new("Error")}},`
        @{N="Uptime";E={[string]::new("Error")}}
    )
}

# Foreach loop to get WMI object from each $cn in $ComputerName
$i = 0
$WmiResults = foreach ($cn in $ComputerName) {
    If (!$NoProgress) {
        $i++
        Write-Progress "Retrieving information from $cn" -PercentComplete ($i / $ComputerName.Count * 100)
    }

    $WmiParams.ComputerName = $cn
    Try {
        $wmi = Get-WmiObject @WmiParams
        If ($wmi) {
            $wmi | Select-Object @WmiSelect
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Warning "'$cn' WMI connectivity failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$WmiResults

}