Function Get-DriveDetails {
<#
.SYNOPSIS
Retrieves drive information for specified computer(s).

.DESCRIPTION
Retrieves drive information for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 12
Revision:
    V01: 2017.04.12 by DS :: Proof of concept.
    V02: 2017.06.19 by DS :: Removed formatting in foreach loop.
    V03: 2017.09.18 by DS :: Added ping test and check for enabled AD object in filter. Added switched parameter 'ServersOnly' and corresponding If tests.
    V04: 2017.11.20 by DS :: Added parameter 'Credential' and corresponding If tests.
    V05: 2018.05.25 by DS :: Removed parenthesis from output.
    V06: 2022.10.04 by DS :: Removed check for computer object in AD. Replaced ping test with WSMan test. Updated documentation.
    V07: 2023.02.21 by DS :: Updated 'Test-WSMan' cmdlet. Added -Authentication Negotiate.
    V09: 2023.05.18 by DS :: Script rewrite to utilize 'Get-WmiObject' template.
    V10: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' from $ComputerName parameter.
    V11: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V12: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which drive information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-DriveDetails -ComputerName FileServer01
Will return drive information for computer FileServer01.

.EXAMPLE
Get-DriveDetails -ComputerName FileServer01,FileServer02
Will return drive information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-DriveDetials -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve drive information for FileServer01.
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
            'Class' = 'Win32_LogicalDisk'
            'Filter' = 'DriveType = 3'
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'Win32_LogicalDisk'
            'Filter' = 'DriveType = 3'
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        'DeviceID',`
        'VolumeName',`
        @{Name="SizeGB";Expression={[Math]::Round($_.Size / 1GB)}},`
        @{Name="FreeGB";Expression={[Math]::Round($_.FreeSpace / 1GB)}},`
        @{Name="PercentFree";Expression={[Math]::Round($_.FreeSpace / $_.Size * 100)}}
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DeviceID";E={[string]::new("None")}},`
        @{N="VolumeName";E={[string]::new("None")}},`
        @{N="SizeGB";E={[string]::new("None")}},`
        @{N="FreeGB";E={[string]::new("None")}},`
        @{N="PercentFree";E={[string]::new("None")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DeviceID";E={[string]::new("Error")}},`
        @{N="VolumeName";E={[string]::new("Error")}},`
        @{N="SizeGB";E={[string]::new("Error")}},`
        @{N="FreeGB";E={[string]::new("Error")}},`
        @{N="PercentFree";E={[string]::new("Error")}}
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