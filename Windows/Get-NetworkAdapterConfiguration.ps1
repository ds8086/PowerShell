Function Get-NetworkAdapterConfiguration {
<#
.SYNOPSIS
Retrieves network adapter configuration information for specified computer(s).

.DESCRIPTION
Retrieves network adapter configuration information for specified computer(s).

.NOTES
Author: 
    Devin S
Notes:
    Revision 04
Revision:
    V01: 2023.06.15 by DS :: First iteration.
    V02: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' from $ComputerName parameter.
    V03: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which drive information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-NetworkAdapterConfiguration -ComputerName FileServer01
Will return network adapter configuration information for computer FileServer01.

.EXAMPLE
Get-NetworkAdapterConfiguration -ComputerName FileServer01,FileServer02
Will return network adapter configuration information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-NetworkAdapterConfiguration -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve network adapter configuration information for FileServer01.
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
            'Class' = 'Win32_NetworkAdapterConfiguration'
            'Filter' = "IPEnabled = 'True'"
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'Win32_NetworkAdapterConfiguration'
            'Filter' = "IPEnabled = 'True'"
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        'DHCPEnabled',`
        'IPAddress',`
        'DefaultIPGateway',`
        'DNSDomain',`
        'ServiceName',`
        'Description',`
        'Index'
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DHCPEnabled";E={[string]::new("None")}},`
        @{N="IPAddress";E={[string]::new("None")}},`
        @{N="DefaultIPGateway";E={[string]::new("None")}},`
        @{N="DNSDomain";E={[string]::new("None")}},`
        @{N="ServiceName";E={[string]::new("None")}},`
        @{N="Description";E={[string]::new("None")}},`
        @{N="Index";E={[string]::new("None")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DHCPEnabled";E={[string]::new("Error")}},`
        @{N="IPAddress";E={[string]::new("Error")}},`
        @{N="DefaultIPGateway";E={[string]::new("Error")}},`
        @{N="DNSDomain";E={[string]::new("Error")}},`
        @{N="ServiceName";E={[string]::new("Error")}},`
        @{N="Description";E={[string]::new("Error")}},`
        @{N="Index";E={[string]::new("Error")}}
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