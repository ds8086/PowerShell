Function Get-InstalledSoftware {
<#
.SYNOPSIS
Retrieves installed software information for specified computer(s).

.DESCRIPTION
Retrieves installed software information for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2017.10.05 by DS :: Proof of concept.
    V02: 2021.11.24 by DS :: Added parameter for alternate credentials.
    V03: 2023.07.05 by DS :: Rewrite using new 'Invoke-Command' template.
    V04: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V05: 2024.12.24 by DS :: Fixed issues identified by VS Code, fixed param block spacing.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which installed software information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-InstalledSoftware -ComputerName FileServer01
Will return installed software information for computer FileServer01.

.EXAMPLE
Get-InstalledSoftware -ComputerName FileServer01,FileServer02
Will return installed software information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-InstalledSoftware -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve installed software information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string[]]$ComputerName,

    [Parameter(Mandatory=$False,Position=1)]
    [string]$Search = "*",
    
    [Parameter(Mandatory=$False,Position=2)]
    [pscredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$NoProgress = $false
)

# ScriptBlock used in 'Invoke-Command'
[System.Management.Automation.ScriptBlock]$ScriptBlock = {
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.DisplayName -like "*$Using:Search*") -and ($null -ne $_.DisplayName) }
    Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.DisplayName -like "*$Using:Search*") -and ($null -ne $_.DisplayName) }
}

# Splat table for 'Invoke-Command' parameters
switch ($Credential) {
    {$_ -ne $null} {
        $InvParams = @{
	        'ComputerName' = ""
	        'Credential' = $Credential
            'ErrorAction' = 'Stop'
            'ScriptBlock' = $ScriptBlock
        }
    }
    {$_ -eq $null} {
        $InvParams = @{
	        'ComputerName' = ""
            'ErrorAction' = 'Stop'
            'ScriptBlock' = $ScriptBlock
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$InvSelect = @{ 
    'Property'= @( `
        'PSComputerName',`
        'DisplayName',`
        'DisplayVersion',`
        'Publisher',`
        'InstallDate',`
        'InstallLocation'
    )
}

# Splat table for 'Select-Object' (successful 'invoke-command' w/o data)
$NonSelect = @{
    'Property'= @( `
        @{N="PSComputerName";E={$cn}},`
        @{N="DisplayName";E={[string]::new("No matching software")}},`
        @{N="DisplayVersion";E={[string]::new("No matching software")}},`
        @{N="Publisher";E={[string]::new("No matching software")}},`
        @{N="InstallDate";E={[string]::new("No matching software")}},`
        @{N="InstallLocation";E={[string]::new("No matching software")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @( `
        @{N="PSComputerName";E={$cn}},`
        @{N="DisplayName";E={[string]::new("Invoke-Command Error")}},`
        @{N="DisplayVersion";E={[string]::new("Invoke-Command Error")}},`
        @{N="Publisher";E={[string]::new("Invoke-Command Error")}},`
        @{N="InstallDate";E={[string]::new("Invoke-Command Error")}},`
        @{N="InstallLocation";E={[string]::new("Invoke-Command Error")}}
    )
}

# Foreach loop to get WMI object from each $cn in $ComputerName
$i = 0
$InvResults = foreach ($cn in $ComputerName) {
    If (!$NoProgress) {
        $i++
        Write-Progress "Retrieving information from $cn" -PercentComplete ($i / $ComputerName.Count * 100)
    }

    $InvParams.ComputerName = $cn
    Try {
        $inv = Invoke-Command @InvParams
        If ($inv) {
            $inv | Select-Object @InvSelect
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Warning "'$cn' 'Invoke-Command' failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$InvResults

}