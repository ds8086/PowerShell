Function Clear-CMClientCache {
<#
.SYNOPSIS
Clear SCCM client cache on specifced computer(s)

.DESCRIPTION
Clear SCCM client cache on specifced computer(s)

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2023.04.21 by DS :: First revision.
    V02: 2024.12.24 by DS :: Fixed issues identified by VS Code, cleaned up param block spacing.
    V03: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The target computer(s) which will have SCCM client cache cleared

.PARAMETER Credential
Alternate credentials used for invoking command on target computer(s)

.EXAMPLE
Clear-CMClientCache -ComputerName 'Fileserver01'
Will clear SCCM client cache on computer 'Fileserver01'

.EXAMPLE
Clear-CMClientCache -ComputerName 'Fileserver01' -Credential (Get-Credential)
Will clear SCCM client cache on computer 'Fileserver01', credentials for the operation will be gathered during execution
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,ValueFromPipeline=$true,Position=0)]
    [Alias('Computer')]
    [string[]]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null
)

# Create a splat table for 'Invoke-Command' parameters
switch ($Credential) {
    {$_ -ne $null} {
        $InvokeParams = @{
	        'ComputerName' = $ComputerName;
	        'Credential' = $Credential;
        }
    }
    {$_ -eq $null} {
        $InvokeParams = @{
	        'ComputerName' = $ComputerName;
        }
    }
}

# Invoke command on $ComputerName using $Credential if specified
Invoke-Command @InvokeParams -ScriptBlock {
    
    # WIN32 ComputerSystem object for output
    $cs = Get-WmiObject Win32_ComputerSystem

    # Initialize the CCM resource manager com object
    [__comobject]$CCMComObject = New-Object -ComObject 'UIResource.UIResourceMgr'
    
    # Get the CacheElementIDs to delete
    $CacheInfo = $CCMComObject.GetCacheInfo().GetCacheElements()
    
    # Remove cache items
    $i = 0
    Foreach ($ci in $CacheInfo) {
        $i++
        Write-Verbose "Removing '$($ci.CacheElementId)' from '$($ci.Location)'"
        $null = $CCMComObject.GetCacheInfo().DeleteCacheElement([string]$($ci.CacheElementID))
    }
    
    $Cache = Get-WmiObject -Namespace root\ccm\SoftMgmtAgent -Class CacheConfig -ErrorAction Stop
    If ($null -eq (Get-ChildItem -Path $Cache.Location)) {
        Write-Host "SUCCESS: '$($cs.Name).$($cs.Domain)' SCCM client cache cleared" -ForegroundColor Green
    }
    Else {
        Write-Warning "'$($cs.Name).$($cs.Domain)' SCCM client cache still exists"
    }
}

}