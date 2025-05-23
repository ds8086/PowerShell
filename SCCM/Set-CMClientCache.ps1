Function Set-CMClientCache {
<#
.SYNOPSIS
Sets SCCM client cache size and/or location.

.DESCRIPTION
Sets SCCM client cache size and/or location.

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2018.02.09 by DS :: First working iteration.
    V02: 2023.04.18 by DS :: Multiple improvements and addition of new parameters.
    V03: 2023.04.21 by DS :: Made $ComputerName a variable type of multi-valued string, dropped Try...Catch from 'Invoke-Command' (not needed).
    V04: 2024.12.24 by DS :: Fixed issues identified by VS Code, cleaned up param block spacing.
    V05: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
Name of the remote computer(s) which will have SCCM client cache reconfigured

.PARAMETER NewLocation
The new location for SCCM client cache, the specified location is appended with 'ccmcache'

.PARAMETER NewSize
The new size in MB for SCCM client cache.

.PARAMETER Credential
Alternate credentials for connecting to the specified computer(s)

.EXAMPLE
Set-CMClientCache -ComputerName 'Server01' -NewLocation E:\
Will move the SCCM client cache on 'Server01' to 'E:\ccmcache'

.EXAMPLE
Set-CMClientCache -ComputerName 'Server01' -NewSize 4096
Will configure a maximum size of 4GB for the SCCM client cache on 'Server01'

.EXAMPLE
Set-CMClientCache -ComputerName 'Server01' -NewSize 8192 -Credential (Get-Credential)
Will configure a maximum size of 8GB for the SCCM client cache on 'Server01, credentials for the operation will be obtained during execution
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [Alias('Computer')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    $NewLocation = $null,

    [Parameter(Mandatory=$False,Position=2)]
    [ValidateScript({($_ -ge 1024 -and $_ -le 8192) -or $_ -eq 0})]
    $NewSize = 0,

    [Parameter(Mandatory=$False,Position=3)]
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
    Try {
        
        # WIN32 ComputerSystem object for output
        $cs = Get-WmiObject Win32_ComputerSystem

        # Get current SCCM client cache config
        $Cache = Get-WmiObject -Namespace root\ccm\SoftMgmtAgent -Class CacheConfig -ErrorAction Stop
        
        # Set new SCCM client cache location
        If ($null -ne $using:NewLocation) {
            Write-Host "MESSAGE: '$($cs.Name).$($cs.Domain)' moving SCCM client cache to $($Cache.Location)" -ForegroundColor Gray
            $Cache.Location = "$(($using:NewLocation).TrimEnd('\ccmcache'))\ccmcache"
        }

        # Set new SCCM client cache size
        If ($using:NewSize -ne 0) {
            Write-Host "MESSAGE: '$($cs.Name).$($cs.Domain)' setting SCCM client cache size to $($Cache.Size)" -ForegroundColor Gray
            $Cache.Size = "$($using:NewSize)"
        }

        # Set SCCM client cache config
        $Cache.Put() | Out-Null

        # Restart SCCM client service
        Try {
            Restart-Service -Name CcmExec -Force -Confirm:$False -ErrorAction Stop
        }
        Catch {
            Write-Warning "'$($cs.Name).$($cs.Domain)' unable to restart 'CcmExec' service. Service must be restarted for changes to be effective."
        }
    }
    Catch {
        Write-Host "FAILURE: '$($cs.Name).$($cs.Domain)' SCCM cache configuration does not exist!" -ForegroundColor Red
    }
}

}