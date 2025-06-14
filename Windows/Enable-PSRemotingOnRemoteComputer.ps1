Function Enable-PSRemotingOnRemoteComputer {
<#
.SYNOPSIS
Attempts to enable PS remoting on specified remote computer(s).

.DESCRIPTION
Attempts to enable PS remoting on specified remote computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2023.06.26 by DS :: First revision.
    V02: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' and added '[Alias('Identity')]' for $ComputerName parameter.
    V03: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
    V05: 2025.05.29 by DS :: Updated function name and documentaiton to match.
    V06: 2025.06.03 by DS :: Reverted function name... already a thing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The name of remote computer(s) on which to enable PS remoting.

.PARAMETER Credential
Optional parameter to specify alternate credentials for enabling PS remoting on specified computer(s).

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Enable-PSRemotingOnRemoteComputer -ComputerName 'fileserver01'
Will attempt to enable PS remoting on 'fileserver01'.

.EXAMPLE
Enable-PSRemotingOnRemoteComputer -ComputerName 'fileserver01' -Credential (Get-Credential)
Will prompt for credentials, then use the credentials in an attempt to enable PS remoting on 'fileserver01'.

.EXAMPLE
Enable-PSRemotingOnRemoteComputer -ComputerName 'fileserver01','fileserver02'
Will attempt to enable PS remoting on 'fileserver01' and 'fileserver02'.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$False)]
    [pscredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$NoProgress = $false
)

$i = 0
foreach ($cn in $ComputerName) {
    If (!$NoProgress) {
        $i++
        Write-Progress "Enabling PS remoting for '$cn'" -PercentComplete ($i / $ComputerName.Count * 100)
    }

    # CIM session options
    $SessionArgs = @{
        ComputerName  = $cn
        Credential    = $Credential
        SessionOption = New-CimSessionOption -Protocol Dcom
    }

    # Arguements for 'Invoke-CimMethod' cmdlet below
    $MethodArgs = @{
        ClassName     = 'Win32_Process'
        MethodName    = 'Create'
        CimSession    = New-CimSession @SessionArgs -ErrorAction SilentlyContinue -OperationTimeoutSec 3
        Arguments     = @{
            CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"
        }
    }

    # Attempt to invoke CIM method
    Try {
        Invoke-CimMethod @MethodArgs -ErrorAction Stop | Out-Null
        Write-Verbose "Enabled PS remoting on '$($cn)'"
        Remove-CimSession -ComputerName $cn
    }
    Catch {
        Write-Host "FAILURE: Unable to create CIM session to '$($cn)'" -ForegroundColor Red
    }
}

}