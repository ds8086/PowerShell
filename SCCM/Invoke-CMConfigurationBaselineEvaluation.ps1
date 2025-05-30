Function Invoke-CMConfigurationBaselineEvaluation {
<#
.SYNOPSIS
Invoke evaluation of SCCM configuration baseline(s).

.DESCRIPTION
Invoke evaluation of SCCM configuration baseline(s) on a specified computer.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2023.02.08 by DS :: First revision
    V02: 2023.04.18 by DS :: Dropped attempt to get WMI object first (over the network). Updated 'Invoke-Command' to use splat table.
    V03: 2023.04.21 by DS :: Made $ComputerName a variable type of multi-valued string, dropped Try...Catch from 'Invoke-Command' (not needed)
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
Name of the computer on which to evaluate SCCM configuration baseline(s). The default value is the local computer.

.PARAMETER ConfigurationBaseline
Name of the SCCM configuration baseline(s) to evaluate. Parameter accepts wildcards. Default value is '*' (all applicable configuration baselines).

.PARAMETER Credential
Credentials used in querying and triggering evaluation of SCCM configuration baseline(s) on the specified computer.

.EXAMPLE
Invoke-CMConfigurationBaselineEvaluation -ComputerName fileserver01.contoso.com
Will trigger an evaluation of all applicable SCCM configuration baselines on the computer 'fileserver01.contoso.com'

.EXAMPLE
Invoke-CMConfigurationBaselineEvaluation -ComputerName fileserver01.contoso.com -ConfigurationBaseline "Disable TLS 1.0"
Will trigger an evaluation of SCCM configuration baseline 'Disable TLS 1.0' on the computer 'fileserver01.contoso.com'

.EXAMPLE
Invoke-CMConfigurationBaselineEvaluation -ComputerName fileserver01.contoso.com -ConfigurationBaseline "Disable TLS 1.0" -Credential (Get-Credential)
Will trigger an evaluation of SCCM configuration baseline 'Disable TLS 1.0' on the computer 'fileserver01.contoso.com' using credentials capture during command execution.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [Alias('Computer')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$False,Position=1)]
    [Alias('Baseline')]
    [string]$ConfigurationBaseline = "*",

    [Parameter(Mandatory=$False,Position=2)]
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

    # SCCM configuration baseline(s)
    Try {
        $Baselines = Get-WmiObject -Namespace root\ccm\dcm -Class SMS_DesiredConfiguration -ErrorAction Stop | Where-Object {$_.DisplayName -like "$using:ConfigurationBaseline"}
    }
    Catch {
        Write-Host "FAILURE: '$($cs.Name).$($cs.Domain)' does not appear to have the SCCM client installed!" -ForegroundColor Red
    }

    # Trigger evaluation of SCCM configuration baseline(s)
    If ($Baselines) {
        foreach ($b in $Baselines) {
            Write-Host "MESSAGE: '$($cs.Name).$($cs.Domain)' evaluating configuration baseline '$($b.DisplayName)'" -ForegroundColor Gray
            ([wmiclass]"\\.\root\ccm\dcm:SMS_DesiredConfiguration").TriggerEvaluation($b.Name, $b.Version) | Out-Null
        }
    }

    # No configuration baseline(s) exist or match the specified name
    Else {
        Write-Warning "'$($cs.Name).$($cs.Domain)' no configuration baselines match specified name '$using:ConfigurationBaseline'"
    }
}

}