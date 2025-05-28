Function Set-VMWareToolsPolicy {
<#
.SYNOPSIS
Sets VMWare Tools upgrade policy for specified VM(s).

.DESCRIPTION
Set VMWare Tools upgrade policy for specified VM(s) to either 'manual' or 'auto'.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2017.05.22 by DS :: Proof of concept.
    V01: 2025.05.28 by DS :: Updated for GitHub. Standalone ESXi complains about licensing so I cannot test this, but it *should* work. AOL Keyword: Should.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
The name of the VIServer for which VMWare tools upgrade policy information will be set. The default value is $global:DefaultVIServers.

.PARAMETER Name
The name of VMs for which to set VMWare tools upgrade policy. Accepts wildcard (*).

.PARAMETER Policy
The VMWare tools upgrade policy to set on VM(s). Valid values are 'manual' and 'upgradeAtPowerCycle'.

.EXAMPLE
Set-ToolsUpgradePolicy -Name "webserver*" -Policy upgradeAtPowerCycle
Will set VMware Tools upgrade policy for each VM with a name like "webserver*" to 'upgradeAtPowerCycle'. A confirmation prompt will occur for each VM.

.EXAMPLE
Set-ToolsUpgradePolicy -Name "webserver*" -Policy upgradeAtPowerCycle -Confirm:$False
Will set VMware Tools upgrade policy for each VM with a name like "webserver*" to 'upgradeAtPowerCycle'. No confirmation prompts will occur.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [AllowNull()]
    [string[]]$Server = $global:DefaultVIServers.Name,

    [Parameter(Mandatory=$True,Position=1)]
    [string]$Name,

    [Parameter(Mandatory=$True,Position=2)]
    [Validateset("manual", "upgradeAtPowerCycle")]
    [string]$Policy,

    [Parameter(Mandatory=$False,Position=3)]
    [bool]$Confirm = $true
)

# Define and import required modules
$RequiredModules = "VMware.VimAutomation.Core"
foreach ($rm in $RequiredModules) {
    Try {
        If (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    Catch {
        Write-Host "FAILURE: Required module '$rm' could not be imported!" -ForegroundColor Red
        Break
    }
}

# Not connected to *any* VIServer(s)
If (!($global:DefaultVIServers)) {
    Write-Warning "Not connected to VIServer(s)"
    If ($Server) {
        Connect-VIServer -Server $Server | Out-Null
    }
    Else {
        Connect-VIServer | Out-Null
    }
    [string[]]$Server = $global:DefaultVIServers.Name
}

# VM config spec
$vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
$vmConfigSpec.Tools = New-Object VMware.Vim.ToolsConfigInfo
$vmConfigSpec.Tools.ToolsUpgradePolicy = $Policy

foreach ($s in $Server) {
    Try {
        $VMs = Get-VM -Server $s -Name $Name
    }
    Catch {
        $Error[0].Exception
    }
    $VMs | ForEach-Object {
        If ($Confirm) {
            $prompt = $null
            Do {
                $prompt = Read-Host -Prompt "Update VMWare tools upgrade policy for '$($_.Name)' to '$Policy'? (Y/n)"
            }
            Until ($prompt.ToLower() -in 'y','n')
            
            If ($prompt -eq 'y') {
                $view = Get-View -Id $_.Id
                $view.ReconfigVM_Task($vmConfigSpec)
            }
            Else {
                Write-Verbose "VMWare tools upgrade policy for '$($_.Name)' unchanged"
            }
        }
        Else {
            $view = Get-View -Id $_.Id
            $view.ReconfigVM_Task($vmConfigSpec)
        }
    }
}

}