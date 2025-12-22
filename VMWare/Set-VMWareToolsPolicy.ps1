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
    Revision 03
Revision:
    V01: 2017.05.22 by DS :: Proof of concept.
    V01: 2025.05.28 by DS :: Updated for GitHub.
    V03: 2025.12.22 by DS :: Line lengths. Statement capitalization. Minor change to required modules.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
VIServer for which VMWare tools upgrade policy information will be set. The default value is $global:DefaultVIServers.

.PARAMETER Name
VM name(s) for which to set VMWare tools upgrade policy. Accepts wildcard (*).

.PARAMETER Policy
VMWare tools upgrade policy to set on VM(s). Valid values are 'manual' and 'upgradeAtPowerCycle'.

.EXAMPLE
Set-ToolsUpgradePolicy -Name "webserver*" -Policy upgradeAtPowerCycle
Sets VMware Tools upgrade policy for VMs with a name like "webserver*" to 'upgradeAtPowerCycle'.

.EXAMPLE
Set-ToolsUpgradePolicy -Name "webserver*" -Policy upgradeAtPowerCycle -Confirm:$False
Sets VMware Tools upgrade policy for VMs with a name like "webserver*" to 'upgradeAtPowerCycle' without confirmation.
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
    try {
        if (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    catch {
        throw
    }
}

# Not connected to *any* VIServer(s)
if (!($global:DefaultVIServers)) {
    Write-Warning "Not connected to VIServer(s)"
    if ($Server) {
        Connect-VIServer -Server $Server | Out-Null
    }
    else {
        Connect-VIServer | Out-Null
    }
    [string[]]$Server = $global:DefaultVIServers.Name
}

# VM config spec
$vmConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
$vmConfigSpec.Tools = New-Object VMware.Vim.ToolsConfigInfo
$vmConfigSpec.Tools.ToolsUpgradePolicy = $Policy

foreach ($s in $Server) {
    try {
        $VMs = Get-VM -Server $s -Name $Name
    }
    catch {
        $Error[0].Exception
    }
    $VMs | ForEach-Object {
        if ($Confirm) {
            $prompt = $null
            do {
                $prompt = Read-Host -Prompt "Update VMWare tools upgrade policy for '$($_.Name)' to '$Policy'? (Y/n)"
            }
            until (
                $prompt.ToLower() -in 'y','n'
            )
            
            if ($prompt -eq 'y') {
                $view = Get-View -Id $_.Id
                $view.ReconfigVM_Task($vmConfigSpec)
            }
            else {
                Write-Verbose "VMWare tools upgrade policy for '$($_.Name)' unchanged"
            }
        }
        else {
            $view = Get-View -Id $_.Id
            $view.ReconfigVM_Task($vmConfigSpec)
        }
    }
}

}