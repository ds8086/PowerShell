Function Get-VMWareToolsPolicy {
<#
.SYNOPSIS
Retrieves VMWare Tools upgrade policy for specified VMs.

.DESCRIPTION
Retrieves VMWare Tools upgrade policy for specified VMs.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2017.05.22 by DS :: Proof of concept.
    V02: 2018.10.03 by DS :: Removed unnecessary error trapping.
    V03: 2025.05.28 by DS :: Minor overhaul for GitHub.
    V04: 2025.12.22 by DS :: Line lengths. Backticks. Statement capitalization. Minor change to required modules.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
VIServer for which VMWare tools upgrade policy info will be retrieved. The default value is $global:DefaultVIServers.

.PARAMETER Name
Name VM(s) for which to retrieve VMWare tools upgrade policy. Accepts wildcard (*). The default value is * (all).

.EXAMPLE
Get-ToolsUpgradePolicy -Name "webserver*"
Retrieves the VMware Tools upgrade policy for each VM with a name like "webserver*".
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [AllowNull()]
    [string[]]$Server = $global:DefaultVIServers.Name,

    [Parameter(Mandatory=$False,Position=1)]
    [string]$Name = "*"
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

foreach ($s in $Server) {
    try {
        $VMs = Get-VM -Server $s -Name $Name
        $VMs | Select-Object @{N="Server";E={$s}},
            Name,
            PowerState,
            @{N="ToolsUpgradePolicy";E={$_.Extensiondata.Config.Tools.toolsUpgradePolicy}}
    }
    catch {
        throw
    }
}

}