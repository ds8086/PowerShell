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
    Revision 03
Revision:
    V01: 2017.05.22 by DS :: Proof of concept.
    V02: 2018.10.03 by DS :: Removed unnecessary error trapping.
    V03: 2025.05.28 by DS :: Minor overhaul for GitHub. Glad the world never saw earlier versions... That's a sign of professional progress though, right? Looking at a script from nearly 7 years ago and saying, "What is this trash?!".
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
The name of the VIServer for which VMWare tools upgrade policy information will be retrieved. The default value is $global:DefaultVIServers.

.PARAMETER Name
The name of VMs for which to retrieve VMWare tools upgrade policy. Accepts wildcard (*). The default value is * (all).

.EXAMPLE
Get-ToolsUpgradePolicy -Name "webserver*"
Will return the VMware Tools upgrade policy for each VM with a name like "webserver*".
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

foreach ($s in $Server) {
    Try {
        $VMs = Get-VM -Server $s -Name $Name
        $VMs | Select-Object `
            @{N="Server";E={$s}},`
            Name,`
            PowerState,`
            @{Name="ToolsUpgradePolicy";Expression={$_.Extensiondata.Config.Tools.toolsUpgradePolicy}}
    }
    Catch {
        $Error[0].Exception
    }
}

}