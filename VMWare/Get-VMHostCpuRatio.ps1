
Function Get-VMHostCpuRatio {
<#
.SYNOPSIS
Calculates the virtual CPU to physical CPU ratio for VM hosts.

.DESCRIPTION
Calculates the virtual CPU to physical CPU ratio for VM hosts.

.NOTES
Author:
    DS
Notes:
    Revision 03
Revision:
    V01: 2021.08.18 by DS :: First revision.
    V02: 2025.05.28 by DS :: Cleaned up for GitHub.
    V03: 2025.12.22 by DS :: Line lengths. Backticks. Statement capitalization. Minor change to required modules.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
VIServer for which CPU ratio information will be calculated. The default value is $global:DefaultVIServers.

.PARAMETER PoweredOn
Return vCPU for only powered on VMs.

.EXAMPLE
Get-VMHostCpuRatio -Server vsphere.contoso.com
Calculates virtual to physical CPU ratio for all VM hosts known to the server 'vsphere.contoso.com'.

.EXAMPLE
Get-VMHostCpuRatio -Server vsphere.contoso.com -PoweredOn
Calculates virtual to physical CPU ratio for powered on VMs on all VM hosts known to the server 'vsphere.contoso.com'.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [AllowNull()]
    [string[]]$Server = $global:DefaultVIServers.Name,

    [Parameter(Mandatory=$False)]
    [switch]$PoweredOn = $false
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

$i = 0
foreach ($s in $Server) {
    $i++
    try {
        Write-Progress "Processing $($s.Name)" -PercentComplete ($i / $Server.Count * 100) -Id 1
    }
    catch {}

    # VMs and hosts
    $s_vms = Get-VM -Server $s
    $s_hst = Get-VMHost -Server $s | Where-Object {$_.ConnectionState -eq "Connected"}
    
    $ii = 0
    foreach ($h in $s_hst) {
        $ii++
        try {
            $a = "Determining pCPU to vCPU ratio for $($h.Name)"
            Write-Progress $a -PercentComplete ($ii / $s_hst.Count * 100) -ParentId 1
        }
        catch {}
        
        # Filter VMs to host and PoweredOn (if specified)
        switch ($PoweredOn) {
            $True { $h_vms = $s_vms | Where-Object {$_.VMHost.Name -eq $h.Name -and $_.PowerState -eq "PoweredOn"} }
            Default { $h_vms = $s_vms | Where-Object {$_.VMHost.Name -eq $h.Name} }
        }
        
        # vCPU count
        $vCpu = 0
        $h_vms | ForEach-Object { $vCpu += $_.NumCpu }
        
        # Output
        $h | Select-Object @{N="Server";E={$s}},
            @{N="VMHost";E={$_.Name}},
            NumCpu,
            @{N="VMs";E={$h_vms.Count}},
            @{N="vCpu";E={$vCpu}},
            @{N="vCpuRatio";E={ "$([math]::Round($vCpu / $h.NumCpu, 2)) : 1" }}
    }
}

}