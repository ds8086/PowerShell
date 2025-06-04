
Function Get-VMHostCpuRatio {
<#
.SYNOPSIS
Calculates the virtual CPU to physical CPU ratio for VM hosts.

.DESCRIPTION
Calculates the virtual CPU to physical CPU ratio for VM hosts. Optionally limits results to only include vCPU for powered on VMs.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2021.08.18 by DS :: First revision.
    V02: 2025.05.28 by DS :: Cleaned up for GitHub.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
The name of the VIServer for which CPU ratio information will be calculated. The default value is $global:DefaultVIServers.

.PARAMETER PoweredOn
Switched parameter which, when specified, includes vCPU for powered on VMs.

.EXAMPLE
Get-VMHostCpuRatio -Server vsphere.contoso.com
Will calculate virtual to physical CPU ratio for all VM hosts known to the server 'vsphere.contoso.com'.

.EXAMPLE
Get-VMHostCpuRatio -Server vsphere.contoso.com -PoweredOn
Will calculate virtual to physical CPU ratio for all VM hosts known to the server 'vsphere.contoso.com'. Only powered on VMs will be used in calculating CPU ratios.
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

$i = 0
foreach ($s in $Server) {
    $i++
    Try {
        Write-Progress "Processing $($s.Name)" -PercentComplete ($i / $Server.Count * 100) -Id 1
    } Catch {}

    # VMs and hosts
    $s_vms = Get-VM -Server $s
    $s_hst = Get-VMHost -Server $s | Where-Object {$_.ConnectionState -eq "Connected"}
    
    $ii = 0
    foreach ($h in $s_hst) {
        $ii++
        Try {
            Write-Progress "Determining pCPU to vCPU ratio for $($h.Name)" -PercentComplete ($ii / $s_hst.Count * 100) -ParentId 1
        } Catch {}
        
        # Filter VMs to host and PoweredOn (if specified)
        switch ($PoweredOn) {
            $True { $h_vms = $s_vms | Where-Object {$_.VMHost.Name -eq $h.Name -and $_.PowerState -eq "PoweredOn"} }
            Default { $h_vms = $s_vms | Where-Object {$_.VMHost.Name -eq $h.Name} }
        }
        
        # vCPU count
        $vCpu = 0
        $h_vms | ForEach-Object { $vCpu += $_.NumCpu }
        
        # Output
        $h | Select-Object `
            @{N="Server";E={$s}},`
            @{N="VMHost";E={$_.Name}},`
            NumCpu,`
            @{N="VMs";E={$h_vms.Count}},`
            @{N="vCpu";E={$vCpu}},`
            @{N="vCpuRatio";E={ "$([math]::Round($vCpu / $h.NumCpu, 2)) : 1" }}
    }
}

}