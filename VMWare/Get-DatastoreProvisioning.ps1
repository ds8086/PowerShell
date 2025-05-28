Function Get-DatastoreProvisioning {
<#
.SYNOPSIS
Retrieves datastore capacity and provisioning from vSphere/ESXi.

.DESCRIPTION
Retrieves datastore capacity and provisioning from vSphere/ESXi. Optionally outputs provisioning information for VMs on each datastore.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2023.01.18 by DS :: First revision.
    V02: 2025.05.22 by DS :: Cleaned up for GitHub.
    V03: 2025.05.28 by DS :: Added output for VM provisioning on each datastore.
    V04: 2025.05.28 by DS & JS :: Updated output with 'DatastoreBrowserPath'.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+
    
.PARAMETER DatastoreName
The name of the datastore for which capacity information will be retrieved. The default value is all datastores.

.PARAMETER IncludeVMs
Switched parameter which, when specified, includes VM provisioning information for each datastore.

.EXAMPLE
Get-DatastoreProvisioning -DatastoreName 'Datastore1'
Will retrieve datastore capacity information for 'Datastore1' including the amount of space provisioned to VMs on the datastore.

.EXAMPLE
Get-DatastoreProvisioning -DatastoreName 'Datastore1' -IncludeVMs
Will retrieve datastore capacity information for 'Datastore1' including the amount of space provisioned to VMs on the datastore. Provisioning information for each VM stored on 'Datastore1' will also be output.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$DatastoreName = "*",
    
    [Parameter(Mandatory=$False)]
    [switch]$IncludeVMs = $False
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

# Connect to vSphere server if not already
If (!($global:DefaultVIServer)) {
    Write-Warning "Not connected to vSphere Server(s). Specify vSphere server."
    Connect-VIServer | Out-Null
}

# Datastores
$Datastores = Get-Datastore $DatastoreName

# 'Main' foreach loop against datastores
$i = 0
foreach ($ds in $Datastores) {
    $i++
    Write-Progress "Processing $($ds.Name)" -PercentComplete ($i / $Datastores.Count * 100)

    $vm = $null
    $vm = $ds | Get-VM
    If ($vm) {
        $ps = 0
        $vm | ForEach-Object {
            $ps += $_.ProvisionedSpaceGB
        }
    }
    Else {
        Write-Warning "No VMs provisioned on datastore '$ds'"
        $ps = 0
    }
    $ds | Select-Object `
        @{N="Object";E={[string]::New('Datastore')}},`
        Name,`
        @{N="DatastoreBrowserPath";E={$_.DatastoreBrowserPath.Replace('vmstores:\','')}},`
        @{N="CapacityGB";E={[math]::Round($_.CapacityGB, 2)}},`
        @{N="ProvisionedGB";E={[math]::Round($ps, 2)}},`
        @{N="PercentProvisioned";E={[math]::Round($ps / $_.CapacityGB * 100, 2)}}
    
    If ($IncludeVMs) {
        $vm | Select-Object `
            @{N="Object";E={[string]::New('VM')}},`
            Name,`
            @{N="DatastoreBrowserPath";E={ "$($ds.DatastoreBrowserPath.Replace('vmstores:\',''))\$($_.Name)" }},`
            @{N="ProvisionedGB";E={[math]::Round($_.ProvisionedSpaceGB, 2)}},`
            @{N="PercentProvisioned";E={[math]::Round($_.ProvisionedSpaceGB / $ds.CapacityGB * 100, 2)}} | Sort-Object PercentProvisioned -Descending
    }
}

}