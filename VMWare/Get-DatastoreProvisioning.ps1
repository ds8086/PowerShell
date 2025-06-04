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
    Revision 05
Revision:
    V01: 2023.01.18 by DS :: First revision.
    V02: 2025.05.22 by DS :: Cleaned up for GitHub.
    V03: 2025.05.28 by DS :: Added output for VM provisioning on each datastore.
    V04: 2025.05.28 by DS & JS :: Updated output with 'DatastoreBrowserPath'.
    V05: 2025.05.28 by DS :: Error handling for 'Server' and 'DatastoreName' parameters.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
The name of the VIServer for which datastore capacity information will be retrieved. The default value is $global:DefaultVIServers.

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
    [AllowNull()]
    [string[]]$Server = $global:DefaultVIServers.Name,

    [Parameter(Mandatory=$False,Position=1)]
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

# Datastores
Try {
    $Datastores = Get-Datastore $DatastoreName -Server $Server -ErrorAction Stop
}
Catch [VMware.VimAutomation.Sdk.Types.V1.ErrorHandling.VimException.VimException] {
    
    # Not connected to specified VIServer
    If ($Error[0].Exception -like "*Could not find VIServer with name *") {
        Write-Warning "Not connected to vSphere/ESXi server '$Server'"
        Connect-VIServer $Server | Out-Null
    }

    # Specified datastore not found (just use wildcard)
    ElseIf ($Error[0].Exception -like "*Datastore with name * was not found*") {
        Write-Warning "Datastore '$DatastoreName' was not found. Returning all datastores instead."
        [string]$DatastoreName = "*"
    }
    $Datastores = Get-Datastore $DatastoreName -Server $Server
}

# 'Main' foreach loop against datastores
$i = 0
foreach ($ds in $Datastores) {
    $i++
    Write-Progress "Processing $($ds.Name)" -PercentComplete ($i / $Datastores.Count * 100)

    # VMs on datastore
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

    # Return only datastore information
    $ds | Select-Object `
        @{N="Object";E={[string]::New('Datastore')}},`
        Name,`
        @{N="DatastoreBrowserPath";E={$_.DatastoreBrowserPath.Replace('vmstores:\','')}},`
        @{N="CapacityGB";E={[math]::Round($_.CapacityGB, 2)}},`
        @{N="ProvisionedGB";E={[math]::Round($ps, 2)}},`
        @{N="PercentProvisioned";E={[math]::Round($ps / $_.CapacityGB * 100, 2)}}
    
    # Return VM information as well
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