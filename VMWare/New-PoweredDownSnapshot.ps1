Function New-PoweredDownSnapshot {
<#
.SYNOPSIS
Creates a new powered down snapshot of the specified VM(s).

.DESCRIPTION
Gracefully power down guest OS of specified VM, takes snapshot, then start the VM(s).

.NOTES
Author:
    DS
Notes:
    Revision 03
Revision:
    V01: 2022.03.23 by DS :: First published revision.
    V02: 2025.05.29 by DS :: Cleaned up for GitHub.
    V03: 2025.12.22 by DS :: Line lengths. Statement capitalization. Minor change to required modules.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
VIServer for performing the powered down snapshot operation. The default value is $global:DefaultVIServers.

.PARAMETER VM
VM which will be powered down and have a snapshot created. Accepts wildcard (*).

.PARAMETER SnapshotName
Snapshot name. Default value is ISO8601 datestamp (yyyy.MM.dd-HHmm).

.PARAMETER SnapshotDescription
Specify the snapshot description. Default value is "Created via 'New-PoweredDownSnapshot' cmdlet".

.PARAMETER WaitTime
Maximum time to wait for graceful OS shutdown. Default value is 300 seconds.

.PARAMETER Confirm
Boolean parameter to display confirmation before shutting down VM guest.

.EXAMPLE
New-PoweredDownShapshot -VM FileServer01
Gracefully powers down the VM guest of 'FileServer01', takes a snapshot, and powers up the VM.

.EXAMPLE
New-PoweredDownShapshot -VM FileServer* -SnapshotName 'Snapshot' -SnapshotDescription 'Before patch installation'
Gracefully powers down the guest OSes of VMs with name like 'FileServer*'.
Takes a snapshot of each VM named 'Snapshot' with a snapshot description of 'Before patch installation'.
Powers up VMs following snapshot creation.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$VM,    
    
    [Parameter(Mandatory=$False,Position=1)]
    [string]$SnapshotName = "$(Get-Date -Format yyy.MM.dd-HHmm)",

    [Parameter(Mandatory=$False,Position=2)]
    [string]$SnapshotDescription = "Created via 'New-PoweredDownSnapshot' cmdlet",

    [Parameter(Mandatory=$False,Position=3)]
    [AllowNull()]
    [string[]]$Server = $global:DefaultVIServers.Name,

    [Parameter(Mandatory=$False,Position=4)]
    [int]$WaitTime = 300,

    [Parameter(Mandatory=$False)]
    [bool]$Confirm = $True
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
        $s_vms = Get-VM -Server $s -Name $VM
        if ($s_vms) {

            # Shutdown guest OS(es)
            switch ($Confirm) {
                $True { $s_vms | Shutdown-VMGuest -Confirm:$true }
                Default { $s_vms | Shutdown-VMGuest -Confirm:$false }
            }

            # Wait for guest OS(es) to shutdown
            Write-Verbose "Waiting for VM(s) guest OS(es) to gracefully shutdown"
            $i = 0
            do {
                Start-Sleep -Seconds 10
                $power = $null
                $power = (Get-VM -Server $s -Name $VM).PowerState | Select-Object -Unique
                $i += 10
                Write-Host "Waited $i seconds (max wait: $WaitTime)"
            }
            until ( ($power.Count -eq 1 -and $power -eq 'PoweredOff') -or $i -ge $WaitTime)
            
            # Take snapshots if all VMs are shutdown
            if ($s_vms.PowerState -eq 'PoweredOff') {
                $s_vms | New-Snapshot -Name $SnapshotName -Description $SnapshotDescription
                $s_vms | Start-VM
            }

            # Output state of VMs and stop execution
            else {
                Write-Warning "VM guest OS(es) did not gracefully shutdown within timeout of $WaitTime seconds"
                $s_vms = Get-VM -Server $s -Name $VM
                $s_vms
                throw "No snapshots taken, exiting!"
                break
            }
        }
        else {
            Write-Warning "No VMs match name '$VM' on server '$s'"
        }
    }
    catch {
        throw
    }
}

}