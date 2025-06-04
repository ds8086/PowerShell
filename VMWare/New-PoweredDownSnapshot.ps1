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
    Revision 02
Revision:
    V01: 2022.03.23 by DS :: First published revision.
    V02: 2025.05.29 by DS :: Cleaned up for GitHub. Standalone ESXi complains about licensing so I cannot test this, but it *should* work. AOL Keyword: Should.
Call From:
    PowerShell v5.1+ w/ VMware.VimAutomation.Core module 13.3.0+

.PARAMETER Server
The name of the VIServer for which VMWare tools upgrade policy information will be retrieved. The default value is $global:DefaultVIServers.

.PARAMETER VM
The VM which will be powered down and have a snapshot created. Accepts wildcard (*).

.PARAMETER SnapshotName
Optional parameter to specify the snapshot name. If unspecified, snapshot name is ISO8601 datestamp.

.PARAMETER SnapshotDescription
Option parameter to specify the snapshot description. If unspecified, snapshot description is 'Created via 'New-PoweredDownSnapshot' cmdlet'.

.PARAMETER Confirm
Boolean parameter to display confirmation before shutting down VM guest.

.EXAMPLE
New-PoweredDownShapshot -VM FileServer01
Will gracefully power down the VM guest of 'FileServer01', take a snapshot, then power up the VM.

.EXAMPLE
New-PoweredDownShapshot -VM FileServer* -SnapshotName 'Snapshot' -SnapshotDescription 'Before patch installation'
Will gracefully power down the guest OSes of VMs with name like 'FileServer*', take a snapshot of each VM, then power up the VMs. Snapshot name and description will reflect the parameter values.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$VM,    
    
    [Parameter(Mandatory=$False,Position=1)]
    [string]$Name = "$(Get-Date -Format yyy.MM.dd-HHmm)",

    [Parameter(Mandatory=$False,Position=2)]
    [string]$Description = "Created via 'New-PoweredDownSnapshot' cmdlet",

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
        $s_vms = Get-VM -Server $s -Name $VM
        If ($s_vms) {

            # Shutdown guest OS(es)
            switch ($Confirm) {
                $True { $s_vms | Shutdown-VMGuest -Confirm:$true }
                default { $s_vms | Shutdown-VMGuest -Confirm:$false }
            }

            # Wait for guest OS(es) to shutdown
            Write-Verbose "Waiting for VM(s) guest OS(es) to gracefully shutdown"
            $i = 0
            Do {
                Start-Sleep -Seconds 10
                $power = $null
                $power = (Get-VM -Server $s -Name $VM).PowerState | Select-Object -Unique
                $i += 10
                Write-Host "Waited $i seconds (max wait: $WaitTime)"
            }
            Until ( ($power.Count -eq 1 -and $power -eq 'PoweredOff') -or $i -ge $WaitTime)
            
            # Take snapshots if all VMs are shutdown
            If ($s_vms.PowerState -eq 'PoweredOff') {
                $s_vms | New-Snapshot -Name $Name -Description $Description
                $s_vms | Start-VM
            }

            # Output state of VMs and stop execution
            Else {
                Write-Warning "One or more VM guest OSes did not gracefully shutdown within timeout of $WaitTime seconds"
                $s_vms = Get-VM -Server $s -Name $VM
                $s_vms
                throw "No snapshots taken, exiting!"
                break
            }
        }
        Else {
            Write-Warning "No VMs match name '$VM' on server '$s'"
        }
    }
    Catch {
        $Error[0].Exception
    }
}

}