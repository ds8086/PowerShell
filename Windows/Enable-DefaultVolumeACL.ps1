Function Enable-DefaultVolumeACL {
<#
.SYNOPSIS
Creates 'Default' volume ACL entries.

.DESCRIPTION
Retrieves volumes not mounted as drive letter C: adds access control list entries (ACEs) for that of a new volume.

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2022.10.05 by DS :: First revision.
    V02: 2022.01.18 by DS :: Added script header. Added check for 'BUILTIN\Users' ACL entry.
    V03: 2025.03.22 by DS :: Updated for GitHub. Removed check for 'BUILTIN\Users' ACL entry.
    V04: 2025.06.12 by DS :: Updated spacing in script header.
    V05: 2025.12.22 by DS :: Line lengths. Backticks. Statement capitalization.
Call From:
    PowerShell v5.1 or higher

.EXAMPLE
Enable-DefaultVolumeAcl
Retrieves volumes not mounted as drive letter C: adds access control list entries (ACEs) for that of a new volume.
#>

# Define and start logging
$Log = ".\ACL-Update.log"
Start-Transcript $Log -Force

# CSV (semicolon separated) of ACEs which make up the default ACL of a newly provisioned volume
$Header = @(
    'FileSystemRights',
    'AccessControlType',
    'IdentityReference',
    'IsInherited',
    'InheritanceFlags',
    'PropagationFlags'
)
$DefaultACL = ConvertFrom-Csv -Delimiter ";" -Header $Header -InputObject (
    "ReadAndExecute, Synchronize;Allow;Everyone;FALSE;None;None",
    "FullControl;Allow;CREATOR OWNER;FALSE;ContainerInherit, ObjectInherit;InheritOnly",
    "FullControl;Allow;NT AUTHORITY\SYSTEM;FALSE;ContainerInherit, ObjectInherit;None",
    "FullControl;Allow;BUILTIN\Administrators;FALSE;ContainerInherit, ObjectInherit;None",
    "AppendData;Allow;BUILTIN\Users;FALSE;ContainerInherit;None",
    "CreateFiles;Allow;BUILTIN\Users;FALSE;ContainerInherit;InheritOnly",
    "ReadAndExecute, Synchronize;Allow;BUILTIN\Users;FALSE;ContainerInherit, ObjectInherit;None"
)

# Store OS (used in filtering $Volumes)
$OS = Get-WmiObject -Class win32_operatingsystem

switch ($OS) {
    
    # Server 2012
    {$_.Version -like "6.*"} {
        $Volumes = Get-Volume | Where-Object {
            ($_.DriveLetter.ToString() -ne "") -and ($_.DriveLetter -ne "C") -and ($_.DriveType -ne "CD-ROM")
        }
    }
    
    # All other OSes
    Default {
        $Volumes = Get-Volume | Where-Object {
            ($null -ne $_.DriveLetter) -and ($_.DriveLetter -ne "C") -and ($_.DriveType -ne "CD-ROM")
        }
    }
}

# Foreach (volume) loop
foreach ($v in $Volumes) {
    
    # Determine current ACL of volume
    $acl = $null
    $acl = Get-Acl -Path "$($v.DriveLetter):\"

    # Output current ACL for drive
    Write-Host "MESSAGE: ACL for '$($v.DriveLetter):' as it exists now:" -ForegroundColor Gray
    ($acl).Access | Format-List

    # Build an ACE for each entry in $DefaultACL and add it to $ACL
    foreach ($da in $DefaultACL) {
        $ace = $null
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule (
            "$($da.IdentityReference)",
            "$($da.FileSystemRights)",
            "$($da.InheritanceFlags)",
            "$($da.PropagationFlags)",
            "$($da.AccessControlType)"
        )
        $acl.AddAccessRule($ace)
    }
    
    # Output future ACL for drive
    Write-Host "MESSAGE: ACL for '$($v.DriveLetter):' as it will exist once updated:" -ForegroundColor Gray
    ($acl).Access | Format-List

    # Set new ACL
    Write-Verbose "Updating ACL (this will take awhile depending on the amount of data on '$($v.DriveLetter):'"
    $acl | Set-Acl
}

# Stop logging
Stop-Transcript

}