<#
.SYNOPSIS
Detects low (less than 20%) disk space on system drive.

.DESCRIPTION
Detects low (less than 20%) disk space on system drive.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.06.24 by DS :: First version for GitHub.
Call From:
    Windows PowerShell v5.1 invoked as Intune detection script.

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
.\Detect-LowDiskSpace.ps1
Exits script with either 1 (low disk space) or 0 (acceptable disk space)
#>

[CmdletBinding()]
param ()

# exit code
$script:e = 0

# subfunctions
function Volume_Stats {
    $v = $null
    $v = Get-Volume -DriveLetter $env:SystemDrive.Replace(':', '')
    
    $s = $null
    $s = [math]::Round($v.Size / 1GB, 2)
    
    $f = $null
    $f = [math]::Round($v.SizeRemaining / 1GB, 2)

    $p = $null
    $p = $([math]::Round($f / $s * 100, 2))

    $res = "" | Select-Object SizeGB, FreeGB, PercentFree
    $res.SizeGB = $s
    $res.FreeGB = $f
    $res.PercentFree = $p

    return $res
}

$v = $null
$v = Volume_Stats
if ($v.PercentFree -le 20) {
    $script:e = 1
}

exit $script:e