<#
.SYNOPSIS
Attempts to remediate low (less than 20%) disk space on system drive.

.DESCRIPTION
Attempts to remediate low (less than 20%) disk space on system drive following detection of low disk space.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.06.24 by DS :: First version for GitHub.
Call From:
    Windows PowerShell v5.1 invoked as Intune remediation script.

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
.\Remediate-LowDiskSpace.ps1
Exits script with either 1 (error occurred) or 0 (no errors)
#>

[CmdletBinding()]
param ()

# working directory
$script:WorkDir = "$env:SystemDrive\Installer"
if (!(Test-Path $script:WorkDir)) {
    Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Creating '$script:WorkDir'"
    mkdir $script:WorkDir | Out-Null
}

# logging
$log = "$script:WorkDir\Logs\Reclaim-DiskSpace.Log"
if (Test-Path $log) {
    Remove-Item $log -Force -Confirm:$false -ErrorAction SilentlyContinue
}
Start-Transcript -Path $log -Append -Force

# exit code
$script:e = 0

# subfunctions
function Disable_Hibernation {
    try {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Disable hibernation"
        $param = $null
        $param = @{
            'FilePath'     = $null
            'ArgumentList' = "/hibernate off"
            'Wait'         = $true
            'NoNewWindow'  = $true
            'ErrorAction'  = 'Stop'
        }
        # Intune runs a 32-bit process, this switch accounts for file system redirection
        # https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
        switch (Test-Path -Path "$env:SystemRoot\sysnative\powercfg.exe") {
            $true {
                $param.FilePath = "$env:SystemRoot\sysnative\powercfg.exe"
            }
            Default {
                $param.FilePath = "$env:SystemRoot\System32\powercfg.exe"
            }
        }
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Run '$($param.FilePath) $($param.ArgumentList)'"
        Start-Process @param
        Start-Sleep -Seconds 30
    }
    catch {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
        $script:e = 1
    }
}
function Empty_Directories {

    $Directories = @(
        @{
            'path' = "$env:SystemDrive\Installer"
            'days' = 3
        }
    )

    foreach ($d in $Directories) {
        $param = $null
        $param = @{
            'Path'    = $d.path
            'Force'   = $true
            'Recurse' = $true
        }
        
        $delete = $null
        $delete = Get-ChildItem @param | Where-Object {
            $_.PsIsContainer -ne $True -and 
            $_.LastWriteTime -lt (Get-Date).AddDays(-$d.days)
        }

        if ($delete) {
            Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Delete files older than $($d.days)d from '$($d.path)'"
            $delete | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue
        }
        else {
            Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): No files older than $($d.days)d in '$($d.path)'"
        }
    }
}
function Remove_Apps {
    
    $apps = @(
        'Dell Command | Update for Windows 10',
        'Dell Command | Update for Windows 11',
        'Dell Digital Delivery Services',
        'Dell Power Manager Service',
        'Dell SupportAssist',
        'Dell SupportAssist OS Recovery Plugin for Dell Update',
        'Dell SupportAssist Remediation'
    )

    foreach ($a in $apps) {
        try {
            $wmi = $null
            $wmi = Get-WmiObject -Class win32_product -ErrorAction Stop | Where-Object { $_.Name -eq $a }
            if ($wmi) {
                try {
                    Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Begin '$a' uninstall"
                    $param = $null
                    $param = @{
                        'FilePath'     = $null
                        'ArgumentList' = "/x `"$($wmi.IdentifyingNumber)`" /quiet /norestart"
                        'Wait'         = $true
                        'NoNewWindow'  = $true
                        'ErrorAction'  = 'Stop'
                    }
                    # Intune runs a 32-bit process, this switch accounts for file system redirection
                    # https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
                    switch (Test-Path -Path "$env:SystemRoot\sysnative\msiexec.exe") {
                        $true {
                            $param.FilePath = "$env:SystemRoot\sysnative\msiexec.exe"
                        }
                        Default {
                            $param.FilePath = "$env:SystemRoot\System32\msiexec.exe"
                        }
                    }
                    Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Run '$($param.FilePath) $($param.ArgumentList)'"
                    Start-Process @param
                    Start-Sleep -Seconds 30

                    Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): End '$a' uninstall"
                }
                catch {
                    Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
                    $script:e = 1
                }
            }
            else {
                Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): App '$a' not present"
            }
        }
        catch {
            Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
            $script:e = 1
        }
    }
}
Function Remove_CamLogs {
    # https://learn.microsoft.com/en-us/answers/questions/5815087/capabilityaccessmanager-is-devouring-my-hard-drive
    $svc = $null
    $svc = 'camsvc'
    
    # stop service
    try {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Stopping service '$svc'"
        Stop-Service $svc -ErrorAction Stop
    }
    catch {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
        $script:e = 1
        return
    }

    # remove CAM database log files
    $param = $null
    $param = @{
        'Path'        = "C:\ProgramData\Microsoft\Windows\CapabilityAccessManager\*.db-wal"
        'Confirm'     = $false
        'Force'       = $true
        'ErrorAction' = 'Stop'
    }
    try {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Removing '$($param.Path)'"
        Remove-Item @param
    }
    catch {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
        $script:e = 1
    }

    # start service
    try {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Starting service '$svc'"
        Start-Service $svc -ErrorAction Stop
    }
    catch {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
        $script:e = 1
    }
}
function Run_Cleanmgr {
    
    # registry entries for cleanmgr
    $regPaths = @(
        '"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup"',
        '"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files"'
    )
    foreach ($rp in $regPaths) {
        $param = $null
        $param = @{
            'FilePath'     = $null
            'ArgumentList' = "ADD $rp /v StateFlags0001 /d 2 /t REG_DWORD /f"
            'Wait'         = $true
            'NoNewWindow'  = $true
            'ErrorAction'  = 'Stop'
        }
        # Intune runs a 32-bit process, this switch accounts for file system redirection
        # https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
        switch (Test-Path -Path "$env:SystemRoot\sysnative\reg.exe") {
            $true {
                $param.FilePath = "$env:SystemRoot\sysnative\reg.exe"
            }
            Default {
                $param.FilePath = "$env:SystemRoot\System32\reg.exe"
            }
        }
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Run '$($param.FilePath) $($param.ArgumentList)'"
        Start-Process @param
    }
    
    # run cleanmgr
    try {
        $param = $null
        $param = @{
            'FilePath'     = $null
            'ArgumentList' = "/sagerun:1"
            'Wait'         = $false
            'WindowStyle'  = 'Hidden'
            'ErrorAction'  = 'Stop'
        }
        # Intune runs a 32-bit process, this switch accounts for file system redirection
        # https://learn.microsoft.com/en-us/windows/win32/winprog64/file-system-redirector
        switch (Test-Path -Path "$env:SystemRoot\sysnative\cleanmgr.exe") {
            $true {
                $param.FilePath = "$env:SystemRoot\sysnative\cleanmgr.exe"
            }
            Default {
                $param.FilePath = "$env:SystemRoot\System32\cleanmgr.exe"
            }
        }
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): Start background '$($param.FilePath) $($param.ArgumentList)'"
        Start-Process @param
    }
    catch {
        Write-Host "$(Get-Date -Format 'yyyMMdd-HHmmss'): ERROR: $($Error[0].Message)"
        $script:e = 1
    }
}
function Volume_Stats {
    $v = $null
    $v = Get-Volume -DriveLetter $env:SystemDrive.Replace(':', '')
    
    $s = $null
    $s = [math]::Round($v.Size / 1GB, 2)
    
    $f = $null
    $f = [math]::Round($v.SizeRemaining / 1GB, 2)

    $p = $null
    $p = $([math]::Round($f / $s * 100, 2))

    $r = "" | Select-Object SizeGB, FreeGB, PercentFree
    $r.SizeGB = $s
    $r.FreeGB = $f
    $r.PercentFree = $p

    return $r
}

# run subfunctions
Volume_Stats | Format-Table -AutoSize
Remove_Apps
Remove_CamLogs
Disable_Hibernation
Empty_Directories
Run_Cleanmgr
Volume_Stats | Format-Table -AutoSize

# end logging and exit
Stop-Transcript
exit $script:e