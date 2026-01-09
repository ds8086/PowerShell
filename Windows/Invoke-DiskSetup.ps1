Function Invoke-QuickDiskSetup {
<#
.SYNOPSIS
Invokes quick disk setup.

.DESCRIPTION
Invokes quick disk setup and optionally moves pagefile.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2025.01.08 by DS :: First version for GitHub.
Call From:
    Windows PowerShell v5.1 or newer.

.INPUTS
None

.OUTPUTS
None

.PARAMETER Pagefile
Move the pagefile to the newly setup disk volume.

.EXAMPLE
Invoke-QuickDiskSetup
Initializes the largest RAW drive and formats it with the next available drive letter.

.EXAMPLE
Invoke-QuickDiskSetup -PageFile
Initializes the largest RAW drive and formats it with the next available drive letter then moves the pagefile.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false)]
    [switch]$Pagefile = $false
)

# Subfunctions
Function DriveLetter {
	$script:letter = $null
	68..90 | ForEach-Object { [char]$_ } | Foreach-Object {
		if (!($script:letter)) {
			if (Get-Volume -DriveLetter $_ -ErrorAction SilentlyContinue) {
				Write-Verbose "$($_):\ already in use"
			}
			else {
				$script:letter = $_
			}
		}
	}
}
Function Initialize {
	try {
		$disk | Initialize-Disk -PartitionStyle GPT -ErrorAction Stop | Out-Null
		$disk | New-Partition -UseMaximumSize -DriveLetter $script:letter -ErrorAction Stop | Out-Null
		Format-Volume -DriveLetter $script:letter -FileSystem NTFS -Confirm:$false -ErrorAction Stop | Out-Null
	}
	catch {
		throw
	}
}
Function PageFile {
	if ((Get-WmiObject -Class Win32_PageFileSetting).Name -ne "$($script:letter):\pagefile.sys") {
		Write-Verbose "Move pagefile to $($script:letter):\"
		
		# Disable automatically managed pagefile
		$SysInfo = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
		$SysInfo.AutomaticManagedPageFile = $false
		[Void]$sysinfo.Put()
		
		# Remove existing pagefile
		(Get-WmiObject -Class Win32_PageFileSetting).Delete()

		# New pagefile
		$wmi = @{
			'Class' = 'Win32_PageFileSetting'
			'Arguments' = @{
				name="$($script:letter):\pagefile.sys"
			}
			'EnableAllPrivileges' = $true
		}
		Set-WmiInstance @wmi | Out-Null
	}
	elseif ((Get-WmiObject -Class Win32_PageFileSetting).Name -eq "$($script:letter):\pagefile.sys") {
		Write-Verbose "Pagefile already on $($script:letter):\"
	}
}

# Determine disk
$disk = Get-Disk | Where-Object {$_.PartitionStyle -eq 'RAW'} | Sort-Object Size -Descending | Select-Object -First 1

if ($disk) {
    DriveLetter
    if ($script:letter) {
        Initialize
        if ($Pagefile) {
			PageFile
		}
    }
}
else {
    Write-Warning "No elligible disks found"
}

}