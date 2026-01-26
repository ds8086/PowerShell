Function Get-SystemPerformance {
<#
.SYNOPSIS
Displays system performance.

.DESCRIPTION
Displays system performance.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2026.01.20 by DS :: First working iteration.
    V02: 2026.01.26 by DS :: Variable names, line lengths, support for Windows PS 5.1.
Call From:
    Windows PowerShell v5.1 or higher

.PARAMETER Detail
Display detailed counters for 'CPU', 'Memory', and/or 'Disk'.

.EXAMPLE
Get-SystemPerformance
Displays system performance overview.

.EXAMPLE
Get-SystemPerformance -Detail CPU
Displays system performance overview with detailed CPU counters.

.EXAMPLE
do { Get-SystemPerformance; sleep 3; Clear-Host } while ( $true )
Displays system performance overview refreshing every 3 seconds.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, Position=0)]
    [Alias('d')]
    [ValidateSet('CPU','Memory','Disk')]
    [AllowNull()]
    [string[]]$Detail
)

# PS version
$ver = $PSVersionTable.PSVersion.Major

# detail tree characters
if ($ver -gt 5) {
    $item = @('├─')
    $last = @('└─')
}
else {
    $item = @('|-')
    $last = @('|-')
}

# uptime
if ($ver -gt 5) {
    $up = (Get-Uptime).ToString("d\:hh\:mm\:ss")
}
else {
    $os = Get-WmiObject -Class win32_OperatingSystem
    $up = ($os | Select-Object @{N="up";E={
        (Get-Date) - ($_.ConvertToDateTime($_.LastBootUpTime))
    }}).up.ToString("d\:hh\:mm\:ss")
}
Write-Host "Uptime......: " -ForegroundColor Green -NoNewline
Write-Host $up
if ($Detail) {
    Write-Host ""
}

# cpu
$cpu = [math]::Round( (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue )
$freq = (Get-Counter '\Processor Information(_total)\Actual Frequency').CounterSamples.CookedValue
Write-Host "CPU.........: " -ForegroundColor Green -NoNewline
Write-Host "$cpu% $( [math]::round($freq / 1000, 2) ) GHz"

# cpu detail
if ($Detail -contains 'CPU') {
    Write-Host "$item Processes: " -ForegroundColor DarkGreen -NoNewline
    Write-Host "$((Get-Counter '\system\processes').CounterSamples.CookedValue)"

    Write-Host "$item Threads..: " -ForegroundColor DarkGreen -NoNewline
    Write-Host "$((Get-Counter '\system\threads').CounterSamples.CookedValue)"

    Write-Host "$last Handles..: " -ForegroundColor DarkGreen -NoNewline
    Write-Host "$((Get-Counter '\Process(_total)\Handle Count').CounterSamples.CookedValue)"
    Write-Host ""
}

# memory
$ram = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).Sum / 1GB
$mem = [math]::Round( ((Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue / 1024),1 )
Write-Host "Memory......: " -ForegroundColor Green -NoNewline
Write-Host "$($ram - $mem)/$ram GB ($([math]::round($($ram - $mem)/$ram * 100))%)"

# memory detail
if ($Detail -contains 'Memory') {
	Write-Host "$item Committed: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue / 1GB, 1))/" -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Commit Limit').CounterSamples.CookedValue / 1GB, 1)) GB"
	
	Write-Host "$item Available: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Available Bytes').CounterSamples.CookedValue / 1GB, 1)) GB"
	
	$cache = @(
		'\Memory\Standby Cache Reserve Bytes',
		'\Memory\Standby Cache Normal Priority Bytes',
		'\Memory\Standby Cache Core Bytes',
		'\Memory\Modified Page List Bytes',
		'\Process(System)\Working Set'
	)
	$total = 0
	$cache | ForEach-Object {
		$total += (Get-Counter $_).CounterSamples.CookedValue
	}
	
	Write-Host "$item Cached...: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round($total / 1GB, 1)) GB"
	
	Write-Host "$item Paged....: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Pool Paged Bytes').CounterSamples.CookedValue / 1GB, 1)) GB"
	
	Write-Host "$last Non-paged: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Pool Nonpaged Bytes').CounterSamples.CookedValue / 1MB)) MB"
    Write-Host ""
}

# disk
$disk = (Get-Counter '\PhysicalDisk(*)\% Idle Time').CounterSamples | Where-Object {$_.InstanceName -ne '_total'}
$disk | ForEach-Object {
    $number = $_.InstanceName.Split(' ') | Select-Object -First 1
    $letter = ($_.InstanceName.Split(' ') | Select-Object -Last 1).ToUpper()
    Write-Host "Disk $number ($letter).: " -ForegroundColor Green -NoNewline
    Write-Host "$([math]::round(100 - $_.CookedValue))%"

    # disk detail
    if ($Detail -contains 'Disk') {
        $read = (Get-Counter "\PhysicalDisk($number $letter)\Disk Read Bytes/sec").CounterSamples.CookedValue
        Write-Host "$item Read.....: " -ForegroundColor DarkGreen -NoNewline
        Write-Host "$([math]::Round($read / 1KB, 1)) KB/s"
        
        $write = (Get-Counter "\PhysicalDisk($number $letter)\Disk Write Bytes/sec").CounterSamples.CookedValue
        Write-Host "$last Write....: " -ForegroundColor DarkGreen -NoNewline
        Write-Host "$([math]::Round($write / 1KB, 1)) KB/s"
        Write-Host ""
    }
}

}