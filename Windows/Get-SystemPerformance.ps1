Function Get-SystemPerformance {
#Requires -Version 7
<#
.SYNOPSIS
Displays system performance.

.DESCRIPTION
Displays system performance.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.01.20 by DS :: First working iteration.
Call From:
    PowerShell v7.0 or higher

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

# uptime
$up = (Get-Uptime).ToString("d\:hh\:mm\:ss")
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
    Write-Host "├─ Processes: " -ForegroundColor DarkGreen -NoNewline
    Write-Host "$((Get-Counter '\system\processes').CounterSamples.CookedValue)"

    Write-Host "├─ Threads..: " -ForegroundColor DarkGreen -NoNewline
    Write-Host "$((Get-Counter '\system\threads').CounterSamples.CookedValue)"

    Write-Host "└─ Handles..: " -ForegroundColor DarkGreen -NoNewline
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
	Write-Host "├─ Committed: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Committed Bytes').CounterSamples.CookedValue / 1GB, 1))/" -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Commit Limit').CounterSamples.CookedValue / 1GB, 1)) GB"
	
	Write-Host "├─ Available: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Available Bytes').CounterSamples.CookedValue / 1GB, 1)) GB"
	
	$cached = @(
		'\Memory\Standby Cache Reserve Bytes',
		'\Memory\Standby Cache Normal Priority Bytes',
		'\Memory\Standby Cache Core Bytes',
		'\Memory\Modified Page List Bytes',
		'\Process(System)\Working Set'
	)
	$c = 0
	$cached | ForEach-Object {
		$c += (Get-Counter $_).CounterSamples.CookedValue
	}
	
	Write-Host "├─ Cached...: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round($c / 1GB, 1)) GB"
	
	Write-Host "├─ Paged....: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Pool Paged Bytes').CounterSamples.CookedValue / 1GB, 1)) GB"
	
	Write-Host "└─ Non-paged: " -ForegroundColor DarkGreen -NoNewline
	Write-Host "$([math]::Round((Get-Counter '\Memory\Pool Nonpaged Bytes').CounterSamples.CookedValue / 1MB)) MB"
    Write-Host ""
}

# disk
$disk = (Get-Counter '\PhysicalDisk(*)\% Idle Time').CounterSamples | Where-Object {$_.InstanceName -ne '_total'}
$disk | ForEach-Object {
    $n = $_.InstanceName.Split(' ') | Select-Object -First 1
    $l = ($_.InstanceName.Split(' ') | Select-Object -Last 1).ToUpper()
    Write-Host "Disk $n ($l).: " -ForegroundColor Green -NoNewline
    Write-Host "$([math]::round(100 - $_.CookedValue))%"

    # disk detail
    if ($Detail -contains 'Disk') {
        Write-Host "├─ Read.....: " -ForegroundColor DarkGreen -NoNewline
        Write-Host "$([math]::Round((Get-Counter "\PhysicalDisk($n $l)\Disk Read Bytes/sec").CounterSamples.CookedValue / 1KB, 1)) KB/s"
        
        Write-Host "└─ Write....: " -ForegroundColor DarkGreen -NoNewline
        Write-Host "$([math]::Round((Get-Counter "\PhysicalDisk($n $l)\Disk Write Bytes/sec").CounterSamples.CookedValue / 1KB, 1)) KB/s"
        Write-Host ""
    }
}

}