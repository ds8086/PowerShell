Function Find-NetConnection {
<#
.SYNOPSIS
Similar to the native 'Test-NetConnection' cmdlet provided by the NetTCPIP module.

.DESCRIPTION
Similar to the native 'Test-NetConnection' cmdlet provided by the NetTCPIP module with the differences outlined below.
- Does not attempt ICMP (ping).
- Has an adjustable timeout (default of 100 ms).
- Accepts multi-valued strings for both 'ComputerName' and 'Port' parameters.
- Actually runs fast enough to be viable for network reconnaissance.
- Provides output with *no* parameters specified (just try it).

.NOTES
Author:
    DS
Notes:
    Revision 02
Revision:
    V01: 2025.06.12 by DS :: Initial revision.
    V02: 2025.12.22 by DS :: Line lengths. Backticks. Statement capitalization.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The ComputerName(s) to test. Can be either IP addresses or host names.

.PARAMETER Port
The TCP port(s) to test.

.PARAMETER Timeout
The timeout (in ms) to wait in between testing each port.

.PARAMETER OpenOnly
Switched parameter which, when specified, will only return port(s) which appear to be open on the specified computer(s).

.EXAMPLE
Find-NetConnection -ComputerName 192.168.0.1 -Port 80, 443
Tests network connectivity on ports 80 and 443 for the computer with IP address 192.168.0.1.

.EXAMPLE
Find-NetConnection -ComputerName 192.168.0.1, 192.168.0.2 -Port 80, 443
Tests network connectivity on ports 80 and 443 for the computer(s) with IP addresses 192.168.0.1 and 192.168.0.2.

.EXAMPLE
Find-NetConnection -ComputerName (Get-Content .\computers.txt) -Port (Get-Content .\ports.txt) -OpenOnly
Tests network connectivity on ports listed in 'ports.txt' for the computers listed in 'computers.txt'.
Only returns ports which appear to be open on the specified computers.

.EXAMPLE
Find-NetConnection
No parameters, but how?! What could it possibly do?
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false, Position=0)]
    [AllowNull()]
    [string[]]$ComputerName = $null,
    
    [Parameter(Mandatory=$false, Position=1)]
    [AllowNull()]
    [string[]]$Port = $null,

    [Parameter(Mandatory=$false, Position=2)]
    [int]$Timeout = 100,

    [Parameter(Mandatory=$false)]
    [switch]$OpenOnly
)

Begin {
    $Results = New-Object -TypeName System.Collections.ArrayList
    function tcpTest {
        
        # Define TCP client connection
        $r = $null # requestCallback
        $s = $null # state
        $t = New-Object System.Net.Sockets.TcpClient
        
        # Create TCP client connection, wait, check if connected, then close
        $t.BeginConnect($c, $p, $r, $s) | Out-Null
        Start-Sleep -Milliseconds $Timeout
        
        if ($t.Connected) { $o = $true } else { $o = $false }
        $t.Close()

        # results for individual test
        $res = $null
        $res = "" | Select-Object @{Name='ComputerName';Expression={$c}},
            @{Name='Port';Expression={$p}},
            @{Name='Open';Expression={$o}}

        # add individual results to array output in 'end' block
        $Results.add($res) | Out-Null
    }

    # Default value for $ComputerName if not specified
    if (!$ComputerName) {
        Write-Verbose "ComputerName not specified, using ARP table entries"
        $ComputerName = arp -a | findstr dynamic | ForEach-Object {
            $_.Split(' ') | Where-Object { $_ -notin '','dynamic' -and $_ -notlike "??-??-??-??-??-??" }
        }
    }

    # Default value for $Port if not specified
    if (!$Port) {
        Write-Verbose "Port not specified, using list of interesting ports"
        $Port = @(
            21,22,23,25,53,80,88,
            110,135,139,143,179,
            201,
            389,
            443,445,
            520,
            1433,1521,
            3128,3306,3389,
            5060,5900,
            6000,
            9100
        )
    }
} # Begin

Process {
    $i = 0
    foreach ($c in $ComputerName) {
        $i++
        Write-Progress "Processing computer '$c'" -PercentComplete ($i / $ComputerName.Count * 100) -Id 1

        $ii = 0
        foreach ($p in $Port) {
            $ii++
            Write-Progress "Testing port '$p'" -PercentComplete ($ii / $Port.Count * 100) -ParentId 1
            tcpTest
        }
    }
} # Process

End {
    if ($OpenOnly) {
        $Results | Where-Object {$_.Open -eq $True}
    }
    else {
        $Results
    }
}

}