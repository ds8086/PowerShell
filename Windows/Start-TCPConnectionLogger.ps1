Function Start-TCPConnectionLogger {
<#
.SYNOPSIS
Logs internet TCP connections, IP whois info, and related process name to CSV.

.DESCRIPTION
Logs internet TCP connections, IP whois info, and related process name to CSV.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 
Call From:
    PowerShell v5.1+

.PARAMETER Sleep
Minutes to sleep between querying internet TCP connections. Default value is '1'.

.PARAMETER Runtime
Minutes to run script execution. Default value is '15'.

.EXAMPLE
Start-TCPConnectionLogger
Log internet TCP connections, IP whois info, and related process name to CSV.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    $Sleep = 1,

    [Parameter(Mandatory = $false)]
    [Int32]$Runtime = 15
)

begin {
    $tmp = "$env:TEMP\TCPConnectionTracker"
    if ( (Test-Path -Path $tmp) -eq $false ) {
        try {
            mkdir $tmp | Out-Null
        }
        catch {
            throw
        }
    }
    $csv = "~\TCPConnectionTracker.csv"
    if ( (Test-Path -Path $csv) -eq $false ) {
        New-Item -Path ~ -Name 'TCPConnectionTracker.csv' -ItemType File | Out-Null
    }
} # begin

process {
    $end = (Get-Date).AddMinutes($Runtime)
    Write-Verbose "TCP connection tracker will run until $($end)"
    $ips = New-Object -TypeName System.Collections.ArrayList
    do {
        $run = Get-Date -Format 'yyyMMdd-HHmmss'
        $tcp = Get-NetTCPConnection | Where-Object {
            $_.State -notin 'Listen', 'Bound' -and
            $_.RemoteAddress -ne "127.0.0.1" -and
            $_.RemoteAddress -notlike "10.*" -and
            $_.RemoteAddress -notlike "192.168.*" -and
            $_.RemoteAddress -notlike "172.16.*" -and
            $_.RemoteAddress -notlike "172.17.*" -and
            $_.RemoteAddress -notlike "172.18.*" -and
            $_.RemoteAddress -notlike "172.19.*" -and
            $_.RemoteAddress -notlike "172.20.*" -and
            $_.RemoteAddress -notlike "172.21.*" -and
            $_.RemoteAddress -notlike "172.22.*" -and
            $_.RemoteAddress -notlike "172.23.*" -and
            $_.RemoteAddress -notlike "172.24.*" -and
            $_.RemoteAddress -notlike "172.25.*" -and
            $_.RemoteAddress -notlike "172.26.*" -and
            $_.RemoteAddress -notlike "172.27.*" -and
            $_.RemoteAddress -notlike "172.28.*" -and
            $_.RemoteAddress -notlike "172.29.*" -and
            $_.RemoteAddress -notlike "172.30.*" -and
            $_.RemoteAddress -notlike "172.31.*"
        }
        $tcp | ForEach-Object {
            try {
                $own = $null
                $own = Get-Process -Id $_.OwningProcess -ErrorAction Stop
            }
            catch {
                $own = "" | Select-Object @{Name = 'Name'; Expression = 'Unknown' }
            }

            if ($ips -notcontains $_.RemoteAddress) {
                $ips.Add($_.RemoteAddress) | Out-Null
            }

            # known ip address
            if ( Test-Path -Path "$tmp\$($_.RemoteAddress).json" ) {
                Write-Verbose "$($_.RemoteAddress) previously seen"
                $who = Get-Content -Path "$tmp\$($_.RemoteAddress).json"
            }
            # new ip address
            else {
                Write-Verbose "$($_.RemoteAddress) is new"
                $who = $null
                $who = (Invoke-WebRequest -Uri "http://ipwho.is/$($_.RemoteAddress)").Content
                $who | Out-File "$tmp\$($_.RemoteAddress).json" | Out-Null
            }
            $jsn = $who | ConvertFrom-Json

            $sel = @{
                'Property' = @(
                    @{Name = "Datetime"; E = { $run } },
                    'RemoteAddress',
                    'RemotePort',
                    @{Name = "Process"; Expression = { $own.Name } },
                    @{Name = "Country"; Expression = { $jsn.country } },
                    @{Name = "Region"; Expression = { $jsn.region } },
                    @{Name = "ASN"; Expression = { $jsn.connection.asn } },
                    @{Name = "Organization"; Expression = { $jsn.connection.org } },
                    @{Name = "ISP"; Expression = { $jsn.connection.isp } }
                )
            }
            Write-Verbose $( $_ | Select-Object @sel )
            $_ | Select-Object @sel | Export-Csv -Path $csv -Append
        }
        Write-Verbose "$($run): unique IP addresses seen: $($ips.Count)"
        Start-Sleep -Seconds $(60 * $Sleep)
    }
    while ((Get-Date) -lt $end)
} # process

end {
    & $csv
}
}