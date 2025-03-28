Function Get-F5HttpMonitors {
<#
.SYNOPSIS
Retrieves HTTP(S) health monitors for the specified F5(s).

.DESCRIPTION
Retrieves HTTP(S) health monitors for the specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2023.08.15 by DS :: First revision.
    V02: 2024.01.03 by DS :: Updated to include 'ssl-profile' attribute in output. Fixed output on 'Name' attribute for HTTPS monitors.
    V03: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V04: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V05: 2025.03.17 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which hardware and version info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5HttpMonitors -F5 'f5-ext-01.contoso.com'
Will retrieve HTTP(S) health monitors from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5HttpMonitors -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve HTTP(S) health monitors from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string[]]$F5,
    
    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null
)

# Define and import required modules
$RequiredModules = "Posh-SSH"
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

# Subfunction to create SSH session if it does not already exist
Function SSHSession {
    If (!(Get-SSHSession -ComputerName $f)) {
        If ($null -eq $Credential) {
            $Credential = Get-Credential -Message "Enter SSH credentials for $f"
        }
        New-SSHSession -ComputerName $f -Port 22 -Credential $Credential -AcceptKey -Force -WarningAction SilentlyContinue | Out-Null
    }
}

# Subfunction for determining if commands should be prefixed with 'tmsh'
Function Shell {
    $commands = "tmsh show /sys version","show /sys version"
    $cmdtests = foreach ($cmd in $commands) {
        $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command $cmd
        $ssh | Select-Object @{N="cmd";E={$cmd}},ExitStatus
    }
    If ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "tmsh *" ) {
        $script:term = "tmsh"
    }
    ElseIf ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "show *" ) {
        $script:term = $null
    }
}

# Subfunctions to retrieve http and https monitors
Function Http {

    # tmsh command: list http monitors
    $cmd = $null
    $cmd = "$term list /ltm monitor http defaults-from interval recv recv-disable send time-until-up timeout"

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")
    
    foreach ($line in $ssh.Output) {
        switch ($line) {
            {$_ -like "ltm monitor http * {"} {
                $res = "" | Select-Object F5,Name,Defaults-From,Interval,Recv,Recv-Disable,Send,Time-Until-Up,Timeout,SSL-Profile
                $res.F5 = $f
                $res.Name = $line.Replace('ltm monitor http ','').Replace(' {','')
            }
            {$_ -like "    adaptive *"} {
                # Do nothing
            }
            {$_ -like "    defaults-from *"} {
                $res.'Defaults-From' = $line.Replace('    defaults-from ','')
            }
            {$_ -like "    interval *"} {
                $res.Interval = $line.Replace('    interval ','')
            }
            {$_ -like "    recv *"} {
                $res.Recv = $line.Replace('    recv ','')
            }
            {$_ -like "    recv-disable *"} {
                $res.'Recv-Disable' = $line.Replace('    recv-disable ','')
            }
            {$_ -like "    send *"} {
                $res.Send = $line.Replace('    send ','')
            }
            {$_ -like "    time-until-up *"} {
                $res.'Time-Until-Up' = $line.Replace('    time-until-up ','')
            }
            {$_ -like "    timeout *"} {
                $res.Timeout = $line.Replace('    timeout ','')
            }
            {$_ -eq "}"} {
                $res.'SSL-Profile' = [string]::new('N/A')
                $Results.add($res) | Out-Null
            }
        }
    }
}
Function Https {

    # tmsh command: list https monitors
    $cmd = $null
    $cmd = "$term list /ltm monitor https defaults-from interval recv recv-disable send time-until-up timeout ssl-profile"

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")
    
    foreach ($line in $ssh.Output) {
        switch ($line) {
            {$_ -like "ltm monitor https * {"} {
                $res = "" | Select-Object F5,Name,Defaults-From,Interval,Recv,Recv-Disable,Send,Time-Until-Up,Timeout,SSL-Profile
                $res.F5 = $f
                $res.Name = $line.Replace('ltm monitor https ','').Replace(' {','')
            }
            {$_ -like "    adaptive *"} {
                # Do nothing
            }
            {$_ -like "    defaults-from *"} {
                $res.'Defaults-From' = $line.Replace('    defaults-from ','')
            }
            {$_ -like "    interval *"} {
                $res.Interval = $line.Replace('    interval ','')
            }
            {$_ -like "    recv *"} {
                $res.Recv = $line.Replace('    recv ','')
            }
            {$_ -like "    recv-disable *"} {
                $res.'Recv-Disable' = $line.Replace('    recv-disable ','')
            }
            {$_ -like "    send *"} {
                $res.Send = $line.Replace('    send ','')
            }
            {$_ -like "    time-until-up *"} {
                $res.'Time-Until-Up' = $line.Replace('    time-until-up ','')
            }
            {$_ -like "    timeout *"} {
                $res.Timeout = $line.Replace('    timeout ','')
            }
            {$_ -like "    ssl-profile *"} {
                $res.'SSL-Profile' = $line.Replace('    ssl-profile ','')
            }
            {$_ -eq "}"} {
                $Results.add($res) | Out-Null
            }
        }
    }
}

# Results array
$Results = New-Object -TypeName System.Collections.ArrayList

# Main foreach loop to run subfunctions on F5(s)
$i = 0
foreach ($f in $F5) {
    
    $i++
    Try {
        Write-Progress "Retrieving HTTP(S) monitors from '$f'" -PercentComplete $($i / $F5.Count * 100)
    }
    Catch {}

    SSHSession
    Shell
    Http
    Https
}

# Output results
$Results

}