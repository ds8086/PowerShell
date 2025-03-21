Function Get-F5VirtualAddresses {
<#
.SYNOPSIS
Retrieves all virtual addresses from the specified F5(s).

.DESCRIPTION
Retrieves all virtual addresses from the specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2023.09.29 by DS :: First revision.
    V02: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V03: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V04: 2025.03.17 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which virtual addresses will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5VirtualAddresses -F5 'f5-ext-01.contoso.com'
Will retrieve virtual addresses from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5SslProfiles -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve virtual addresses from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
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

# Subfunction for virtual addresses
Function VirtualAddresses {
    
    # TMSH cmd: Retrieve list of all virtual addresses
    $cmd = $null
    $cmd = "$term list /ltm virtual-address address enabled floating icmp-echo mask partition traffic-group"
    $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd"

    # Populate $Results based on $ssh.output
    foreach ($line in $ssh.Output) {
        switch ($line) {
            {$_ -like "ltm virtual-address * {"} {
                $addr = "" | Select-Object F5,Address,Enabled,Floating,ICMP-echo,Mask,Partition,Traffic-group
                $addr.F5 = $f
            }
            {$_ -like "    address *"} {
                $addr.Address = ($_).TrimStart(' ').Replace('address ','')
            }
            {$_ -like "    enabled *"} {
                $addr.Enabled = ($_).TrimStart(' ').Replace('enabled ','')
            }
            {$_ -like "    floating *"} {
                $addr.Floating = ($_).TrimStart(' ').Replace('floating ','')
            }
            {$_ -like "    icmp-echo *"} {
                $addr.'ICMP-echo' = ($_).TrimStart(' ').Replace('icmp-echo ','')
            }
            {$_ -like "    mask *"} {
                $addr.Mask = ($_).TrimStart(' ').Replace('mask ','')
            }
            {$_ -like "    partition *"} {
                $addr.Partition = ($_).TrimStart(' ').Replace('partition ','')
            }
            {$_ -like "    traffic-group *"} {
                $addr.'Traffic-group' = ($_).TrimStart(' ').Replace('traffic-group ','')
            }
            {$_ -eq "}"} {
                $Results.Add($addr) | Out-Null
            }
        }
    }
}

# Results array populated by the 'VirtualServers' subfunction
$script:Results = New-Object -TypeName System.Collections.ArrayList

# Main foreach loop to run subfunctions on F5(s)
$i = 0
foreach ($f in $F5) {
    $i++
    Write-Progress "Retrieving virtual address export from '$f'" -PercentComplete ($i / $F5.Count * 100) -Id 1
    SSHSession
    Shell
    VirtualAddresses
}

# Return results
$Results

}