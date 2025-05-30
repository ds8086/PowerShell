Function Get-F5SecurtyLogProfiles {
<#
.SYNOPSIS
Determine security log profile and virtual server info for specified F5(s).

.DESCRIPTION
Determine security log profile and virtual server info for specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2023.07.18 by DS :: First revision.
    V02: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V03: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V04: 2025.03.17 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which security log profiles and virtual server info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5SecurtyLogProfiles -F5 'f5-ext-01.contoso.com'
Will retrieve security log profile and virtual server info from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5SslProfiles -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve security log profile and virtual server info from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
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

# Subfunction to retrieve virtual servers and security log profiles
Function SecurityLogProfiles {
    
    # tmsh command: list virtual servers
    $cmd = $null
    $cmd = "$term list /ltm virtual security-log-profiles"
    Write-Host "Run '$cmd' on $f" -ForegroundColor Gray

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")
    
    If ($ssh.ExitStatus -eq 0) {
        Write-Verbose "Successfully ran '$cmd' on $f"
        
        $out = $ssh.Output
        foreach ($o in $out) {
            switch ($o) {
                {$_ -like "ltm virtual * {"} {
                    $res = "" | Select-Object F5,VS,SecurityLogProfile
                    $res.F5 = $f
                    $res.VS = $o.Replace('ltm virtual ','').Replace(' {','')
                }
                {$_ -eq "    security-log-profiles none"} {
                    $res.SecurityLogProfile = "none"
                    $res | Select-Object *
                }
                {$_ -in "    security-log-profiles {","    }","}"} {
                    
                }
                Default {
                    $res.SecurityLogProfile = $o.TrimStart(' ')
                    $res | Select-Object *
                }
            }
        }
    }
    Else {
        Write-Warning "Execution of '$cmd' on '$f' was not successful!"
    }
}

# Main foreach loop to run subfunctions on F5(s)
$i = 0
$Results = foreach ($f in $F5) {
    
    $i++
    Try {
        Write-Progress "Gathering SSL profile info from '$f'" -PercentComplete $($i / $F5.Count * 100)
    }
    Catch {}

    Shell
    SSHSession
    SecurityLogProfiles
}

# Output results
$Results

}