Function Get-F5SslProfiles {

<#
.SYNOPSIS
Determine SSL profile and virtual server info for specified F5(s).

.DESCRIPTION
Determine SSL profile and virtual server info for specified F5(s).

.NOTES
Author: 
    Devin S
Notes:
    Revision 6
Revision:
    V01: 2023.04.24 by DS :: First revision.
    V02: 2023.06.01 by DS :: Added '#Requires -Module Posh-SSH'.
    V03: 2023.07.03 by DS :: Removed 'ValueFromPipeline=$True' from $F5 parameter. Cleaned up spacing.
    V04: 2023.07.12 by DS :: Removed '#Requires -Module Posh-SSH' (not honored in functions). Added logic for importing the module.
    V05: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V06: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which hardware and version info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5SslProfiles -F5 'f5-ext-01.contoso.com'
Will retrieve SSL profile and virtual server info from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5SslProfiles -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve SSL profile and virtual server info from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
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

# Subfunction to retrieve SSL (client and server) profiles
Function SslProfiles {

    # tmsh command: list client-ssl profiles
    $cmd = $null
    $cmd = "$term list ltm profile client-ssl defaults-from"

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    # Store client SSL profiles names in $clientssl
    $clientssl = ($ssh.Output | Where-Object {$_ -like "* {"}).Replace('ltm profile client-ssl ','').TrimEnd(' {')

    # Store client SSL profiles names in $allssl adding the 'Context' attribute
    $allssl = foreach ($_ in $clientssl) {
        $_ | Select-Object @{N="F5";E={$f}},@{N="Profile";E={$_}},@{N="Context";E={'client-ssl'}}
    }

    # tmsh command: list server-ssl profiles
    $cmd = $null
    $cmd = "$term list ltm profile server-ssl defaults-from"

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    # Store client SSL profiles names in $clientssl
    $serverssl = ($ssh.Output | Where-Object {$_ -like "* {"}).Replace('ltm profile server-ssl ','').TrimEnd(' {')

    # Store server SSL profiles names in $allssl adding the 'Context' attribute
    $allssl += foreach ($_ in $serverssl) {
        $_ | Select-Object @{N="F5";E={$f}},@{N="Profile";E={$_}},@{N="Context";E={'server-ssl'}}
    }

    $allssl
}

# Subfunction to retrieve virtual servers and profiles
Function VsProfiles {
    
    # tmsh command: list virtual servers
    $cmd = $null
    $cmd = "$term list ltm virtual"

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    # Create $virtualservers from ssh output
    $virtualservers = $null
    $virtualservers = ($ssh.Output | Where-Object {$_ -like "ltm virtual *"}).Replace('ltm virtual ','').Replace(' {','')

    If ($virtualservers) {
        foreach ($vs in $virtualservers) {

            # tmsh command: list profiles for specifc virtual server
            $cmd = $null
            $cmd = "$term list ltm virtual $vs profiles"

            # Invoke tmsh command
            $ssh = $null
            $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

            # Create $profiles from ssh output
            $profiles = $null
            $profiles = ($ssh.Output | Where-Object {$_ -like " *{" -and $_ -notlike "ltm virtual *" -and $_ -notlike "*profiles {"}).TrimStart(' ').TrimEnd(' {')
            
            # Profiles exist on the given virtual server
            If ($profiles) {

                foreach ($p in $profiles) {
                    $p | Select-Object @{N="F5";E={$f}},@{N="VirtualServer";E={$vs}},@{N="Profile";E={$_}}
                }
            }
            Else {
                $vs | Select-Object @{N="F5";E={$f}},@{N="VirtualServer";E={$_}},@{N="Profile";E={[string]::new("None")}}
            }
        }
    }
    Else {
        $f | Select-Object @{N="F5";E={$_}},@{N="VirtualServer";E={[string]::new("None")}},@{N="Profile";E={[string]::new("None")}} 
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

    SSHSession
    Shell

    Write-Verbose "'$f' gathering SSL profiles"
    $sslprofiles = SslProfiles
    
    Write-Verbose "'$f' gathering virtual servers"
    $vsprofiles = VsProfiles

    # Attempt to match each SSL profile with a virtual server using data stored in $sslprofiles and $vsprofiles
    foreach ($sp in $sslprofiles) {
        
        $match = $null
        $match = $vsprofiles | Where-Object {$_.Profile -eq $sp.Profile}

        # The individual SSL profile ($sp) is used by a virtual server
        If ($match) {
            Write-Verbose "'$f' SSL profile '$($sp.Profile)' is used by VS '$($match.VirtualServer)'"
            $match | Select-Object F5,VirtualServer,Profile,@{N="Context";E={$sp.Context}}
        }

        # The individual SSL profile ($sp) is *NOT* used by a virtual server
        Else {
            Write-Verbose "'$f' SSL profile '$($sp.Profile)' is *NOT* used by any VS"
            $sp | Select-Object F5,@{N="VirtualServer";E={[string]::new("None")}},Profile,Context
        }
    }
}

# Output results
$Results

}
