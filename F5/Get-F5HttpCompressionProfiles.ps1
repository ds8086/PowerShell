Function Get-F5HttpCompressionProfiles {
<#
.SYNOPSIS
Determine HTTP compression profile and virtual server info for specified F5(s).

.DESCRIPTION
Determine HTTP compression profile and virtual server info for specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2025.03.20 by DS :: First revision (quick repurpose of 'Get-F5SslProfiles').
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which hardware and version info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5HttpCompressionProfiles -F5 'f5-ext-01.contoso.com'
Will retrieve HTTP compression profile and virtual server info from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5SslProfiles -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve HTTP compression profile and virtual server info from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
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

# Subfunction for determining shell (tmsh or bash) for later commands
Function GetShell {
    Remove-Variable -Name term -Scope script -ErrorAction SilentlyContinue

    $commands = "tmsh show /sys version","show /sys version"
    $cmdtests = foreach ($cmd in $commands) {
        $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command $cmd
        $ssh | Select-Object @{N="cmd";E={$cmd}},ExitStatus
    }
    If ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "tmsh *" ) {
        return "bash"
    }
    ElseIf ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "show *" ) {
        return "tmsh"
    }
}

# Subfunction to retrieve HTTP compression profiles
Function CompressionProfiles {
    
    # Results for this subfunction
    $Results = New-Object -TypeName System.Collections.ArrayList

    # tmsh command: list http compression profiles
    $cmd = $null
    switch ($shell) {
        'bash' {$cmd = "tmsh list /ltm profile http-compression"}
        'tmsh' {$cmd = "list /ltm profile http-compression"}
    }

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    If ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output
        foreach ($o in $out) {
            switch ($o) {
                {$_ -like "ltm profile http-compression * {"} {
                    $res = "" | Select-Object F5,Profile
                    $res.F5 = $f
                    $res.Profile = $_.Replace('ltm profile http-compression ','').TrimEnd(' {')
                }
                {$_ -eq '}'} {
                    $Results.Add($res) | Out-Null
                }
            }
        }
    }

    $Results
}

# Subfunction to retrieve virtual servers and profiles
Function VsProfiles {
    
    # $Results = New-Object -TypeName System.Collections.ArrayList

    # tmsh command: list virtual servers
    $cmd = $null
    switch ($shell) {
        'bash' {$cmd = "tmsh list /ltm virtual profiles"}
        'tmsh' {$cmd = "list /ltm virtual profiles"}
    }

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    If ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output
        foreach ($o in $out) {
            switch ($o) {
                {$_ -like "ltm virtual * {"} {
                    $res = "" | Select-Object F5,VS,Profile
                    $res.F5 = $f
                    $res.VS = $_.Replace('ltm virtual ','').TrimEnd(' {')
                }
                {$_ -eq '    profiles {'} {
                    # do nothing
                }
                {$_ -like "        * {"} {
                    $Res.Profile = $_.Replace('        ','').TrimEnd(' {')
                }
                {$_ -like "            context *"} {
                    # output individual result
                    $res | Select-Object *
                }
                {$_ -in '        }', '    }', '}'} {
                    # do nothing
                }
            }
        }
    }
}

# Main foreach loop to run subfunctions on F5(s)
$i = 0
$Results = foreach ($f in $F5) {
    
    $i++
    Try {
        Write-Progress "Gathering HTTP compression profile info from '$f'" -PercentComplete $($i / $F5.Count * 100)
    }
    Catch {}

    SSHSession
    $shell = GetShell

    Write-Verbose "Retrieve HTTP compression profiles from '$f'"
    $compressionprofiles = CompressionProfiles
    
    Write-Verbose "Retrieve virtual servers from '$f'"
    $vsprofiles = VsProfiles

    # Attempt to match each HTTP compression profile with a virtual server using data stored in $compressionprofiles and $vsprofiles
    foreach ($cp in $compressionprofiles) {
        
        $match = $null
        $match = $vsprofiles | Where-Object { ($_.Profile -eq $cp.Profile) -and ($_.F5 -eq $f) }

        # The individual HTTP compression profile ($cp) is used by a virtual server
        If ($match) {
            $match | Select-Object F5,VS,Profile
        }

        # The individual HTTP compression profile ($cp) is *NOT* used by a virtual server
        Else {
            $cp | Select-Object F5,@{N="VS";E={[string]::new("None")}},Profile
        }
    }
}

# Output results
$Results

}