Function Get-F5SslProfiles {
<#
.SYNOPSIS
Determine SSL profile and virtual server info for specified F5(s).

.DESCRIPTION
Determine SSL profile and virtual server info for specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 10
Revision:
    V01: 2023.04.24 by DS :: First revision.
    V02: 2023.06.01 by DS :: Added '#Requires -Module Posh-SSH'.
    V03: 2023.07.03 by DS :: Removed 'ValueFromPipeline=$True' from $F5 parameter. Cleaned up spacing.
    V04: 2023.07.12 by DS :: Removed '#Requires -Module Posh-SSH' (not honored in functions). Added logic for importing the module.
    V05: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V06: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V07: 2025.03.17 by DS :: Updated comments and spacing.
    V08: 2025.03.20 by DS :: Added 'peer-cert-mode' to output. Replaced 'Shell' subfunction with 'GetShell'. Improved 'VsProfiles' subfunction.
    V09: 2025.03.21 by DS :: Cleaned variable names in subfunctions.
    V10: 2025.12.11 by DS :: Cleaned up header and statement capitalization. Minor change to required modules.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.INPUTS
None

.OUTPUTS
None

.PARAMETER F5
The name(s) of F5(s) for which hardware and version info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5SslProfiles -F5 'f5-ext-01.contoso.com'
Will retrieve SSL profile and virtual server info from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5SslProfiles -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Using credentials in variable $F5Creds, retrieves SSL profile and virtual server info from 'f5-ext-01.contoso.com'.
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
    try {
        if (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    catch {
        throw
    }
}

# Subfunction to create SSH session if it does not already exist
Function SSHSession {
    if (!(Get-SSHSession -ComputerName $f)) {
        if ($null -eq $Credential) {
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
    if ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "tmsh *" ) {
        return "bash"
    }
    elseif ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "show *" ) {
        return "tmsh"
    }
}

# Subfunction to retrieve SSL (client and server) profiles
Function SslProfiles {
    
    # Results for this subfunction
    $ssl = New-Object -TypeName System.Collections.ArrayList

    # tmsh command: list client-ssl profiles
    $cmd = $null
    switch ($shell) {
        'bash' {$cmd = "tmsh list /ltm profile client-ssl peer-cert-mode"}
        'tmsh' {$cmd = "list /ltm profile client-ssl peer-cert-mode"}
    }

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    if ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output
        foreach ($o in $out) {
            switch ($o) {
                {$_ -like "ltm profile client-ssl * {"} {
                    $res = "" | Select-Object F5,Profile,Context,Peer-Cert-Mode
                    $res.F5 = $f
                    $res.Profile = $_.Replace('ltm profile client-ssl ','').TrimEnd(' {')
                    $res.Context = [string]::new('client-ssl')
                }
                {$_ -like "    peer-cert-mode *"} {
                    $res.'Peer-Cert-Mode' = $_.Replace('    peer-cert-mode ','')
                }
                {$_ -eq '}'} {
                    $ssl.Add($res) | Out-Null
                }
            }
        }
    }

    # tmsh command: list server-ssl profiles
    $cmd = $null
    switch ($shell) {
        'bash' {$cmd = "tmsh list /ltm profile server-ssl peer-cert-mode"}
        'tmsh' {$cmd = "list /ltm profile server-ssl peer-cert-mode"}
    }

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    if ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output
        foreach ($o in $out) {
            switch ($o) {
                {$_ -like "ltm profile server-ssl * {"} {
                    $res = "" | Select-Object F5,Profile,Context,Peer-Cert-Mode
                    $res.F5 = $f
                    $res.Profile = $_.Replace('ltm profile server-ssl ','').TrimEnd(' {')
                    $res.Context = [string]::new('server-ssl')
                }
                {$_ -like "    peer-cert-mode *"} {
                    $res.'Peer-Cert-Mode' = $_.Replace('    peer-cert-mode ','')
                }
                {$_ -eq '}'} {
                    $ssl.Add($res) | Out-Null
                }
            }
        }
    }

    $ssl
}

# Subfunction to retrieve virtual servers and profiles
Function VsProfiles {
    
    # tmsh command: list virtual servers
    $cmd = $null
    switch ($shell) {
        'bash' {$cmd = "tmsh list /ltm virtual profiles"}
        'tmsh' {$cmd = "list /ltm virtual profiles"}
    }

    # Invoke tmsh command
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    if ($ssh.ExitStatus -eq 0) {
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
    try {
        Write-Progress "Gathering SSL profile info from '$f'" -PercentComplete $($i / $F5.Count * 100)
    }
    catch {}

    SSHSession
    $shell = GetShell

    Write-Verbose "Retrieve SSL profiles from '$f'"
    $sslprofiles = SslProfiles
    
    Write-Verbose "Retrieve virtual servers from '$f'"
    $vsprofiles = VsProfiles

    # Attempt to match each SSL profile with a virtual server using data stored in $sslprofiles and $vsprofiles
    foreach ($sp in $sslprofiles) {
        
        $match = $null
        $match = $vsprofiles | Where-Object { ($_.Profile -eq $sp.Profile) -and ($_.F5 -eq $f) }

        # The individual SSL profile ($sp) is used by a virtual server
        if ($match) {
            $match | Select-Object F5,VS,Profile,@{N="Context";E={$sp.Context}},@{N="Peer-Cert-Mode";E={$sp.'Peer-Cert-Mode'}}
        }

        # The individual SSL profile ($sp) is *NOT* used by a virtual server
        else {
            $sp | Select-Object F5,@{N="VS";E={[string]::new("None")}},Profile,Context,'Peer-Cert-Mode'
        }
    }
}

# Output results
$Results

}