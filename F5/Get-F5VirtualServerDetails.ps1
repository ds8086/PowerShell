Function Get-F5VirtualServerDetails {
<#
.SYNOPSIS
Retrieves all virtual server, pool, and pool members from the specified F5.

.DESCRIPTION
Retrieves all virtual server, pool, and pool members from the specified F5. Note that pools which are not associated with a virtual server are not returned.

.NOTES
Author: 
    DS
Notes:
    Revision 07
Revision:
    V01: 2023.05.05 by DS :: First revision.
    V02: 2023.06.01 by DS :: Added '#Requires -Module Posh-SSH'.
    V03: 2023.07.03 by DS :: Removed 'ValueFromPipeline=$True' from $F5 parameter. Cleaned up spacing.
    V04: 2023.07.12 by DS :: Removed '#Requires -Module Posh-SSH' (not honored in functions). Added logic for importing the module.
    V05: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V06: 2025.03.17 by DS :: Updated comments and spacing. Fixed 'problems' reported by VS code.
    V07: 2025.03.26 by DS :: Replaced 'Shell' subfunction with 'GetShell'. Added 'IncludePoolMembers' parameter and supporting logic.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which virtual server, pool, and pool member (optional) info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.PARAMETER IncludePoolMembers
Switched parameter which, when specified, includes the member information for pools.

.EXAMPLE
Get-F5VirtualServerDetails -F5 'f5-ext-01.contoso.com'
Will retrieve virtual server and pool info from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5SslProfiles -F5 'f5-ext-01.contoso.com' -Credential $F5Creds -IncludePoolMembers
Will prompt for and store credentials in variable $F5Creds. Will retrieve virtual server, pool, and pool member info from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string[]]$F5,

    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory=$False)]
    [switch]$IncludePoolMembers = $False
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

# Subfunction for virtual servers, destination, and pool
Function VirtualServers {
    
    # TMSH cmd: Retrieve list of all virtual servers
    $cmd = $null
    switch ($shell) {
        'bash' {$cmd = 'tmsh list ltm virtual recursive destination pool'}
        'tmsh' {$cmd = 'list ltm virtual recursive destination pool'}
    }
    $Virtual = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd").Output

    # Array: F5, VS, Desintation, Pool
    $script:VirtualServers = New-Object -TypeName System.Collections.ArrayList
    
    # Populate $VirtualServers with F5, VS, Destination, and Pool depending on contents of each line of output in $Virtual
    foreach ($_ in $Virtual) {
        switch ($_) {
            {$_ -like "ltm virtual *"} {
                $vs = "" | Select-Object F5,VS,Destination,Pool
                $vs.F5 = $f
                $vs.VS = ($_).Replace('ltm virtual ','').Replace(' {','')
            }
            {$_ -like "    destination *"} {
                $vs.Destination = ($_).TrimStart(' ').Replace('destination ','')
            }
            {$_ -like "    pool *"} {
                $vs.Pool = ($_).TrimStart(' ').Replace('pool ','')
            }
            {$_ -eq "}"} {
                $VirtualServers.Add($vs) | Out-Null
            }
        }
    }
}

# Subfunction for determining pool member and address
Function PoolMembers {
    
    $ii = 0
    foreach ($vs in $VirtualServers) {
        $ii++
        Write-Progress "Retrieving details for '$($vs.VS)'" -PercentComplete ($ii / $VirtualServers.Count * 100) -ParentId 1

        # The virtual server has a pool
        If ($vs.Pool -ne "none") {
            
            # TMSH cmd: Retrieve pool
            $cmd = $null
            switch ($shell) {
                'bash' {$cmd = "tmsh list ltm pool $($vs.Pool)"}
                'tmsh' {$cmd = "list ltm pool $($vs.Pool)"}
            }

            # Select output from SSH command, limiting to only members and addresses
            $mem = $null
            $mem = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $vs.F5) -Command "$cmd").Output | Where-Object {$_ -like "*:*" -or $_ -like "*address *"}

            # The pool has at least one member
            If ($mem) {

                # Initialize $res, populate based on the line from $mem, then add to $Results and re-initialize
                $res = "" | Select-Object F5,VS,Destination,Pool,Member,Address
                foreach ($m in $mem) {
                    switch ($m) {
                        {$_ -like "* {"} {
                            $res.F5 = $vs.F5
                            $res.VS = $vs.VS
                            $res.Destination = $vs.Destination
                            $res.Pool = $vs.Pool
                            $res.Member = ($_).TrimStart(' ').Replace(' {','')
                        }
                        {$_ -like "*address *"} {
                            $res.Address = ($_).TrimStart(' ').Replace('address ','')
                            $Results.Add($res) | Out-Null
                            $res = "" | Select-Object F5,VS,Destination,Pool,Member,Address
                        }
                    }
                }
            }

            # The pool has no members
            Else {
                $res = "" | Select-Object F5,VS,Destination,Pool,Member,Address
                $res.F5 = $vs.F5
                $res.VS = $vs.VS
                $res.Destination = $vs.Destination
                $res.Pool = $vs.Pool
                $res.Member = [string]::new('none')
                $res.Address = [string]::new('none')
                $Results.Add($res) | Out-Null
            }
        }

        # The virtual server does not have a pool
        Else {
            $res = "" | Select-Object F5,VS,Destination,Pool,Member,Address
            $res.F5 = $vs.F5
            $res.VS = $vs.VS
            $res.Destination = $vs.Destination
            $res.Pool = [string]::new('none')
            $res.Member = [string]::new('n/a')
            $res.Address = [string]::new('n/a')
            $Results.Add($res) | Out-Null
        }
    }
}

# Results array populated by the 'PoolMembers' subfunction
$script:Results = New-Object -TypeName System.Collections.ArrayList

# Main foreach loop to run subfunctions on F5(s)
$i = 0
foreach ($f in $F5) {
    $i++
    Write-Progress "Retrieving virtual server export from '$f'" -PercentComplete ($i / $F5.Count * 100) -Id 1
    
    SSHSession
    
    $shell = $null
    $shell = GetShell

    VirtualServers

    If ($IncludePoolMembers) {
        PoolMembers
    }
}

# Output based on if pool members are included
If ($IncludePoolMembers) {
    $Results
}
Else {
    $VirtualServers
}

}