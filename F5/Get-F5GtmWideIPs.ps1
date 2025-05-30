Function Get-F5GtmWideIPs {
<#
.SYNOPSIS
Retrieves F5 GTM wide IP A records

.DESCRIPTION
Retrieves F5 GTM wide IP A records

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2024.12.06 by DS :: First revision.
    V02: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V03: 2025.03.17 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) from which GTM wide IPs will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
$F5Creds = Get-Credential; Get-F5GtmWideIPs -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve GTM wide IPs from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string[]]$F5,

    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null
)

# Properties to retrieve for wide IPs
$Properties = 'Aliases','Pool-LB-Mode','Pools','Rules'

# Define and import required modules
$RequiredModules = "Posh-SSH"
foreach ($rm in $RequiredModules) {
    Try {
        If (!(Get-Module -Name $rm)) {
            Import-Module -Name $rm -ErrorAction Stop
        }
    }
    Catch {
        throw $Error[0]
        Break
    }
}

# Subfunction to create SSH session if it does not already exist
Function SSHSession {
    If (!(Get-SSHSession -ComputerName $f)) {
        If ($null -eq $Credential) {
            $Credential = Get-Credential -Message "Enter SSH credentials for $f"
        }
        Try {
            New-SSHSession -ComputerName $f -Port 22 -Credential $Credential -AcceptKey -Force -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }
        Catch {
            Write-Error -Exception "SSH.Error" -Message "Cannot SSH to '$f' with username '$($Credential.UserName)'" -Category AuthenticationError
        }
    }
}

# Subfunction for determining if commands should be prefixed with 'tmsh'
Function Shell {
    Remove-Variable -Name term -Scope script -ErrorAction SilentlyContinue

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

# Results array
$Results = New-Object -TypeName System.Collections.ArrayList

# 'Main' foreach loop against F5s
Foreach ($f in $F5) {
    SSHSession
    Shell

    # Retrieve just wide IPs from F5
    $cmd = "$term list /gtm wideip a"
    $out = (Invoke-SSHCommand -SessionId (Get-SSHSession -ComputerName $f).SessionId -Command $cmd).Output | Where-Object {$_ -like "gtm wideip a * {"}

    # Seed results with F5 and wide IPs
    Foreach ($o in $out) {
        $res = "" | Select-Object F5,WideIP,Aliases,Pool-LB-Mode,Pools,Rules
        $res.F5 = $f
        $res.WideIP = $o.Replace('gtm wideip a ','').Replace(' {','')
        $Results.Add($res) | Out-Null
    }

    # Add wide IP properties to results
    foreach ($p in $Properties) {
        
        $cmd = "$term list /gtm wideip a $p"
        $out = (Invoke-SSHCommand -SessionId (Get-SSHSession -ComputerName $f).SessionId -Command $cmd).Output

        # Perform line breaking and results additions based on selected properties
        switch ($p) {

            # Wide IP aliases
            {$_ -eq 'Aliases'} {
                foreach ($o in $out) {
                    switch ($o) {
                        {$_ -like "gtm wideip a * {"} {
                            $wip = $null
                            $wip = $o.Replace('gtm wideip a ','').Replace(' {','')
                        }
                        {$_ -eq '    aliases none'} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).Aliases = 'none'
                        }
                        {$_ -eq '    aliases {'} {
                            $aliases = New-Object -TypeName System.Collections.ArrayList
                        }
                        {$_ -like "        *"} {
                            $aliases.Add($o.Replace('        ','')) | Out-Null
                        }
                        {$_ -eq '    }'} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).Aliases = $aliases
                        }
                    }
                }
            }

            # Wide IP pool load balancing mode
            {$_ -eq 'Pool-LB-Mode'} {
                foreach ($o in $out) {
                    switch ($o) {
                        {$_ -like "gtm wideip a * {"} {
                            $wip = $null
                            $wip = $o.Replace('gtm wideip a ','').Replace(' {','')
                        }
                        {$_ -like "    pool-lb-mode *"} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).'Pool-LB-Mode' = $o.Replace('    pool-lb-mode ','')
                        }
                    }
                }
            }
            
            # Wide IP pools
            {$_ -eq 'Pools'} {
                foreach ($o in $out) {
                    switch ($o) {
                        {$_ -like "gtm wideip a * {"} {
                            $wip = $null
                            $wip = $o.Replace('gtm wideip a ','').Replace(' {','')
                        }
                        {$_ -eq '    pools none'} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).Pools = 'none'
                        }
                        {$_ -eq '    pools {'} {
                            $pools = New-Object -TypeName System.Collections.ArrayList
                        }
                        {$_ -like "        * *{"} {
                            $pools.Add($o.Replace('        ','').Replace(' {','')) | Out-Null
                        }
                        {$_ -eq '    }'} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).Pools = $pools
                        }
                    }
                }
            }
            
            # Wide IP iRules
            {$_ -eq 'Rules'} {
                foreach ($o in $out) {
                    switch ($o) {
                        {$_ -like "gtm wideip a * {"} {
                            $wip = $null
                            $wip = $o.Replace('gtm wideip a ','').Replace(' {','')
                        }
                        {$_ -eq '    rules none'} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).Rules = 'none'
                        }
                        {$_ -eq '    rules {'} {
                            $rules = New-Object -TypeName System.Collections.ArrayList
                        }
                        {$_ -like "        *"} {
                            $rules.Add($o.Replace('        ','')) | Out-Null
                        }
                        {$_ -eq '    }'} {
                            ($Results | Where-Object {$_.WideIP -eq $wip -and $_.F5 -eq $f}).Rules = $rules
                        }
                    }
                }
            }
        }
    }
}
$Results

}