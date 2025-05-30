Function Remove-F5Certificate {
<#
.SYNOPSIS
Removes specified certificate(s) and related files from specified F5.

.DESCRIPTION
Removes specified certificate(s) and related files (keys and CSRs) from specified F5.

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2023.07.06 by DS :: First iteration.
    V02: 2023.07.06 by DS :: Fixed progress bar.
    V03: 2023.07.12 by DS :: Removed '#Requires -Module Posh-SSH' (not honored in functions). Added logic for importing the module.
    V04: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V05: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V06: 2025.03.17 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name of F5 where certificate(s) and related files will be removed.

.PARAMETER Certificate
The name of the certificate(s) which will be removed.

.PARAMETER Credential
Credentials for connecting to F5.

.PARAMETER Sync
Switched parameter which, when specified performs a config sync from the specifed F5 to the group.

.EXAMPLE
Remove-F5Certificate -F5 'f5-ext-01.contoso.com' -Certificate 'website-cert'
Will remove the certificate, key, and CSR named 'website-cert' from 'f5-ext-01.contoso.com'.

.EXAMPLE
Remove-F5Certificate -F5 'f5-ext-01.contoso.com' -Certificate 'website-cert','ldap-cert'
Will remove the certificates, keys, and CSRs named 'website-cert' and 'ldap-cert' from 'f5-ext-01.contoso.com'.

.EXAMPLE
Remove-F5Certificate -F5 'f5-ext-01.contoso.com' -Certificate 'website-cert' -Sync
Will remove the certificate, key, and CSR named 'website-cert' from 'f5-ext-01.contoso.com' then sync changes from 'f5-ext-01.contoso.com' to all other devices in the sync failover group.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string]$F5,

    [Parameter(Mandatory=$True,Position=1)]
    [string[]]$Certificate,

    [Parameter(Mandatory=$False,Position=2)]
    [AllowNull()]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory=$False)]
    [switch]$Sync = $False
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

# Subfunction for creating SSH session
Function SSHSession {
    If (!(Get-SSHSession -ComputerName $F5)) {
        If ($null -eq $Credential) {
            $Credential = Get-Credential -Message "Enter SSH credentials for $F5"
        }
        New-SSHSession -ComputerName $F5 -Port 22 -Credential $Credential -AcceptKey -Force -WarningAction SilentlyContinue | Out-Null
    }
}

# Subfunction for determining if commands should be prefixed with 'tmsh'
Function Shell {
    $commands = "tmsh show /sys version","show /sys version"
    $cmdtests = foreach ($cmd in $commands) {
        $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $F5) -Command $cmd
        $ssh | Select-Object @{N="cmd";E={$cmd}},ExitStatus
    }
    If ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "tmsh *" ) {
        $script:term = "tmsh"
    }
    ElseIf ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "show *" ) {
        $script:term = $null
    }
}

# Subfunction for saving configuration
Function SaveConfig {
    $cmd = $null
    $cmd = "$term save sys config"
    Write-Host "MESSAGE: Run '$cmd' on $F5" -ForegroundColor Gray
    $ssh = $null
    $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $F5) -Command "$cmd"
    switch ($ssh.ExitStatus) {
        {$_ -eq 0} {
            Write-Verbose "Config was saved on $F5"
        }
        Default {
            Write-Warning "Config was NOT saved on $F5"
        }
    }
}

# Subfunction for performing sync failover
Function SyncFailover {
    $cmd = $null
    $cmd = "$term list /cm device-group one-line | grep 'type sync-failover'"
    
    $ssh = $null
    Write-Host "MESSAGE: Run '$cmd' on $F5" -ForegroundColor Gray
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $F5) -Command "$cmd")

    $grp = ($ssh.Output.Split('{') | Select-Object -First 1).Replace('cm device-group ','').TrimEnd(' ')

    If ($grp) {
        $cmd = $null
        $cmd = "$term run /cm config-sync to-group $grp"
        Write-Host "MESSAGE: Run '$cmd' on $F5" -ForegroundColor Gray
        Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $F5) -Command "$cmd"
    }
    Else {
        Write-Warning "$F5 is not a member of a 'sync-failover' device group"
    }
}

# Subfunction to find and remove certificate, key, and CSR
Function RemoveFiles {
    $FileTypes = "ssl-cert","ssl-key","ssl-csr"
    foreach ($file in $FileTypes) {
        $cmd = $null
        $cmd = "$term list /sys file $file $cert"

        Write-Host "MESSAGE: Run '$cmd' on $F5" -ForegroundColor Gray
        $ssh = $null
        $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $F5) -Command "$cmd"

        If ($ssh.ExitStatus -eq 0) {
            $cmd = $null
            $cmd = "$term delete /sys file $file $cert"
            Write-Host "MESSAGE: Run '$cmd' on $F5" -ForegroundColor Gray
            $ssh = $null
            $ssh = Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $F5) -Command "$cmd"
            switch ($ssh.ExitStatus) {
                {$_ -eq 0} {
                    Write-Verbose "'$cert' $file was removed from $F5"
                }
                Default {
                    Write-Warning "'$cert' $file was NOT removed from $F5"
                }
            }
        }
        Else {
            Write-Warning "'$cert' $file does not exist on $F5"
        }
    }
}

# Create SSH session and determine shell
SSHSession
Shell

# 'Main' foreach loop against values in $Certificate
$i = 0
foreach ($cert in $Certificate) {
    $i++
    Write-Progress "Processing $cert on $F5" -PercentComplete ($i / $Certificate.Count * 100)
    
    RemoveFiles
}

# Save configuration
SaveConfig

# Sync configuration if specified
If ($Sync -eq $True) {
    SyncFailover
}

}