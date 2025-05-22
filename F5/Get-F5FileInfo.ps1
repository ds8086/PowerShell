Function Get-F5FileInfo {
<#
.SYNOPSIS
Determine file info for a specified file on F5(s).

.DESCRIPTION
Determine file info for a specified file on F5(s). Useful for determining if there are synchronization issues between F5s in a GTM mesh.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2025.02.20 by DS :: First revision.
    V02: 2025.05.22 by DS :: Updated for GitHub.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module.

.PARAMETER F5
The name(s) of F5(s) for which file info will be retrieved.

.PARAMETER File
The path of the F5 file.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5FileInfo -F5 'f5-ext-01.contoso.com' -File '/config/bigip.conf'
Will retrieve file info for '/config/bigip.conf' from F5 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5FileInfo -F5 'f5-ext-01.contoso.com' -File '/config/bigip.conf'
Will prompt for and store credentials in variable $F5Creds. Will retrieve file info for '/config/bigip.conf' from F5 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.

.EXAMPLE
Get-F5FileInfo -F5 'f5-ext-01.contoso.com','f5-ext-02.contoso.com' -File '/config/bigip_gtm.conf'
Will retrieve file info for '/config/bigip_gtm.conf' from F5 'f5-ext-01.contoso.com' and 'f5-ext-02.contoso.com'.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string[]]$F5,

    [Parameter(Mandatory=$False,Position=1)]
    [string]$File = '/config/bigip.conf',

    [Parameter(Mandatory=$False,Position=2)]
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

# Results array
$Results = New-Object -TypeName System.Collections.ArrayList

# 'Main' foreach loop against F5s
$i = 0
foreach ($f in $F5) {
    $i++
    Write-Progress "Processing $f" -PercentComplete ($i / $F5.Count * 100)

    # Create SSH session and determine shell
    SSHSession
    $shell = $null
    $shell = GetShell

    # Individual result set for loop iteration
    $res = "" | Select-Object F5,File,Size,Modified,ShaSum
    $res.F5 = $f
    $res.File = $File

    # Size and modified date for file
    switch ($shell) {
        'bash' {
            $cmd = "ls -l $File | awk '{print `$5,`$6,`$7,`$8}'"
        }
        'tmsh' {
            $cmd = "bash -c `"ls -l $File | awk '{print `$5,`$6,`$7,`$8}'`""
        }
    }
    $ssh = Invoke-SSHCommand -Command $cmd -SSHSession (Get-SSHSession -ComputerName $f)
    If ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output.Split(' ')
        $res.Size = $out[0]
        $res.Modified = "$($out[1]) $($out[2]) $($out[3])"
    }
    Else {
        $res.Size = [string]::new('Error')
        $res.Modified = [string]::new('Error')
    }

    # Shasum (hash) for file
    switch ($shell) {
        'bash' {
            $cmd = "shasum $File"
        }
        'tmsh' {
            $cmd = "bash shasum $File"
        }
    }
    $ssh = Invoke-SSHCommand -Command $cmd -SSHSession (Get-SSHSession -ComputerName $f)
    If ($ssh.ExitStatus -eq 0) {
        $res.ShaSum = $ssh.Output.Split(' ') | Select-Object -First 1
    }
    Else {
        $res.ShaSum = [string]::new('Error')
    }

    # Add $res to $Results
    $Results.Add($res) | Out-Null
}

# Output results
$Results
}