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
    Revision 03
Revision:
    V01: 2025.02.20 by DS :: First revision.
    V02: 2025.05.22 by DS :: Updated for GitHub.
    V03: 2025.12.11 by DS :: Cleaned up header and statement capitalization. Minor change to required modules.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module.

.INPUTS
None

.OUTPUTS
None

.PARAMETER F5
The name(s) of F5(s) for which file info will be retrieved.

.PARAMETER File
The path of the F5 file.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5FileInfo -F5 'f5-ext-01.contoso.com' -File '/config/bigip.conf'
Retrieves file info for '/config/bigip.conf' from F5 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5FileInfo -F5 'f5-ext-01.contoso.com' -File '/config/bigip.conf'
Using credentials in variable $F5Creds, retrieves file info for '/config/bigip.conf' from F5 'f5-ext-01.contoso.com'.

.EXAMPLE
Get-F5FileInfo -F5 'f5-ext-01.contoso.com','f5-ext-02.contoso.com' -File '/config/bigip_gtm.conf'
Retrieves file info for '/config/bigip_gtm.conf' from F5 'f5-ext-01.contoso.com' and 'f5-ext-02.contoso.com'.
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
        try {
            New-SSHSession -ComputerName $f -Port 22 -Credential $Credential -AcceptKey -Force -WarningAction SilentlyContinue -ErrorAction Stop | Out-Null
        }
        catch {
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
    if ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "tmsh *" ) {
        return "bash"
    }
    elseif ( ($cmdtests | Where-Object {$_.ExitStatus -eq 0}).cmd -like "show *" ) {
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
    if ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output.Split(' ')
        $res.Size = $out[0]
        $res.Modified = "$($out[1]) $($out[2]) $($out[3])"
    }
    else {
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
    if ($ssh.ExitStatus -eq 0) {
        $res.ShaSum = $ssh.Output.Split(' ') | Select-Object -First 1
    }
    else {
        $res.ShaSum = [string]::new('Error')
    }

    # Add $res to $Results
    $Results.Add($res) | Out-Null
}

# Output results
$Results
}