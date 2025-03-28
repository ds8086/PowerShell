Function Get-F5Certificates {
<#
.SYNOPSIS
Retrieves SSL traffic certificates from specified F5(s).

.DESCRIPTION
Retrieves SSL traffic certificates from specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2023.06.27 by DS :: First revision.
    V02: 2023.07.03 by DS :: Removed 'ValueFromPipeline=$True' from $F5 parameter. Cleaned up spacing.
    V03: 2023.07.12 by DS :: Removed '#Requires -Module Posh-SSH' (not honored in functions). Added logic for importing the module.
    V04: 2024.07.17 by DS :: Added 'Shell' subfunction and updated invoked SSH commands to account for non-bash shell users.
    V05: 2024.12.23 by DS :: Fixed 'problems' reported by VS code.
    V06: 2025.03.17 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) for which hardware and version info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5Certificates -F5 'f5-ext-01.contoso.com'
Will retrieve F5 SSL traffic certificates from 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5Certificates -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve F5 SSL traffic certificates from 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
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

# Date variable to determining status of certificates
$Date = Get-Date

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

# Subfunction to retrieve cert info
Function CertInfo {
    
    # TMSH command: list traffic certificates
    $cmd = $null
    $cmd = "$term list sys file ssl-cert"

    # Invoke TMSH command via SSH
    $ssh = $null
    $ssh = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command "$cmd")

    # Output from SSH command above
    $Output = $ssh.Output | Where-Object {$_ -like "sys file ssl-cert *" -or $_ -like "    subject *" -or $_ -like "    issuer *" -or $_ -like "    expiration-date *"}

    foreach ($o in $Output) {
        switch ($o) {
            {$_ -like "sys file ssl-cert *"} {
                $res = "" | Select-Object F5,Certificate,Subject,Issuer,Expiration,Status
                $res.F5 = $f
                $res.Certificate = $_.Replace('sys file ssl-cert ','').Replace(' {','')
            }
            {$_ -like "    subject *"} {
                $res.Subject = $_.Replace('    subject ','').TrimStart('"').TrimEnd('"')
            }
            {$_ -like "    issuer *"} {
                $res.Issuer = $_.Replace('    issuer ','').TrimStart('"').TrimEnd('"')
            }
            {$_ -like "    expiration-date *"} {
                $res.Expiration = (([System.DateTimeOffset]::FromUnixTimeSeconds($($_.Replace('    expiration-date ','')))).DateTime)
                switch ($res) {
                    {$res.Expiration -gt $Date.AddDays(60)} {
                        $res.Status = "SUCCESS"
                    }
                    {($res.Expiration -lt $Date.AddDays(60)) -and ($res.Expiration -gt $Date.AddDays(14))} {
                        $res.Status = "WARNING"
                    }
                    {$res.Expiration -lt $Date.AddDays(14)} {
                        $res.Status = "CRITICAL"
                    }
                    {$res.Expiration -lt $Date} {
                        $res.Status = "EXPIRED"
                    }
                }
                $Results.Add($res) | Out-Null
            }
        }
    }
}

# Results array
$Results = New-Object -TypeName System.Collections.ArrayList

# Main foreach loop to run subfunctions on F5(s)
$i = 0
foreach ($f in $F5) {
    
    $i++
    Try {
        Write-Progress "Gathering traffic certificates from '$f'" -PercentComplete $($i / $F5.Count * 100)
    }
    Catch {}

    SSHSession
    Shell
    CertInfo
}

# Output results
$Results

}