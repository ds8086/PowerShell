Function Get-F5OutboundSmtp {
<#
.SYNOPSIS
Retrieves outbound SMTP config for specified F5(s).

.DESCRIPTION
Retrieves outbound SMTP config for specified F5(s).

.NOTES
Author: 
    DS
Notes:
    Revision 1
Revision:
    V01: 2025.03.02 by DS :: First revision.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH

.PARAMETER F5
The name(s) of F5(s) for which outbound SMTP info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.EXAMPLE
Get-F5OutboundSmtp -F5 'f5-ext-01.contoso.com'
Will retrieve F5 outbound SMTP info for 'f5-ext-01.contoso.com'.

.EXAMPLE
$F5Creds = Get-Credential; Get-F5OutboundSmtp -F5 'f5-ext-01.contoso.com' -Credential $F5Creds
Will prompt for and store credentials in variable $F5Creds. Will retrieve F5 outbound smtp info for 'f5-ext-01.contoso.com' using the credentials stored in $F5Creds.
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
Function GetShell {

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
foreach ($f in $F5s) {
    
    $i++
    Try {
        Write-Progress "Retrieving outbound SMTP info from '$f'" -PercentComplete $($i / $F5.Count * 100)
    }
    Catch {}

    # Create SSH session
    SSHSession
    
    # Determine shell
    $shell = $null
    $shell = GetShell

    # Define command based on shell
    switch ($shell) {
        'bash' {
            $cmd = 'tmsh list /sys outbound-smtp all-properties'
        }
        'tmsh' {
            $cmd = 'list /sys outbound-smtp all-properties'
        }
    }

    # Invoke SSH command
    $ssh = Invoke-SSHCommand -Command $cmd -SSHSession (Get-SSHSession -ComputerName $f)

    # Build indivdual result from SSH command output
    If ($ssh.ExitStatus -eq 0) {
        $out = $ssh.Output

        foreach ($o in $out) {
            switch ($o) {
                {$_ -eq 'sys outbound-smtp {'} {
                    $res = "" | Select-Object F5,description,from-line-override,mailhub,rewrite-domain
                    $res.F5 = $f
                }
                {$_ -like "    description *"} {
                    $res.description = $_.Replace('    description ','')
                }
                {$_ -like "    from-line-override *"} {
                    $res.'from-line-override' = $_.Replace('    from-line-override ','')
                }
                {$_ -like "    mailhub *"} {
                    $res.'mailhub' = $_.Replace('    mailhub ','')
                }
                {$_ -like "    rewrite-domain *"} {
                    $res.'rewrite-domain' = $_.Replace('    rewrite-domain ','')
                }
                {$_ -eq '}'} {
                    $Results.Add($res) | Out-Null
                }
            }
        }
    }
    Else {
        Write-Warning "Execution of '$cmd' on '$f' was not successful!"
    }
}

$Results

}