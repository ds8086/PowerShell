Function Get-F5LTMObjectStatus {
<#
.SYNOPSIS
Retrieves status of F5 LTM objects.

.DESCRIPTION
Retrieves status of specified F5 LTM objects. Parameters can be used to filter the types of objects and states which are returned.

.NOTES
Author: 
    DS
Notes:
    Revision 07
Revision:
    V01: 2023.05.25 by DS :: First revision.
    V02: 2023.06.01 by DS :: Added '#Requires -Module Posh-SSH'. Fixed issue with some output having trailing spaces.
    V03: 2023.07.03 by DS :: Removed 'ValueFromPipeline=$True' from $F5 parameter. Cleaned up spacing.
    V04: 2023.07.12 by DS :: Removed '#Requires -Module Posh-SSH' (not honored in functions). Added logic for importing the module.
    V05: 2024.06.12 by DS :: Added '%' attribute to output if '-IncludePoolMemberCounts' is specified.
    V06: 2024.07.10 by DS :: Added 'shell' subfunction for determining if SSH commands should be prefixed with 'tmsh' or not.
    V07: 2025.03.17 by DS :: Updated comments and spacing. Fixed 'problems' reported by VS code.
Call From:
    PowerShell v5.1 or higher w/ Posh-SSH module

.PARAMETER F5
The name(s) of F5(s) from which LTM object status info will be retrieved.

.PARAMETER Credential
Credentials for connecting to F5(s).

.PARAMETER Object
The LTM object(s) to return. Valid values are 'virtual', 'pool', and 'node'. All objects are returned by default.

.PARAMETER Availability
The LTM availability state to return. Valid values are 'available', 'offline', 'unknown', and '*' (all). All availability states are returned by default.

.PARAMETER State
The LTM object state to return. Valid values are 'enabled', 'disabled', and '*' (all). All states are returned by default.

.PARAMETER IncludePoolMemberCounts
Switched parameter which specifies that pool member counts be returned. This only matters if 'pool' is included when '-Object' is specified.

.EXAMPLE
Get-F5LTMObjectStatus -F5 'f5-ext-01.contoso.com'
Will retrieve F5 LTM object status for all virtual servers, pools, and nodes from 'f5-ext-01.contoso.com'.

.EXAMPLE
Get-F5LTMObjectStatus -F5 'f5-ext-01.contoso.com' -Availability available -Object virtual
Will retrieve F5 LTM object status for all virtual servers with an availability state of 'available' from 'f5-ext-01.contoso.com'.

.EXAMPLE
Get-F5LTMObjectStatus -F5 'f5-ext-01.contoso.com' -Object pool -IncludePoolMemberCounts
Will retrieve F5 LTM object status for all pools from 'f5-ext-01.contoso.com'. Pool member counts, both total and available will be included in results.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string[]]$F5,

    [Parameter(Mandatory=$False,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory=$False,Position=2)]
    [ValidateSet("Virtual", "Pool", "Node")]
    [string[]]$Object = @("Virtual", "Pool", "Node"),

    [Parameter(Mandatory=$False,Position=3)]
    [ValidateSet("available","offline","unknown","*")]
    [string]$Availability = "*",

    [Parameter(Mandatory=$False,Position=4)]
    [ValidateSet("enabled","disabled","*")]
    [string]$State = "*",

    [Parameter(Mandatory=$False)]
    [switch]$IncludePoolMemberCounts = $False
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

# Subfunction for determining if SSH commands should be prefixed with 'tmsh'
Function shell {
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

# Subfunctions for LTM objects. (This will be a single function at some point)
Function pool {
    
    $results = New-Object -TypeName System.Collections.ArrayList
    
    $cmd = "$term show ltm pool"
    
    $out = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command $cmd).Output | Where-Object { `
        $_ -like "Ltm::*: *" -or `
        $_ -like "  Availability*: *" -or `
        $_ -like "  State*: *" -or `
        $_ -like "  Reason*: *" -or `
        $_ -like "  Available Members*: *" -or `
        $_ -like "  Total Members*: *"
    }

    foreach ($o in $out) {
    
        switch ($o) {
            {$_ -like "Ltm::*: *"} {
                $res = "" | Select-Object F5,Object,Name,Availability,State,Reason,AvailableMembers,TotalMembers,%
                $res.F5 = $f
                $res.Object = $o.Replace('Ltm::','').Split(':')[0]
                $res.Name = $o.Replace('Ltm::','').Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Availability*: *"} {
                $res.Availability = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  State*: *"} {
                $res.State = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Reason*: *"} {
                $res.Reason = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Available Members*: *"} {
                $res.AvailableMembers = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Total Members*: *"} {
                $res.TotalMembers = $o.Split(':')[1].TrimStart().TrimEnd()
                Try {
                    $res.'%' = [math]::Round($res.AvailableMembers / $res.TotalMembers * 100,2)
                }
                Catch [System.Management.Automation.RuntimeException] {
                    $res.'%' = 0
                }

                $results.Add($res) | Out-Null
            }
        }
    }

    $results
}
Function virtual {
    
    $results = New-Object -TypeName System.Collections.ArrayList
    
    $cmd = "$term show ltm virtual"
    
    $out = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command $cmd).Output | Where-Object { `
        $_ -like "Ltm::*: *" -or `
        $_ -like "  Availability*: *" -or `
        $_ -like "  State*: *" -or `
        $_ -like "  Reason*: *" -or `
        $_ -like "  Available Members*: *" -or `
        $_ -like "  Total Members*: *"
    }

    foreach ($o in $out) {
    
        switch ($o) {
            {$_ -like "Ltm::*: *"} {
                $res = "" | Select-Object F5,Object,Name,Availability,State,Reason,AvailableMembers,TotalMembers,%
                $res.F5 = $f
                $res.Object = $o.Replace('Ltm::','').Split(':')[0]
                $res.Name = $o.Replace('Ltm::','').Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Availability*: *"} {
                $res.Availability = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  State*: *"} {
                $res.State = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Reason*: *"} {
                $res.Reason = $o.Split(':')[1].TrimStart().TrimEnd()
                $results.Add($res) | Out-Null
            }
        }
    }

    $results
}
Function node {
    
    $results = New-Object -TypeName System.Collections.ArrayList
    
    $cmd = "$term show ltm node"
    
    $out = (Invoke-SSHCommand -SSHSession (Get-SSHSession -ComputerName $f) -Command $cmd).Output | Where-Object { `
        $_ -like "Ltm::*: *" -or `
        $_ -like "  Availability*: *" -or `
        $_ -like "  State*: *" -or `
        $_ -like "  Reason*: *" -or `
        $_ -like "  Available Members*: *" -or `
        $_ -like "  Total Members*: *"
    }

    foreach ($o in $out) {
    
        switch ($o) {
            {$_ -like "Ltm::*: *"} {
                $res = "" | Select-Object F5,Object,Name,Availability,State,Reason,AvailableMembers,TotalMembers,%
                $res.F5 = $f
                $res.Object = $o.Replace('Ltm::','').Split(':')[0]
                $res.Name = $o.Replace('Ltm::','').Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Availability*: *"} {
                $res.Availability = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  State*: *"} {
                $res.State = $o.Split(':')[1].TrimStart().TrimEnd()
            }
            {$_ -like "  Reason*: *"} {
                $res.Reason = $o.Split(':')[1].TrimStart().TrimEnd()
                $results.Add($res) | Out-Null
            }
        }
    }

    $results
}

# Splat table for 'Select-Object' in the main foreach loop
switch ($IncludePoolMemberCounts) {
    {$_ -eq $True} {
        $DataSelect = @{
            'Property' = @('F5','Object','Name','Availability','State','Reason','AvailableMembers','TotalMembers','%')
        }
    }
    {$_ -eq $False} {
        $DataSelect = @{
            'Property' = @('F5','Object','Name','Availability','State','Reason')
        }
    }
}

# 'Main' foreach loop for retrieving F5 LTM objects from each F5
$i = 0
foreach ($f in $F5) {
    $i++
    Write-Progress "Retrieving LTM object(s) from $f" -PercentComplete ($i / $F5.Count * 100) -Id 1

    SSHSession
    shell
        
    $ii = 0
    foreach ($obj in $Object) {
        $ii++
        Write-Progress "Retrieving object type: '$obj'" -PercentComplete ($ii / $Object.Count * 100) -ParentId 1

        & $obj | Where-Object {$_.Availability -like $Availability -and $_.State -like $State} | Select-Object @DataSelect
    }
}

}