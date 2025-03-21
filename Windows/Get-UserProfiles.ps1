Function Get-UserProfiles {
<#
.SYNOPSIS
Retrieves user profile information for specified computer(s).

.DESCRIPTION
Retrieves user profile information for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2023.07.05 by DS :: First revision.
    V02: 2023.07.05 by DS :: Added error handling for SIDs that cannot be translated.
    V03: 2023.07.06 by DS :: Added 'LocalPath' attribute to output to assist w/ SIDs that cannot be translated.
    V04: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V05: 2023.07.24 by DS :: Updated 'Identity' parameter, no longer mandatory and default value of '$env:COMPUTERNAME`. Change 'Write-Warning' to 'Write-Error' on WMI failures.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which user profile information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-UserProfiles -ComputerName FileServer01
Will return user profile information for computer FileServer01.

.EXAMPLE
Get-UserProfiles -ComputerName FileServer01,FileServer02
Will return user profile information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-UserProfiles -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve user profile information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$false,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false,Position=1)]
    [AllowNull()]
    [pscredential]$Credential = $null,

    [Parameter(Mandatory=$false)]
    [switch]$NoProgress = $false
)

# Splat table for 'Get-WmiObject' parameters
switch ($Credential) {
    {$_ -ne $null} {
        $WmiParams = @{
	        'ComputerName' = ""
	        'Credential' = $Credential
            'Class' = 'Win32_UserProfile'
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'Win32_UserProfile'
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="UserDomain";E={$sid.Split('\')[0]}},`
        @{N="UserName";E={$sid.Split('\')[1]}},`
        @{N="LocalPath";E={$w.LocalPath}},`
        @{N="SID";E={$w.SID}}
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="UserDomain";E={[string]::new('None')}},`
        @{N="UserName";E={[string]::new('None')}},`
        @{N="LocalPath";E={[string]::new('None')}},`
        @{N="SID";E={[string]::new('None')}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="UserDomain";E={[string]::new('Error')}},`
        @{N="UserName";E={[string]::new('Error')}},`
        @{N="LocalPath";E={[string]::new('Error')}},`
        @{N="SID";E={[string]::new('Error')}}
    )
}

# Foreach loop to get WMI object from each $cn in $ComputerName
$i = 0
$WmiResults = foreach ($cn in $ComputerName) {
    If (!$NoProgress) {
        $i++
        Write-Progress "Retrieving information from $cn" -PercentComplete ($i / $ComputerName.Count * 100)
    }

    $WmiParams.ComputerName = $cn
    Try {
        $wmi = Get-WmiObject @WmiParams
        If ($wmi) {
            foreach ($w in $wmi) {
                Try {
                    $sid = (New-Object -TypeName System.Security.Principal.SecurityIdentifier($w.sid)).Translate([System.Security.Principal.NTAccount]).Value
                    $sid | Select-Object @WmiSelect
                }
                Catch [System.Management.Automation.MethodInvocationException] {
                    Write-Warning "Could not translate SID '$($w.SID)'"
                    $w | Select-Object @{N="ComputerName";E={$cn}},@{N="SID";E={$w.SID}},@{N="LocalPath";E={$w.LocalPath}}
                }
            }
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Error "'$cn' WMI connectivity failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$WmiResults

}