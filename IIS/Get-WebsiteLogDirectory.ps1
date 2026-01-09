Function Get-WebsiteLogDirectory {
<#
.SYNOPSIS
Retrieve website(s) and their corresponding log directory.

.DESCRIPTION
Retrieve website(s) and their corresponding log directory.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2022.05.23 by DS :: First revision.
    V02: 2026.01.08 by DS :: Revamp for GitHub.
Call From:
    Windows PowerShell v5.1 or higher with WebAdministration module

.INPUTS
None

.OUTPUTS
None

.EXAMPLE
Get-WebsiteLogDirectory
Retrieve website(s) and their corresponding log directory.
#>

[CmdletBinding()]
param ()

# Define and import required modules
$RequiredModules = "WebAdministration"
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

$Websites = Get-Website
if ($Websites) {
    $Websites | Select-Object @{N="PSComputerName";E={$env:COMPUTERNAME}},
        name,
        id,
        state,
        physicalPath,
        @{N="logs";E={($_.logfile.directory).Replace('%SystemDrive%',$env:SystemDrive) + "\w3svc" + $_.id}}
}
else {
    Write-Warning "No websites found on $env:COMPUTERNAME"
    "" | Select-Object @{N="PSComputerName";E={$env:COMPUTERNAME}},
        @{N="name";E={[string]::new("No websites")}},    
        @{N="id";E={[string]::new("No websites")}},
        @{N="state";E={[string]::new("No websites")}},
        @{N="physicalPath";E={[string]::new("No websites")}},
        @{N="logs";E={[string]::new("No websites")}}
}

}