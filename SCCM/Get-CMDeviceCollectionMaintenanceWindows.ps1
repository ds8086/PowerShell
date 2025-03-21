Function Get-CMDeviceCollectionMaintenanceWindows {
<#
.SYNOPSIS
Retrieves specified SCCM device collection(s) and associated maintenance window(s).

.DESCRIPTION
Retrieves specified SCCM device collection(s) and associated maintenance window(s).

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2023.05.23 by DS :: First revision.
    V02: 2023.07.13 by DS :: Removed '#Requires -Module ConfigurationManager' (not honored in functions). Added logic for required module import.
    V03: 2023.08.02 by DS :: Updated 'Begin' block w/ new logic to handle multiple 'CMSite' PSDrives.
    V04: 2024.12.24 by DS :: Fixed issues identified by VS Code, cleaned up param block spacing.
    V05: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ConfigurationManager module.

.PARAMETER Name
Name(s) of SCCM device collections. Default value is '*' (all SCCM device collections).

.PARAMETER AllCollections
Switched parameter that specifies all SCCM device collections should be returned including those without maintenance windows.

.PARAMETER ExcludePast
Switched parameter that specifies non-reoccurring maintenance windows with dates in the past be excluded.

.EXAMPLE
Get-CMDeviceCollectionMaintenanceWindows
Will retrieve all SCCM device collections and associated maintenance windows if they exist.

.EXAMPLE
Get-CMDeviceCollectionMaintenanceWindows -Name "Windows Servers - Testing"
Will retrieve the 'Windows Servers - Testing' SCCM device collection and associated maintenance windows if they exist.

.EXAMPLE
Get-CMDeviceCollectionMaintenanceWindows -Name "Windows Servers - *"
Will retrieve SCCM device collections matching the name 'Windows Servers - *' and associated maintenance windows if they exist.
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Parameter(Mandatory=$False,ValueFromPipeline=$true,Position=0)]
    [string]$Name = "*",

    [Parameter(Mandatory=$False)]
    [switch]$AllCollections = $False,

    [Parameter(Mandatory=$False)]
    [switch]$ExcludePast = $False
)

Begin {

# Define and import required modules
$RequiredModules = "ConfigurationManager"
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

# Not connected to a configuration manager site via PowerShell
$CMSite = Get-PSDrive -PSProvider CMSite -ErrorAction SilentlyContinue
If (!($CMSite)) {
    Write-Host "FAILURE: Not currently connected to CMSite!" -ForegroundColor Red
    Write-Warning "See 'https://learn.microsoft.com/en-us/powershell/sccm/overview?view=sccm-ps' for help connecting to SCCM via PowerShell."
    Break
}
Else {
    Set-Location "$($($CMSite | Select-Object -First 1).Name):\"
}

} # Begin

Process {

# Splat table for 'Get-CMCollection' parameters
$CcmParams = @{
    'CollectionType' = 'Device'
    'Name' = $Name
}

# Splat table for 'Select-Object' (success w/ data)
$CcmSelect = @{ 
    'Property' = @(
        @{N="CollectionID";E={$dc.CollectionID}},`
        @{N="CollectionName";E={$dc.Name}},`
        'Name',`
        'IsEnabled',`
        'Description',`
        @{N="Recurrence";E={
            switch ($_.RecurrenceType) {
                1 {[String]::new("None")}
                2 {[String]::new("Daily")}
                3 {[String]::new("Weekly")}
                4 {[String]::new("MonthlyByWeekDay")}
                5 {[String]::new("MonthlyByDate")}
            }
        }},`
        'StartTime',`
        @{N="InPast";E={If ($(($_.StartTime).AddMinutes($_.Duration) -lt $Date) -and $_.RecurrenceType -eq 1) {$True} Else {$False} }},`
        'Duration'
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property' = @(
        @{N="CollectionID";E={$dc.CollectionID}},`
        @{N="CollectionName";E={$dc.Name}},`
        @{N="Name";E={[string]::new("None")}},`
        @{N="IsEnabled";E={[string]::new("None")}},`
        @{N="Description";E={[string]::new("None")}},`
        @{N="RecurrenceType";E={[string]::new("None")}},`
        @{N="StartTime";E={[string]::new("None")}},`
        @{N="InPast";E={[string]::new("None")}},`
        @{N="Duration";E={[string]::new("None")}}
    )
}

# Retrieve SCCM device collection(s)
Write-Verbose "Retrieving SCCM device collections matching name '$Name'"
$DeviceCollections = Get-CMCollection @CcmParams

# Retreive SCCM maintenance windows (if they exist) for specified device collection(s)
$i = 0
If ($DeviceCollections) {
    $Date = Get-Date
    $MaintenanceWindows = foreach ($dc in $DeviceCollections) {
        $i++
        Write-Progress "Retrieving maintenance windows for $($dc.Name)" -PercentComplete ($i / $DeviceCollections.Count * 100)

        $mw = $null
        $mw = $dc | Get-CMMaintenanceWindow
    
        If ($mw) {
            foreach ($_ in $mw) {
                $_ | Select-Object @CcmSelect
            }
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
}

# No SCCM device collection(s) match $Name
Else {
    Write-Warning "'$Name' does not match any SCCM device collection names"
}

} # Process

End {
    If ($AllCollections -eq $False) {
        $MaintenanceWindows = $MaintenanceWindows | Where-Object {$_.Name -ne "None"}
    }
    If ($ExcludePast -eq $True) {
        $MaintenanceWindows = $MaintenanceWindows | Where-Object {$_.InPast -ne $True}
    }
    
    If ($MaintenanceWindows) {
        $MaintenanceWindows
    }
    Else {
        Write-Warning "No SCCM device collections match specified criteria"
    }
}

}