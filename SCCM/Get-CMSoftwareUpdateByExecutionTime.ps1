Function Get-CMSoftwareUpdateByExecutionTime {
<#
.SYNOPSIS
Retrieves SCCM software updates with an execution time greater than or equal to the specified time in minutes.

.DESCRIPTION
Retrieves SCCM software updates with an execution time greater than or equal to the specified time in minutes.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2023.08.02 by DS :: First (complete) revision
    V02: 2024.12.24 by DS :: Fixed issues identified by VS Code, cleaned up param block spacing.
    V03: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ConfigurationManager module.

.PARAMETER CategoryName
The category name(s) of updates which will be displayed. By default 'Critical Updates', 'Definition Updates', 'Security updates', 'Update Rollups', and 'Updates' are returned.

.PARAMETER ExecutionTime
The minimum execution time (in minutes) of updates which will be displayed. The default value is 120 minutes which is the default for all 'new' updates synchronized from Microsoft Update.

.PARAMETER AllCategories
Switched parameter which, when specified, displays updates from all categories. 

.EXAMPLE
Get-CMSoftwareUpdateByExecutionTime
Will retrieve and display all updates classified as 'Critical Updates', 'Definition Updates', 'Security updates', 'Update Rollups', or 'Updates' with an execution time of at least 120 minutes.

.EXAMPLE
Get-CMSoftwareUpdateByExecutionTime -CategoryName 'Feature Packs' -ExecutionTime 60
Will retrieve and display all Feature Pack updates with an execution time of at least 60 minutes.

.EXAMPLE
Get-CMSoftwareUpdateByExecutionTime -AllCategories -ExecutionTime 90
Will retrieve and display all updates, regardless of category, with an execution time of at least 90 minutes.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
	[AllowNull()]
	[ValidateSet("Critical Updates","Definition Updates","Feature Packs","Security Updates","Update Rollups","Updates")]
    [string[]]$CategoryName = @("Critical Updates","Definition Updates","Security Updates","Update Rollups","Updates"),

    [Parameter(Mandatory=$False,Position=1)]
    [int]$ExecutionTime = 120,

    [Parameter(Mandatory=$False)]
    [switch]$AllCategories = $False
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

# Create $CcmParams splat table based on if '-AllCategories' switch is used
switch ($AllCategories) {
    {$_ -eq $True} {
        $CcmParams = @{
            'IsDeployed' = $True
            'Fast' = $True
        }
    }
    {$_ -eq $False} {
        $CcmParams = @{
            'IsDeployed' = $True
            'Fast' = $True
            'CategoryName' = $CategoryName
        }
    }
}

# Splat table for 'Select-Object'
$CcmSelect = @{
    'Property' = @('CI_ID','ArticleID','LocalizedDisplayName','IsSuperseded','IsExpired','NumMissing',@{N="MaxExecutionTimeMin";E={$_.MaxExecutionTime / 60}})
}

# Retrieve updates which match criteria
$Updates = Get-CMSoftwareUpdate @CcmParams | Where-Object {$_.NumMissing -gt 0 -and ($_.MaxExecutionTime -ge [timespan]::FromMinutes($ExecutionTime).TotalSeconds)}

} # Process

End {

# Output results if they exist
If ($Updates) {
    $Updates | Select-Object @CcmSelect
}
Else {
    Write-Host "MESSSAGE: No SCCM software updates match the provided criteria" -ForegroundColor Gray
}

} # End

}