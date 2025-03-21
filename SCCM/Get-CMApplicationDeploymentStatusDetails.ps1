Function Get-CMApplicationDeploymentStatusDetails {
<#
.SYNOPSIS
Retrieves SCCM application deployment host level statuses.

.DESCRIPTION
Retrieves SCCM application deployment host level statuses.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2024.09.03 by DS :: First revision.
    V02: 2024.09.06 by DS :: Minor overhaul for efficency (retrieve app deployments rather than collections).
    V03: 2024.12.24 by DS :: Fixed issues identified by VS Code.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 w/ ConfigurationManager module

.PARAMETER Collection
The SCCM collection name(s) included in the status detail output. Default value is '*' (all). Accepts wildcards.

.PARAMETER Application
The SCCM application name(s) included in status detail output. Default value is '*' (all). Accepts wildcards.

.PARAMETER IncludeDisabled
Switched parameter, when specified includes application deployments which are disabled.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$Application = "*",

    [Parameter(Mandatory=$False,Position=1)]
    [string]$Collection = "*",

    [Parameter(Mandatory=$False)]
    [switch]$IncludeDisabled = $False
)


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

# Check for connection to SCCM instance via PowerShell
If (!(Get-PSDrive | Where-Object {$_.Provider.Name -eq 'CMSite'})) {
    Write-Warning "Not connected to an SCCM instance via PowerShell, exiting"
    Write-Host "MESSAGE: See 'https://learn.microsoft.com/en-us/powershell/sccm/overview?view=sccm-ps' for info on connecting to SCCM via PowerShell" -ForegroundColor Gray
    Break
}

# Ensure the application(s) exists
If (!(Get-CMApplication -Name $Application)) {
    Write-Warning "No application matching name '$Application' found"
    Break
}

# Retrieve application deployments filtering for only enabled unless '-IncludeDisabled' is specified
$CM_Deployments = Get-CMApplicationDeployment -Name $Application | Where-Object {$_.CollectionName -like "$Collection"}
If ($IncludeDisabled -eq $False) {
    $CM_Deployments = $CM_Deployments | Where-Object {$_.Enabled -eq $True}
}

# Ensure the application(s) is deployed
If (!($CM_Deployments)) {
    Write-Warning "Application deployment(s) for '$Application' targeting collection(s) '$Collection' not found!"
    Break
}

# Retrieve deployment status(es)
$i = 0
$Deployment_Status = Foreach ($cd in $CM_Deployments) {
    Try {
        $i++
        Write-Progress "Processing application '$($cd.ApplicationName)'" -PercentComplete ($i / $CM_Deployments.Count * 100) 
    }
    Catch {}

    $cd | Get-CMApplicationDeploymentStatus
}

# Splat table for 'Select-Object' below
$Select_Params = @{
    'Property' = @(
        'MachineName',
        'CollectionName',
        'AppName',
        @{N='DeploymentType';E={$_.DTName}},`
        @{N='StatusType';E={
            switch ($_.StatusType) {
                1 {'Success'}
                2 {'InProgress'}
                3 {'RequirementsNotMet'}
                4 {'Unknown'}
                5 {'Error'}
            }
        }},`
        @{N='Status';E={
            switch ($_.EnforcementState) {
                5000 { 'Deployment failed' }
                5001 { 'Evaluation failed' }
                5002 { 'Deployment failed' }
                5003 { 'Failed to locate content' }
                5004 { 'Dependency installation failed' }
                5005 { 'Failed to download dependent content' }
                5006 { 'Conflicts with another application deployment' }
                5007 { 'Waiting Retry' }
                5008 { 'Failed to uninstall superseded deployment type' }
                5009 { 'Failed to download superseded deployment type' }
            }
        }}
    )
}

# Retrieve deployment status detail(s)
$i = 0
$Host_Status = foreach ($ds in $Deployment_Status)  {
    Try {
        $i++
        Write-Progress "Processing '$($ds.AppName)' deployed to collection '$($ds.CollectionName)'" -PercentComplete ($i / $Deployment_Status.Count * 100) 
    }
    Catch {}   

    Get-CMDeploymentStatusDetails -InputObject $ds | Select-Object @Select_Params
}
$Host_Status

}