#Requires -Version 7
#Requires -Module Microsoft.Graph.Authentication
Function Get-MgDeviceManagementScripts {
    <#
.SYNOPSIS
Get InTune device management scripts.

.DESCRIPTION
Get InTune device management scripts.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.04.15 by DS :: First working iteration.
Call From:
    PowerShell v7 w/ Microsoft.Graph modules

.INPUTS
None

.OUTPUTS
None

.PARAMETER FolderPath
Folder path for exporting scripts. Creates a folder in $env:TEMP by default.

.EXAMPLE
Get-MgDeviceManagementScripts.ps1
Retrieves and exports all InTune device management scripts.
#>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $False)]
        [String]$FolderPath = "$($env:TEMP)\Get-MgDeviceManagementScripts"
    )
    
    # Microsoft Graph connection    
    $Scopes = @{
        'ErrorAction' = 'Stop'
        'Scopes'      = @(
            'DeviceManagementScripts.Read.All'
        )
    }
    try {
        Write-Verbose "Connect to Microsoft graph"
        Connect-MgGraph @Scopes
    }
    catch {
        throw
    }

    # Create folder if needed
    if (!(Test-Path $FolderPath)) {
        mkdir $FolderPath | Out-Null
    }

    # MS Graph request
    $GraphUrl = "https://graph.microsoft.com/beta"
    $Response = Invoke-MgGraphRequest -Uri "$GraphUrl/deviceManagement/deviceManagementScripts" -Method GET

    foreach ($r in ($Response.value)) {

        # Individual script
        $s = $null
        $s = Invoke-MgGraphRequest -Uri "$GraphUrl/deviceManagement/deviceManagementScripts/$($r.id)" -Method GET
        
        # Script content
        $c = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($($s.scriptContent))).TrimStart('???')
        $c | Out-File -Encoding ascii -FilePath "$FolderPath\$($s.fileName)" -Force
    }

    # Open folder path in explorer
    Start-Process explorer.exe -ArgumentList $FolderPath
}