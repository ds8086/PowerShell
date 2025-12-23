Function Get-FolderSize {
<#
.SYNOPSIS
Calculates the total file size for the specified folder path.

.DESCRIPTION
Calculates the total file size for the specified folder path.

.NOTES
Author:
    DS
Notes:
    Revision 03
Revision
    V01: 2022.04.19 by DS :: First published and polished revision, previously a dot-slash script.
    V02: 2025.05.22 by DS :: Put on your Sunday clothes kids, we're going to GitHub!
    V03: 2025.12.22 by DS :: Line lengths. Statement capitalization.
Call From:
    PowerShell v5.1+

.PARAMETER FolderPath
The folder path for total file size calculation. The default value is the current working directory.

.EXAMPLE
Get-FolderSize -FolderPath ~\Downloads
Will retrieve the total file size of all files in the '~\Downloads' folder.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    $FolderPath = "$((Get-Location).Path)"
)

# Define what the $Results variable to return
$Results = "" | Select-Object FolderPath,FileCount,SizeMB,SizeGB

try {
    # Retrieve files (stop on first permissions error)
    $Files = Get-ChildItem $FolderPath -Recurse -Force -ErrorAction Stop |
        Where-Object {$_.PSIsContainer -ne $true}
}
catch [System.UnauthorizedAccessException] {
    Write-Warning "$($Error[0].exception)"
    Write-Warning "Results may be incomplete!"
    $Files = Get-ChildItem $FolderPath -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object {$_.PSIsContainer -ne $true}
}
finally {
    $Results.FolderPath = $FolderPath
    $Results.FileCount = $Files.Count
    $Results.SizeMB = [math]::Round( ($Files | Measure-Object -Property length -Sum).Sum / 1MB, 2 )
    $Results.SizeGB = [math]::Round( ($Files | Measure-Object -Property length -Sum).Sum / 1GB, 2 )
    $Results
}

}