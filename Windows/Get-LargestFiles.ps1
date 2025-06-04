Function Get-LargestFiles {
<#
.SYNOPSIS
Determines the largest files in the specified folder path.

.DESCRIPTION
Determines the largest files in the specified folder path.

.NOTES
Author:
    DS
Notes:
    Revision 01
Revision
    V01: 2025.05.22 by DS :: First published version, split from 'Get-FolderSize'.
Call From:
    PowerShell v5.1+

.PARAMETER FolderPath
The folder path to use when determining largest files. The default value is the current working directory.

.PARAMETER Top
The number of files to output in results of largest files in the specified folder path. The default value is 10.

.EXAMPLE
Get-LargestFiles -FolderPath ~\Music -Top 25
Will retrieve the top 25 largest files from the folder path ~\Music.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    $FolderPath = "$((Get-Location).Path)",

    [Parameter(Mandatory=$False,Position=1)]
    [int]$Top = 10
)

# Results splat table
$Results = @{
    'Property' = @(
        @{Name='FolderPath';E={$FolderPath}},`
        'FullName',`
        @{Name='SizeMB';E={[math]::Round($_.Length / 1MB, 2)}},`
        @{Name='SizeGB';E={[math]::Round($_.Length / 1GB, 2)}}
    )
}

Try {
    # Retrieve files (stop on first permissions error)
    $Files = Get-ChildItem $FolderPath -Recurse -Force -ErrorAction Stop | Where-Object {$_.PSIsContainer -ne $true}
}
Catch [System.UnauthorizedAccessException] {
    Write-Warning "$($Error[0].exception)"
    Write-Warning "Results may be incomplete!"
    $Files = Get-ChildItem $FolderPath -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.PSIsContainer -ne $true}
}
Finally {
    $Files | Sort-Object Length -Descending | Select-Object -First $Top @Results
}

}