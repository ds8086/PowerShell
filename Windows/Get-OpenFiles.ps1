Function Get-OpenFiles {
<#
.SYNOPSIS
Retrieves and optionally closes open shared file(s) on a specified server.

.DESCRIPTION
Retrieves and optionally closes open shared file(s) on a specified server. All open shared files are returned by default, results can be refined by searching for a file name or user name.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2022.09.09 by DS :: First revision.
    V02: 2023.08.01 by DS :: Minor rewrite, too many changes to list.
    V03: 2023.08.03 by DS :: Updated variable names, output, and script header.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER Server
The hostname/FQDN of the server which will be searched for open shared files

.PARAMETER File
Optional parameter to refine results by file name. Wildcards (*) accepted and automatically appeneded to beginning of name specified in File.

.PARAMETER User
Optional parameter to refine results by user who has file(s) open. If Specified, is used in conjuction with the File parameter via the AND operator.

.EXAMPLE
Get-OpenFiles -Server 'FileServer01.contoso.com' -OpenFile 'Yearlybudget.xlsx'
Searches the server 'FileServer01.contoso.com' for any open shared files with a file name like 'Yearlybudget.xlsx', displays results (if any) and prompts for File ID(s) corresponding to files which need to be closed.

.EXAMPLE
Get-OpenFiles -Server 'FileServer01.contoso.com' -OpenFile 'Yearlybudget.xlsx' -AccessedBy 'JKirk'
Searches the server 'FileServer01.contoso.com' for any open shared files with a file name like 'Yearlybudget.xlsx' accessed by user 'JKirk', displays results (if any) and prompts for File ID(s) corresponding to files which need to be closed.

.EXAMPLE
Get-OpenFiles -Server 'FileServer01.contoso.com' -User 'AccessedBy'
Searches the server 'FileServer01.contoso.com' for any open shared files accessed by user 'JKirk', displays results (if any) and prompts for File ID(s) corresponding to files which need to be closed.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [string]$Server,

    [Parameter(Mandatory=$False,Position=1)]
    [Alias('File')]
    [string]$OpenFile = "*",

    [Parameter(Mandatory=$False,Position=2)]
    [Alias('User','Username')]
    [string]$AccessedBy = "*"
)

# Determine open files on $Server
$Open = openfiles.exe /query /s $Server /fo CSV /nh
If ($Open -like "*INFO: No shared open files found.*") {
    Write-Host "MESSAGE: Successfully queried open shared files on '$Server' and found none" -ForegroundColor Gray
    Break
}
Else {
    Try {
        $Format = ConvertFrom-Csv -InputObject $Open -Delimiter "," -Header "ID","AccessedBy","Type","OpenFile" -ErrorAction Stop
        $Format = $Format | Select-Object @{Name="Server";Expression={$Server}},ID,AccessedBy,Type,OpenFile
    }
    Catch {
        Write-Host "FAILURE: Unable to query open shared files on '$Server'. Please ensure that '$Server' is a valid hostname/FDQN and reachable on the network" -ForegroundColor Red
        Break
    }
}

# Determine $Matches
$Matches = $Format | Where-Object {$_.OpenFile -like "$OpenFile" -and $_.AccessedBy -like "$AccessedBy"}

# At least one open file matches file/user query
If ($Matches) {

    # Output open files as a table
    $Matches | Format-Table -Wrap

    # $IDs variable to hold file IDs which will be closed
    $IDs = New-Object -TypeName System.Collections.ArrayList

    # Prompt user for file IDs to close until a blank entry is input
    Do {
        $i = $null
        $i = Read-Host "File ID to close (Blank to exit)"
        If ($i.Length -gt 0) {
            $IDs.Add($i) | Out-Null
        }
    }
    Until (
        $i.Length -eq 0    
    )

    # User entered at least one open file ID to close
    If ($IDs) {
        
        # User has invoked the (undocumented) 'ALL' option
        If ($IDs.Count -eq 1 -and $IDs -eq "ALL") {
            
            # Warn user that all open files matching critera will be closed, prompt for confirmation
            Write-Warning "You have typed 'ALL' This will close all open shared files listed above!"
            Do {
                $conf = Read-Host "Confirm closing all open files listed above (YES/NO)"
            }
            Until (
                $conf -eq "NO" -or $conf -eq "YES"
            )

            # User typed 'NO' at confirmation prompt
            If ($conf -eq "NO") {
                Write-Host "MESSAGE: Exiting without closing any open shared files" -ForegroundColor Gray
            }

            # User typed 'YES' at confirmation prompt
            ElseIf ($conf -eq "YES") {
                
                # There are more than 10 open files which match query criteria, do not close files, inform user of built-in safety check
                If ($Matches.Count -gt 10) {
                    Write-Warning "There are $($Matches.Count) open shared files on '$Server' which match query criteria."
                    Write-Warning "Built-in safety check will not allow 'ALL' to be specified if more than 10 open shared files match query criteria."
                    Write-Host "MESSAGE: Exiting without closing any open shared files on '$Server'" -ForegroundColor Gray
                }

                # Close each open file with matching ID
                Else {
                    foreach ($m in $Matches) {
                        Write-Host "INFO: Closing open shared file with ID: '$($m.ID)' on '$Server'" -ForegroundColor Gray
                        openfiles.exe /disconnect /id "$($m.ID)" /s $Server
                    }
                }
            }
        }

        # User entered a file ID(s) close each open file with matching ID
        Else {
            foreach ($i in $IDs) {
                
                # The entered file ID matches one listed in results showing open files
                If ($Matches.ID -contains $i) {
                    Write-Host "MESSAGE: Closing open shared file with ID: '$i' on '$Server'" -ForegroundColor Gray
                    openfiles.exe /disconnect /id $i /s $Server
                }

                # The entered file ID does not matches an open file listed in results
                Else {
                    Write-Warning "File ID '$($i)' is not an open shared file on '$Server'"
                }
            }
        }
    }

    # User did not enter any file IDs
    Else {
        Write-Host "MESSAGE: Exiting without closing any open shared files on '$Server'" -ForegroundColor Gray
    }
}

# No open files match the file name/user query
Else {
    Write-Host "MESSAGE: No open shared files match the query on '$Server'" -ForegroundColor Gray
}

}