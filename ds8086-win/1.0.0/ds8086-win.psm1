Function Enable-DefaultVolumeACL {
<#
.SYNOPSIS
Creates 'Default' volume ACL entries.
.DESCRIPTION
Retrieves all volumes not mounted as drive letter C: and adds access control list entries (ACEs) for that of a newly provisioned volume.
.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2022.10.05 by DS :: First revision.
    V02: 2022.01.18 by DS :: Added script header. Added check for 'BUILTIN\Users' ACL entry.
    V03: 2025.03.22 by DS :: Updated for GitHub. Removed check for 'BUILTIN\Users' ACL entry.
Call From:
    PowerShell v5.1 or higher
.EXAMPLE
Enable-DefaultVolumeAcl
Retrieves all volumes not mounted as drive letter C: and adds access control list entries (ACEs) for that of a newly provisioned volume. Transcript log wil be generated in the current working directory.
#>

# Define and start logging
$Log = ".\ACL-Update.log"
Start-Transcript $Log -Force

# CSV (semicolon separated) of ACEs which make up the default ACL of a newly provisioned volume
$DefaultACL = ConvertFrom-Csv -Delimiter ";" -Header FileSystemRights,AccessControlType,IdentityReference,IsInherited,InheritanceFlags,PropagationFlags -InputObject (
    "ReadAndExecute, Synchronize;Allow;Everyone;FALSE;None;None",`
    "FullControl;Allow;CREATOR OWNER;FALSE;ContainerInherit, ObjectInherit;InheritOnly",`
    "FullControl;Allow;NT AUTHORITY\SYSTEM;FALSE;ContainerInherit, ObjectInherit;None",`
    "FullControl;Allow;BUILTIN\Administrators;FALSE;ContainerInherit, ObjectInherit;None",`
    "AppendData;Allow;BUILTIN\Users;FALSE;ContainerInherit;None",`
    "CreateFiles;Allow;BUILTIN\Users;FALSE;ContainerInherit;InheritOnly",`
    "ReadAndExecute, Synchronize;Allow;BUILTIN\Users;FALSE;ContainerInherit, ObjectInherit;None"
)

# Store OS (used in filtering $Volumes)
$OS = Get-WmiObject -Class win32_operatingsystem

switch ($OS) {
    
    # Server 2012
    {$_.Version -like "6.*"} {
        $Volumes = Get-Volume | Where-Object { ($_.DriveLetter.ToString() -ne "") -and ($_.DriveLetter -ne "C") -and ($_.DriveType -ne "CD-ROM") }
    }
    
    # All other OSes
    Default {
        $Volumes = Get-Volume | Where-Object { ($null -ne $_.DriveLetter) -and ($_.DriveLetter -ne "C") -and ($_.DriveType -ne "CD-ROM") }
    }
}

# Foreach (volume) loop
foreach ($v in $Volumes) {
    
    # Determine current ACL of volume
    $acl = $null
    $acl = Get-Acl -Path "$($v.DriveLetter):\"

    # Output current ACL for drive
    Write-Host "INFO: ACL for '$($v.DriveLetter):' as it exists now:" 
    ($acl).Access | Format-List

    # Build an ACE for each entry in $DefaultACL and add it to $ACL
    foreach ($da in $DefaultACL) {
        $ace = $null
        $ace = New-Object System.Security.AccessControl.FileSystemAccessRule (
            "$($da.IdentityReference)", `
            "$($da.FileSystemRights)", `
            "$($da.InheritanceFlags)", `
            "$($da.PropagationFlags)", `
            "$($da.AccessControlType)"
        )
        $acl.AddAccessRule($ace)
    }
    
    # Output future ACL for drive
    Write-Host "INFO: ACL for '$($v.DriveLetter):' as it will exist once updated:" 
    ($acl).Access | Format-List

    # Set new ACL
    Write-Host "INFO: Updating ACL (this will take awhile depending on the amount of data on '$($v.DriveLetter):'"
    $acl | Set-Acl
}

# Stop logging
Stop-Transcript

}
Function Enable-PSRemotingOnRemoteComputer {
<#
.SYNOPSIS
Attempts to enable PS remoting on specified remote computer(s).

.DESCRIPTION
Attempts to enable PS remoting on specified remote computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2023.06.26 by DS :: First revision.
    V02: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' and added '[Alias('Identity')]' for $ComputerName parameter.
    V03: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
    V05: 2025.05.29 by DS :: Updated function name and documentaiton to match.
    V06: 2025.06.03 by DS :: Reverted function name... already a thing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The name of remote computer(s) on which to enable PS remoting.

.PARAMETER Credential
Optional parameter to specify alternate credentials for enabling PS remoting on specified computer(s).

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Enable-PSRemotingOnRemoteComputer -ComputerName 'fileserver01'
Will attempt to enable PS remoting on 'fileserver01'.

.EXAMPLE
Enable-PSRemotingOnRemoteComputer -ComputerName 'fileserver01' -Credential (Get-Credential)
Will prompt for credentials, then use the credentials in an attempt to enable PS remoting on 'fileserver01'.

.EXAMPLE
Enable-PSRemotingOnRemoteComputer -ComputerName 'fileserver01','fileserver02'
Will attempt to enable PS remoting on 'fileserver01' and 'fileserver02'.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName,
    
    [Parameter(Mandatory=$False)]
    [pscredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$NoProgress = $false
)

$i = 0
foreach ($cn in $ComputerName) {
    If (!$NoProgress) {
        $i++
        Write-Progress "Enabling PS remoting for '$cn'" -PercentComplete ($i / $ComputerName.Count * 100)
    }

    # CIM session options
    $SessionArgs = @{
        ComputerName  = $cn
        Credential    = $Credential
        SessionOption = New-CimSessionOption -Protocol Dcom
    }

    # Arguements for 'Invoke-CimMethod' cmdlet below
    $MethodArgs = @{
        ClassName     = 'Win32_Process'
        MethodName    = 'Create'
        CimSession    = New-CimSession @SessionArgs -ErrorAction SilentlyContinue -OperationTimeoutSec 3
        Arguments     = @{
            CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"
        }
    }

    # Attempt to invoke CIM method
    Try {
        Invoke-CimMethod @MethodArgs -ErrorAction Stop | Out-Null
        Write-Verbose "Enabled PS remoting on '$($cn)'"
        Remove-CimSession -ComputerName $cn
    }
    Catch {
        Write-Host "FAILURE: Unable to create CIM session to '$($cn)'" -ForegroundColor Red
    }
}

}
Function Get-DriveDetails {
<#
.SYNOPSIS
Retrieves drive information for specified computer(s).

.DESCRIPTION
Retrieves drive information for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 12
Revision:
    V01: 2017.04.12 by DS :: Proof of concept.
    V02: 2017.06.19 by DS :: Removed formatting in foreach loop.
    V03: 2017.09.18 by DS :: Added ping test and check for enabled AD object in filter. Added switched parameter 'ServersOnly' and corresponding If tests.
    V04: 2017.11.20 by DS :: Added parameter 'Credential' and corresponding If tests.
    V05: 2018.05.25 by DS :: Removed parenthesis from output.
    V06: 2022.10.04 by DS :: Removed check for computer object in AD. Replaced ping test with WSMan test. Updated documentation.
    V07: 2023.02.21 by DS :: Updated 'Test-WSMan' cmdlet. Added -Authentication Negotiate.
    V09: 2023.05.18 by DS :: Script rewrite to utilize 'Get-WmiObject' template.
    V10: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' from $ComputerName parameter.
    V11: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V12: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which drive information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-DriveDetails -ComputerName FileServer01
Will return drive information for computer FileServer01.

.EXAMPLE
Get-DriveDetails -ComputerName FileServer01,FileServer02
Will return drive information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-DriveDetials -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve drive information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName,

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
            'Class' = 'Win32_LogicalDisk'
            'Filter' = 'DriveType = 3'
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'Win32_LogicalDisk'
            'Filter' = 'DriveType = 3'
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        'DeviceID',`
        'VolumeName',`
        @{Name="SizeGB";Expression={[Math]::Round($_.Size / 1GB)}},`
        @{Name="FreeGB";Expression={[Math]::Round($_.FreeSpace / 1GB)}},`
        @{Name="PercentFree";Expression={[Math]::Round($_.FreeSpace / $_.Size * 100)}}
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DeviceID";E={[string]::new("None")}},`
        @{N="VolumeName";E={[string]::new("None")}},`
        @{N="SizeGB";E={[string]::new("None")}},`
        @{N="FreeGB";E={[string]::new("None")}},`
        @{N="PercentFree";E={[string]::new("None")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DeviceID";E={[string]::new("Error")}},`
        @{N="VolumeName";E={[string]::new("Error")}},`
        @{N="SizeGB";E={[string]::new("Error")}},`
        @{N="FreeGB";E={[string]::new("Error")}},`
        @{N="PercentFree";E={[string]::new("Error")}}
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
            $wmi | Select-Object @WmiSelect
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Warning "'$cn' WMI connectivity failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$WmiResults

}
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
    Revision 02
Revision
    V01: 2022.04.19 by DS :: First published and polished revision, previously a dot-slash script.
    V02: 2025.05.22 by DS :: Put on your Sunday clothes kids, we're going to GitHub!
Call From:
    PowerShell v5.1+

.PARAMETER FolderPath
The folder path for which to calculate the total file size. The default value is the current working directory.

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
    $Results.FolderPath = $FolderPath
    $Results.FileCount = $Files.Count
    $Results.SizeMB = [math]::Round( ($Files | Measure-Object -Property length -Sum).Sum / 1MB, 2 )
    $Results.SizeGB = [math]::Round( ($Files | Measure-Object -Property length -Sum).Sum / 1GB, 2 )
    $Results
}

}
Function Get-InstalledSoftware {
<#
.SYNOPSIS
Retrieves installed software information for specified computer(s).

.DESCRIPTION
Retrieves installed software information for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2017.10.05 by DS :: Proof of concept.
    V02: 2021.11.24 by DS :: Added parameter for alternate credentials.
    V03: 2023.07.05 by DS :: Rewrite using new 'Invoke-Command' template.
    V04: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V05: 2024.12.24 by DS :: Fixed issues identified by VS Code, fixed param block spacing.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which installed software information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-InstalledSoftware -ComputerName FileServer01
Will return installed software information for computer FileServer01.

.EXAMPLE
Get-InstalledSoftware -ComputerName FileServer01,FileServer02
Will return installed software information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-InstalledSoftware -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve installed software information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string[]]$ComputerName,

    [Parameter(Mandatory=$False,Position=1)]
    [string]$Search = "*",
    
    [Parameter(Mandatory=$False,Position=2)]
    [pscredential]$Credential,

    [Parameter(Mandatory=$false)]
    [switch]$NoProgress = $false
)

# ScriptBlock used in 'Invoke-Command'
[System.Management.Automation.ScriptBlock]$ScriptBlock = {
    Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.DisplayName -like "*$Using:Search*") -and ($null -ne $_.DisplayName) }
    Get-ItemProperty HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { ($_.DisplayName -like "*$Using:Search*") -and ($null -ne $_.DisplayName) }
}

# Splat table for 'Invoke-Command' parameters
switch ($Credential) {
    {$_ -ne $null} {
        $InvParams = @{
	        'ComputerName' = ""
	        'Credential' = $Credential
            'ErrorAction' = 'Stop'
            'ScriptBlock' = $ScriptBlock
        }
    }
    {$_ -eq $null} {
        $InvParams = @{
	        'ComputerName' = ""
            'ErrorAction' = 'Stop'
            'ScriptBlock' = $ScriptBlock
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$InvSelect = @{ 
    'Property'= @( `
        'PSComputerName',`
        'DisplayName',`
        'DisplayVersion',`
        'Publisher',`
        'InstallDate',`
        'InstallLocation'
    )
}

# Splat table for 'Select-Object' (successful 'invoke-command' w/o data)
$NonSelect = @{
    'Property'= @( `
        @{N="PSComputerName";E={$cn}},`
        @{N="DisplayName";E={[string]::new("No matching software")}},`
        @{N="DisplayVersion";E={[string]::new("No matching software")}},`
        @{N="Publisher";E={[string]::new("No matching software")}},`
        @{N="InstallDate";E={[string]::new("No matching software")}},`
        @{N="InstallLocation";E={[string]::new("No matching software")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @( `
        @{N="PSComputerName";E={$cn}},`
        @{N="DisplayName";E={[string]::new("Invoke-Command Error")}},`
        @{N="DisplayVersion";E={[string]::new("Invoke-Command Error")}},`
        @{N="Publisher";E={[string]::new("Invoke-Command Error")}},`
        @{N="InstallDate";E={[string]::new("Invoke-Command Error")}},`
        @{N="InstallLocation";E={[string]::new("Invoke-Command Error")}}
    )
}

# Foreach loop to get WMI object from each $cn in $ComputerName
$i = 0
$InvResults = foreach ($cn in $ComputerName) {
    If (!$NoProgress) {
        $i++
        Write-Progress "Retrieving information from $cn" -PercentComplete ($i / $ComputerName.Count * 100)
    }

    $InvParams.ComputerName = $cn
    Try {
        $inv = Invoke-Command @InvParams
        If ($inv) {
            $inv | Select-Object @InvSelect
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Warning "'$cn' 'Invoke-Command' failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$InvResults

}
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
Function Get-NetworkAdapterConfiguration {
<#
.SYNOPSIS
Retrieves network adapter configuration information for specified computer(s).

.DESCRIPTION
Retrieves network adapter configuration information for specified computer(s).

.NOTES
Author: 
    Devin S
Notes:
    Revision 04
Revision:
    V01: 2023.06.15 by DS :: First iteration.
    V02: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' from $ComputerName parameter.
    V03: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which drive information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-NetworkAdapterConfiguration -ComputerName FileServer01
Will return network adapter configuration information for computer FileServer01.

.EXAMPLE
Get-NetworkAdapterConfiguration -ComputerName FileServer01,FileServer02
Will return network adapter configuration information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-NetworkAdapterConfiguration -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve network adapter configuration information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName,

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
            'Class' = 'Win32_NetworkAdapterConfiguration'
            'Filter' = "IPEnabled = 'True'"
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'Win32_NetworkAdapterConfiguration'
            'Filter' = "IPEnabled = 'True'"
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        'DHCPEnabled',`
        'IPAddress',`
        'DefaultIPGateway',`
        'DNSDomain',`
        'ServiceName',`
        'Description',`
        'Index'
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DHCPEnabled";E={[string]::new("None")}},`
        @{N="IPAddress";E={[string]::new("None")}},`
        @{N="DefaultIPGateway";E={[string]::new("None")}},`
        @{N="DNSDomain";E={[string]::new("None")}},`
        @{N="ServiceName";E={[string]::new("None")}},`
        @{N="Description";E={[string]::new("None")}},`
        @{N="Index";E={[string]::new("None")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="DHCPEnabled";E={[string]::new("Error")}},`
        @{N="IPAddress";E={[string]::new("Error")}},`
        @{N="DefaultIPGateway";E={[string]::new("Error")}},`
        @{N="DNSDomain";E={[string]::new("Error")}},`
        @{N="ServiceName";E={[string]::new("Error")}},`
        @{N="Description";E={[string]::new("Error")}},`
        @{N="Index";E={[string]::new("Error")}}
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
            $wmi | Select-Object @WmiSelect
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Warning "'$cn' WMI connectivity failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$WmiResults

}
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
    Revision 05
Revision:
    V01: 2022.09.09 by DS :: First revision.
    V02: 2023.08.01 by DS :: Minor rewrite, too many changes to list.
    V03: 2023.08.03 by DS :: Updated variable names, output, and script header.
    V04: 2025.03.21 by DS :: Updated comments and spacing.
    V05: 2025.06.03 by DS :: Replaced $Matches with $FileMatches (VS code suggestion).
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

# Determine $FileMatches
$FileMatches = $Format | Where-Object {$_.OpenFile -like "$OpenFile" -and $_.AccessedBy -like "$AccessedBy"}

# At least one open file matches file/user query
If ($FileMatches) {

    # Output open files as a table
    $FileMatches | Format-Table -Wrap

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
                If ($FileMatches.Count -gt 10) {
                    Write-Warning "There are $($FileMatches.Count) open shared files on '$Server' which match query criteria."
                    Write-Warning "Built-in safety check will not allow 'ALL' to be specified if more than 10 open shared files match query criteria."
                    Write-Host "MESSAGE: Exiting without closing any open shared files on '$Server'" -ForegroundColor Gray
                }

                # Close each open file with matching ID
                Else {
                    foreach ($m in $FileMatches) {
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
                If ($FileMatches.ID -contains $i) {
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
Function Get-RadiusPassword {
<#
.SYNOPSIS
Generates a RADIUS password.

.DESCRIPTION
Generates a RADIUS password with the specified length if provided.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2023.06.27 by DS :: First revision
    V02: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher

.PARAMETER Length
The length of the RADIUS password. If not specified, the default value is 16 for RADIUS v1 compatibility.

.PARAMETER Clip
Switched parameter which will copy the generated RADIUS password in the clipboard.

.EXAMPLE
Get-RadiusPassword
Will generate a 16 character length RADIUS password.

.EXAMPLE
Get-RadiusPassword -Length 64 -Clip
Will generate a 64 character length RADIUS password and copy the password to the clipboard.

.EXAMPLE
1..10 | % {Get-RadiusPassword}
Will generate ten, 16 character length RADIUS passwords.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
	[ValidateScript({$_ -le 64})]
    [int32]$Length = 16,

    [Parameter(Mandatory=$False)]
    [switch]$Clip = $False
)

# Define character sets for RADIUS password
$lletters = "abcdefghijklmnopqrstuvwxyz"
$uletters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
$integers = "0123456789"
$All = $lletters + $uletters + $integers

# Set $Password to an empty string
$Password = ""

# Set $Password to string created from character sets and $Length
foreach ($_ in 1..$Length) {
    $Password += $All[(Get-Random -Minimum 0 -Maximum 62)]
}

# Output $Password
$Password

# Store $Password in clipboard
If ($Clip) {
    $Password | clip
}

}
Function Get-UptimeFromRemoteComputer {
<#
.SYNOPSIS
Retrieves system uptime for specified computer(s).

.DESCRIPTION
Retrieves system uptime for specified computer(s).

.NOTES
Author: 
    DS
Notes:
    Revision 07
Revision:
    V01: 2017.11.02 by DS :: First working itteration.
    V02: 2018.12.28 by DS :: Added 'Credential' parameter and improved parameter block.
    V03: 2023.05.16 by DS :: Major script rewrite using template for 'Get-WmiObject' based cmdlets.
    V04: 2023.07.05 by DS :: Removed 'ValueFromPipeline=$true' from $ComputerName parameter.
    V05: 2023.07.14 by DS :: Added '-NoProgress' switch parameter.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
    V07: 2025.06.03 by DS :: Updated function name and documentation to match.
Call From:
    PowerShell v5.1 or higher

.PARAMETER ComputerName
The computer(s) for which uptime information will be retrieved.

.PARAMETER Credential
Optional parameter to specify alternate credentials for running the cmdlet.

.PARAMETER NoProgress
Optional switched parameter which, when specified, does not display a progress bar.

.EXAMPLE
Get-UptimeFromRemoteComputer -ComputerName FileServer01
Will return uptime information for computer FileServer01.

.EXAMPLE
Get-UptimeFromRemoteComputer -ComputerName FileServer01,FileServer02
Will return uptime information for computers FileServer01 and FileServer02.

.EXAMPLE
Get-UptimeFromRemoteComputer -ComputerName FileServer01 -Credential (Get-Credential)
Will prompt for alternate credentials to run the cmdlet and retrieve uptime information for FileServer01.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('Identity')]
    [string[]]$ComputerName,

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
            'Class' = 'win32_OperatingSystem'
            'ErrorAction' = 'Stop'
        }
    }
    {$_ -eq $null} {
        $WmiParams = @{
	        'ComputerName' = ""
            'Class' = 'win32_OperatingSystem'
            'ErrorAction' = 'Stop'
        }
    }
}

# Splat table for 'Select-Object' (success w/ data)
$WmiSelect = @{ 
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="LastBootUp";E={$_.ConvertToDateTime($_.LastBootUpTime)}}
        @{N="Uptime";E={(Get-Date) - ($_.ConvertToDateTime($_.LastBootUpTime))}}
    )
}

# Splat table for 'Select-Object' (success w/o data)
$NonSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="LastBootUp";E={[string]::new("None")}},`
        @{N="Uptime";E={[string]::new("None")}}
    )
}

# Splat table for 'Select-Object' (failure)
$ErrSelect = @{
    'Property'= @(`
        @{N="ComputerName";E={$cn}},`
        @{N="LastBootUp";E={[string]::new("Error")}},`
        @{N="Uptime";E={[string]::new("Error")}}
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
            $wmi | Select-Object @WmiSelect
        }
        Else {
            "" | Select-Object @NonSelect
        }
    }
    Catch {
        Write-Warning "'$cn' WMI connectivity failure"
        "" | Select-Object @ErrSelect
    }
}

# Output results
$WmiResults

}
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
Function Read-IISLogFile {
<#
.SYNOPSIS
Reads the specified IIS log file, adds the 'local' time for log entries, and converts log to a CSV.

.DESCRIPTION
Reads the specified IIS log file, adds the 'local' time for log entries, and converts log to a CSV.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2023.07.26 by DS :: First revision
    V02: 2024.12.24 by DS :: Fixed issues identified by VS Code, cleaned up param block spacing.
    V03: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    Windows PowerShell v5.1 or higher

.PARAMETER Path
The path to the IIS log file.

.PARAMETER Credential
Optional parameter for alternate credentials used in accessing the IIS log file.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log'
Will read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and output the results to the default output.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log' -Credential (Get-Credential)
Will prompt for credentials at exeuction and use them to read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and output the results to the default output.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log' | Out-GridView
Will read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and output the results to grid view.

.EXAMPLE
Read-IISLogFile -Path 'D:\Logs\W3SVC1\19991231.log' | Export-CSV .\19991231.csv -NoTypeInformation
Will read the IIS log file located in 'D:\Logs\W3SVC1\19991231.log', convert the log contents to a CSV, and export the results to a CSV file named '19991231.csv' in the current directory.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
	[ValidateScript({Test-Path $_})]
    [string]$Path,

    [Parameter(Mandatory=$False,Position=1)]
    [pscredential]$Credential = $null
)

# Determine $ContentParams for 'Get-Content' below
switch ($Credential) {
    {$_ -ne $null} {
        $ContentParams = @{
            'Path' = $Path
            'Credential' = $Credential
        }
    }
    {$_ -eq $null} {
        $ContentParams = @{
            'Path' = $Path
        }
    }
}

# Determine local timezone
$tz = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date))

# Get log and determine header
$Log = Get-Content @ContentParams
$Header = ($Log[3]).Replace('#Fields: ','').Split(' ')

# Convert log to CSV using header and add local time
$Csv = ConvertFrom-Csv -Delimiter " " -InputObject $Log -Header $Header
$Csv | Select-Object @{N="datetime(UTC$($tz.Hours))";E={([datetime]::Parse($_.date + " " + $_.time)).AddHours($tz.Hours)}},*

}