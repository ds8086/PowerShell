Function Get-EffectivePermissions {
<#
.SYNOPSIS
Retrieve effective permissions for a file or directory.

.DESCRIPTION
Retrieve effective permissions for a file or directory.

.NOTES
Author: 
    DS
Notes:
    Revision 08
Revision:
    V01: 2017.10.19 by DS :: First working iteration.
    V02: 2017.12.11 by DS :: Resolved bug with trimming domain name from identity references.
    V03: 2018.03.09 by DS :: Added parameters to filter 'IdentityReference' and 'PermissionsFrom'.
    V04: 2018.05.18 by DS :: Added 'Path' to output to make more loop friendly.
    V05: 2019.01.29 by DS :: Added '-ExcludeIT' to exclude inherited permissions granted to IT staff from results.
    V06: 2021.12.16 by DS :: Updated '-ExcludeIT' switch. Updated $object to exclude $NBDomain.
    V07: 2026.01.19 by DS :: Overhaul for GitHub.
    V08: 2026.03.18 by DS :: Verified working, first publish to GitHub.
Call From:
    Windows PowerShell v5.1 or newer w/ ActiveDirectory module.

.PARAMETER Path
Path to the file or directory on which to calculate effective permissions

.PARAMETER IdentityReference
Return a specific IdentityReference in results. Accepts wildcards and is * (all) by default.

.PARAMETER PermissionsFrom
Return a specific PermissionsFrom in results. Accepts wildcards and is * (all) by default.

.EXAMPLE
Get-EffectivePermissions -Path \\Server01\Share\Security
Returns effective permissions for specified directory.

.EXAMPLE
Get-EffectivePermissions -Path \\Server01\Share\Security\File.txt
Returns effective permissions for specified file.

.EXAMPLE
Get-EffectivePermissions -Path \\Server01\Share\Security -IdentityReference JKirk
Returns effective permissions for specified directory as they exist for IdentityReference 'JKirk'.

.EXAMPLE
Get-EffectivePermissions -Path \\Server01\Share\Security -PermissionsFrom SecurityGroup
Returns effective permissions for specified directory where granted via the group named 'SecurityGroup'.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True)]
    [ValidateScript( {Test-Path $_} )]
    $Path,

    [Parameter(Mandatory=$False)]
    $PermissionsFrom = "*",

    [Parameter(Mandatory=$False)]
    $IdentityReference = "*"
)

# Define and import required modules
$RequiredModules = "ActiveDirectory"
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

# Find NetBIOS domain name and get ACL entries
$DomainBios = Get-ADDomain | Select-Object -ExpandProperty NetBIOSName
$AclObjects = Get-Acl -Path $Path | Select-Object -ExpandProperty Access

# Main loop
$Data = foreach ($ace in $AclObjects) {
    
    # IdentityReferences from the domain
    if ($ace.IdentityReference -like "$DomainBios\*") {
        $null = $object
        # Drop NetBIOS domain name from ACL IdentityReference ($object)
        $object = $ace.IdentityReference.ToString().Split("\") | Where-Object {$_ -ne "$DomainBios"}
        
        # Find $object in AD, determine the ObjectClass (user or group)
        $objectclass = Get-ADObject -Filter {SamAccountName -eq $object} | Select-Object -ExpandProperty ObjectClass
        
        # Object is group
        if ($objectclass -eq "group") {
            
            # Recursively get group membership selecting SamAccountName of each group member
            $sams = Get-ADGroupMember -Identity $object -Recursive | Select-Object -ExpandProperty SamAccountName
            foreach ($sam in $sams) {
                $sam | Select-Object @{Name="Path";Expression={$Path}},
                    @{Name="FileSystemRights";Expression={$ace.FileSystemRights}},
                    @{Name="AccessControlType";Expression={$ace.AccessControlType}},
                    @{Name="IdentityReference";Expression={$sam}},
                    @{Name="PermissionsFrom";Expression={$object}},
                    @{Name="IsInherited";Expression={$ace.IsInherited}},
                    @{Name="InheritanceFlags";Expression={$ace.InheritanceFlags}},
                    @{Name="PropagationFlags";Expression={$ace.PropagationFlags}}
            }
        }

        # Object is not group
        else {
            $object | Select-Object @{Name="Path";Expression={$Path}},
                @{Name="FileSystemRights";Expression={$ace.FileSystemRights}},
                @{Name="AccessControlType";Expression={$ace.AccessControlType}},
                @{Name="IdentityReference";Expression={$object}},
                @{Name="PermissionsFrom";Expression={[string]::new("Self")}},
                @{Name="IsInherited";Expression={$ace.IsInherited}},
                @{Name="InheritanceFlags";Expression={$ace.InheritanceFlags}},
                @{Name="PropagationFlags";Expression={$ace.PropagationFlags}}
        }       
    }

    # Object is not from the domain
    else {
        $ace | Select-Object @{Name="Path";Expression={$Path}},
             @{Name="FileSystemRights";Expression={$ace.FileSystemRights}},
             @{Name="AccessControlType";Expression={$ace.AccessControlType}},
             @{Name="IdentityReference";Expression={$ace.IdentityReference}},
             @{Name="PermissionsFrom";Expression={[string]::new("Self")}},
             @{Name="IsInherited";Expression={$ace.IsInherited}},
             @{Name="InheritanceFlags";Expression={$ace.InheritanceFlags}},
             @{Name="PropagationFlags";Expression={$ace.PropagationFlags}}  
    }
}

# Filtered results
$Data | Where-Object {
    $_.IdentityReference -like "$IdentityReference" -and
    $_.PermissionsFrom -like "$PermissionsFrom"
}

}