Function New-ADOrganizationalUnitDelegation {
<#
.SYNOPSIS
Delegates access over specific AD objects within a specified OU to the specified group

.DESCRIPTION
Delegates access over specific AD objects within a specified OU to the specified group

.NOTES
Author: 
    DS
Notes:
    Revision 05
Revision:
    V01: 2022.09.22 by DS :: First revision.
    V02: 2023.06.06 by DS :: Updated documentation and cleaned up spacing.
    V03: 2023.07.18 by DS :: Removed '#Requires -Module ActiveDirectory' and added logic for required modules.
    V04: 2024.08.13 by DS :: Fixed typo in cmdlet name and script header.
    V05: 2025.03.10 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module

.PARAMETER OrganizationalUnit
The 'DistinguishedName' of the AD Organizational Unit where access will be delegated. The 'DistinguishedName' of the domain root may also be used.

.PARAMETER Group
The AD Group to which access will be delegated. AD group can be specified via SamAccountName, DistinguishedName, ObjectGUID or SID.

.PARAMETER ADObject
The AD 'object' to which the specified group will have delegated access. Valid options are: 'Users', 'Computers', 'Groups', 'OUs', 'GPLinks', and 'PasswordAndLockouts'

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingUsers,DC=contoso,DC=com" -Group HelpDesk -ADObject Users
Will delegate access over AD User objects in the "OU=AccountingUsers,DC=contoso,DC=com" OU, to the AD group 'HelpDesk'. Users in the 'HelpDesk' group can create/delete AD User objects in the OU and have 'FullControl' permissions on existing AD User objects within the OU and sub-OUs.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingUsers,DC=contoso,DC=com" -Group HelpDesk -ADObject PasswordAndLockouts
Will delegate access over AD User objects in the "OU=AccountingUsers,DC=contoso,DC=com" OU, to the AD group 'HelpDesk'. Users in the 'HelpDesk' group can reset passwords of AD User objects and unlock accounts of AD User objects in the OU and sub-OUs.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingGroups,DC=contoso,DC=com" -Group HelpDesk -ADObject Groups
Will delegate access over AD Group objects in the "OU=AccountingGroups,DC=contoso,DC=com" OU, to the AD group 'HelpDesk'. Users in the 'HelpDesk' group can create/delete AD Group objects in the OU and have 'FullControl' permissions on existing AD Group objects within the OU and sub-OUs.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingComputers,DC=contoso,DC=com" -Group DesktopTeam -ADObject GPLinks
Will delegate access over GPLinks in the "OU=AccountingComputers,DC=contoso,DC=com" OU, to the AD group 'DesktopTeam'. Users in the 'DesktopTeam' group can link/enforce existing GPOs to the OU and sub-OUs, however new GPOs cannot be be created by the 'DesktopTeam' group.

.EXAMPLE
New-ADOrganizationalUnitDelegation -OrganizationalUnit "OU=AccountingComputers,DC=contoso,DC=com" -Group DesktopTeam -ADObject Computers
Will delegate access over AD Computer objects in the "OU=AccountingComputers,DC=contoso,DC=com" OU, to the AD group 'DesktopTeam'. Users in the 'DesktopTeam' group can create/delete AD Computer objects in the OU and have 'FullControl' permissions on existing AD Computer objects within the OU and sub-OUs.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,Position=0)]
    [Alias('OU')]
    $OrganizationalUnit,

    [Parameter(Mandatory=$True,Position=1)]
    $Group,

    [Parameter(Mandatory=$True,Position=2)]
    [ValidateScript({$_.Count -eq 1})]
    [ValidateSet("Users", "Computers", "Groups", "OUs", "GPLinks", "PasswordAndLockouts")]
    $ADObject
)

# Define and import required modules
$RequiredModules = "ActiveDirectory"
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

# Set location to 'AD:\'
Try {
    Set-Location "AD:\" -ErrorAction Stop
}
Catch {
    Write-Host "FAILURE: Could not set location to 'AD:\'!" -ForegroundColor Red
    Break
}

# Ensure that both the specified Group exists
Try {
    Write-Verbose "Checking for AD Group '$Group'"
    $G = Get-ADGroup -Identity $Group -ErrorAction Stop
}
Catch {
    Write-Host "ERROR: Specified AD group '$Group' was not found" -ForegroundColor Red
    Break
}

# Ensure that specified OU exists, retrieve existing ACL if it does
Write-Verbose "Checking for AD Organizational Unit '$OrganizationalUnit'"
If (!(Test-Path $OrganizationalUnit -ErrorAction Stop)) {
    Write-Host "ERROR: Specified AD Organizational Unit '$OrganizationalUnit' was not found" -ForegroundColor Red
    Break
}
Else {
    $ACL = Get-Acl -Path $OrganizationalUnit -ErrorAction Stop
}

# Subfunctions named after the 'ADObject' parameter
Function Users {

# ACE: Full control over descendent user objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete user objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function Computers {

# ACE: Full control over descendent computer objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete computer objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967a86-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function Groups {

# ACE: Full control over descendent group objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete group objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967a9c-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function OUs {

# ACE: Full control over descendent OU objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "GenericAll"
$AccessControlType = "Allow"
$ObjectType = "00000000-0000-0000-0000-000000000000"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aa5-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to create/delete OU objects
$IdentityReference = $G.SID
$ActiveDirectoryRights = "CreateChild, DeleteChild"
$AccessControlType = "Allow"
$ObjectType = "bf967aa5-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function GPLinks {

# ACE: Ability to read & write the 'gPOtions' attribute
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "f30e3bbf-9ff0-11d1-b603-0000f80367c1"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to read & write the 'GP-Link' attribute
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "f30e3bbe-9ff0-11d1-b603-0000f80367c1"
$InheritenceType = "All"
$InheritedObjectType = "00000000-0000-0000-0000-000000000000"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}
Function PasswordAndLockouts {

# ACE: Ability to read & write the 'Lockout-Time' attribute on 'Users'
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "28630ebf-41d5-11d1-a9c1-0000f80367c1"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Ability to read & write the 'Pwd-Last-Set' attribute on 'Users'
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ReadProperty, WriteProperty"
$AccessControlType = "Allow"
$ObjectType = "bf967a0a-0de6-11d0-a285-00aa003049e2"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

# ACE: Grant the extended right 'Reset Password' on 'Users'
$IdentityReference = $G.SID
$ActiveDirectoryRights = "ExtendedRight"
$AccessControlType = "Allow"
$ObjectType = "00299570-246d-11d0-a768-00aa006e0529"
$InheritenceType = "Descendents"
$InheritedObjectType = "bf967aba-0de6-11d0-a285-00aa003049e2"

# Create ACE
$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    $IdentityReference,
    $ActiveDirectoryRights,
    $AccessControlType,
    $ObjectType,
    $InheritenceType,
    $InheritedObjectType
)

# Add ACE to ACL
$ACL.AddAccessRule($ace)

}

# Call the subfunction specified by '-ADObject' parameter
Write-Verbose "Creating ACEs to grant '$Group' delegated access over '$ADObject' in AD OU '$OrganizationalUnit'"
& $ADObject

# Set the new ACL (with added ACEs) on the AD OU
Write-Verbose "Setting updated ACL on AD OU '$OrganizationalUnit'"
Set-Acl -AclObject $ACL -Path $OrganizationalUnit

}