Function Get-AzureADGroupMemberRecurse {
<#
.SYNOPSIS
Retrieves Azure AD group membership recursively.

.DESCRIPTION
Retrieves Azure AD group membership recursively for the specified AzureAD group ObjectID.

.NOTES
Author: 
    DS
Notes:
    Revision 07
Revision:
    V01: 2024.02.21 by DS :: First revision.
    V02: 2024.02.29 by DS :: Updated to include 'AccountEnabled' in output. Added logic to determine the 'need' for selecting unique members.
    V03: 2024.03.01 by DS :: Updated to include 'Mail' in output.
    V04: 2024.03.22 by DS :: Updated to include 'DirSyncEnabled' in output.
    V05: 2024.12.24 by DS :: Fixed issues identified by VS Code.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
    V07: 2025.04.28 by DS :: Change 'while' in do...while to '$SubADGroups -ne $null' ($null on the left as VS code suggests causes an infinite loop).
Call From:
    PowerShell v5.1 or higher w/ AzureAD module

.PARAMETER ObjectId
The ObjectId of the AzureAD group for which to retrieve membership recursively.

.EXAMPLE
Get-AzureADGroupMemberRecurse -ObjectId 'bc2b7e60-fb61-49fb-ba03-dfb238c44637'
Will retrieve recursive membership of the specified AuzreAD group with ObjectId 'bc2b7e60-fb61-49fb-ba03-dfb238c44637'.

.EXAMPLE
Get-AzureADGroup -SearchString "Marketing" | Get-AzureADGroupMemberRecurse
Will search for AzureAD groups using the string "Marketing" and retrieve recursive membership of each group which is found.
#>
[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
    [string]$ObjectId
)

Begin {

# Define and import required modules
$RequiredModules = "AzureAD"
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

# Connect to Azure AD if not already
Try {
    Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
}
Catch [Microsoft.Open.Azure.AD.CommonLibrary.AadNeedAuthenticationException] {
    Connect-AzureAD
}

} # Begin
Process {

# Ensure specified group exists
$ADGroup = Get-AzureADGroup -ObjectId $ObjectId -ErrorAction SilentlyContinue

If ($ADGroup) {
    
    # Members of specified group
    Write-Verbose "Retrieve membership of '$($ADGroup.ObjectId)' ($($ADGroup.DisplayName))"
    $Members = $null
    $Members = Get-AzureADGroupMember -ObjectId $ADGroup.ObjectId -All:$true

    If ($Members) {
        
        # Arrays for user members of both group and sub-groups
        $UserMembers = New-Object -TypeName System.Collections.ArrayList
        $SubADGroups = New-Object -TypeName System.Collections.ArrayList
        
        foreach ($m in $Members) {
            switch ($m.ObjectType) {
                
                # Member of specified group is itself a group, add ObjectId to $SubADGroups
                {$_ -eq "Group"} {
                    $SubADGroups.Add($m.ObjectId) | Out-Null
                }

                # Member of specified group is a user
                {$_ -eq "User"} {
                    $add = $null
                    $add = $m | Select-Object ObjectId,DisplayName,UserPrincipalName,AccountEnabled,Mail,ObjectType,DirSyncEnabled
                    $UserMembers.Add($add) | Out-Null
                }
            }
        }
        
        # Determine membership for all sub-groups, add *further* sub-groups to $SubADGroups array as needed
        Do {
            foreach ($sg in $SubADGroups) {
                Write-Verbose "Retrieve membership of '$sg' (Nested groups remaining: $($SubADGroups.Count))"
                $submembers = $null
                $submembers = Get-AzureADGroupMember -ObjectId $sg -All:$True
        
                foreach ($sm in $submembers) {
                    switch ($sm.ObjectType) {
                        {$_ -eq "Group"} {
                            $SubADGroups += $sm.ObjectId
                        }
                        {$_ -eq "User"} {
                            $add = $null
                            $add = $sm | Select-Object ObjectId,DisplayName,UserPrincipalName,AccountEnabled,Mail,ObjectType,DirSyncEnabled
                            $UserMembers.Add($add) | Out-Null
                        }
                    }
                }
                $SubADGroups = $SubADGroups | Where-Object {$_ -ne $sg}
            }
        }
        While (
            $SubADGroups -ne $null
        )
        
        # Total user members is equal to unique user members
        If ($UserMembers.Count -eq ($UserMembers.ObjectId | Select-Object -Unique).Count) {
            $UserMembers | Select-Object `
                @{N="GroupObjectId";E={$ADGroup.ObjectId}},`
                @{N="GroupDisplayName";E={$ADGroup.DisplayName}},`
                ObjectId,DisplayName,UserPrincipalName,AccountEnabled,Mail,ObjectType,DirSyncEnabled
        }

        # Duplicate user members exist due to group nesting (select only unique user members)
        Else {
            foreach ($id in ($UserMembers.ObjectId | Select-Object -Unique))  {
                $UserMembers | Where-Object {$_.ObjectId -eq $id} | Select-Object -First 1 | Select-Object `
                    @{N="GroupObjectId";E={$ADGroup.ObjectId}},`
                    @{N="GroupDisplayName";E={$ADGroup.DisplayName}},`
                    ObjectId,DisplayName,UserPrincipalName,AccountEnabled,Mail,ObjectType,DirSyncEnabled
            }
        }
    }

    # Specified group has no members
    Else {
        Write-Warning "'$ObjectId' ($($ADGroup.DisplayName)) has no members"
    }
}

# Specified group (ObjectId) does not exist
Else {
    Write-Warning "'$ObjectId' is not a valid AzureAD group ObjectId"
}

} # Process

}