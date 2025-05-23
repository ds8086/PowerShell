Function Clear-MsolRoleMembership {
<#
.SYNOPSIS
Clears MSOL and Exchange administrative role membership from one or more users.

.DESCRIPTION
Clears MSOL and Exchange administrative role membership from one or more users.

.NOTES
Author: 
    DS
Notes:
    Revision 02
Revision:
    V01: 2024.02.09 by DS :: First revision
    V02: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ MSOnline and ExchangeOnlineManagement modules.

.PARAMETER Identity
The UserPrincipalName of the user from which MSOL and Exchange roles will be removed.

.PARAMETER Force
Switched parameter which, when used, removes specified user(s) from MSOL and Exchange roles without confirmation.

.EXAMPLE
Clear-MsolRoleMembership -Identity 'James.Kirk@contoso.com'
Will retrieve MSOL and Exchange role membership for user 'James.Kirk@contoso.com' and display the results, prompting for confirmation before role removal.

.EXAMPLE
Clear-MsolRoleMembership -Identity 'James.Kirk@contoso.com' -Force
Will retrieve MSOL and Exchange role membership for user 'James.Kirk@contoso.com' and remove user from all roles without confirmation.

.EXAMPLE
$Remove = "Ensign.Ricky@contoso.com","Lt.Redshirt@contoso.com"
$Remove | Clear-MsolRoleMembership -Force
Will retrieve MSOL and Exchange role membership for users stored in the $Remove variable and remove users from all roles without confirmation. MSOL and Exchange roles and members are only queried once using this method, making it more efficient.
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=0)]
    [string]$Identity,

    [Parameter(Mandatory=$False)]
    [Switch]$Force = $False
)

Begin {

# Define and import required modules
$RequiredModules = "MSOnline","ExchangeOnlineManagement"
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

# Retrieve MSOL roles connecting to MSOL service if not already
Try {
    Write-Verbose "Retrieving MSOL roles"
    $MsolRoles = Get-MsolRole -ErrorAction Stop
}
Catch [Microsoft.Online.Administration.Automation.MicrosoftOnlineException] {
    Try {
        Write-Warning "Not connected to MSOL service"
        Connect-MsolService -ErrorAction Stop
        $MsolRoles = Get-MsolRole -ErrorAction Stop
    }
    Catch {
        Write-Host "FAILURE: Unable to connect to MSOL service and/or retrieve MSOL roles!" -ForegroundColor Red
        Break
    }
}

# Retrieve Exchange roles connecting to Exchange online if not already
Try {
    Write-Verbose "Retrieving Exchange Online roles"
    $ExchangeRoles = Get-RoleGroup -ErrorAction Stop
}
Catch {
    Try {
        Write-Warning "Not connected to Exchange online"
        Connect-IPPSSession -ErrorAction Stop
        $ExchangeRoles = Get-RoleGroup -ErrorAction Stop
    }
    Catch {
        Write-Host "FAILURE: Unable to connect to Exchange Online and/or retrieve Exchange roles!" -ForegroundColor Red
        Break
    }
}

# Determine MSOL role members
$i = 0
$RoleMembers = foreach ($mr in $MsolRoles) {
    $i++
    Write-Progress "Retrieving role members for MSOL role '$($mr.Name)'" -PercentComplete ($i / $MsolRoles.Count * 100)

    Get-MsolRoleMember -RoleObjectId $mr.ObjectId | Select-Object `
        @{N="ObjectId";E={$mr.ObjectId}},`
        @{N="Name";E={$mr.Name}},`
        @{N="RoleType";E={[string]::new('MSOL')}},`
        @{N="UserId";E={$_.ObjectId}}
}

# Determine Exchange role members
$i = 0
$RoleMembers += foreach ($er in $ExchangeRoles) {
    $i++
    Write-Progress "Retrieving role members for Exchange Online role '$($er.Name)'" -PercentComplete ($i / $ExchangeRoles.Count * 100)

    Get-RoleGroupMember -Identity $er.Guid | Select-Object `
        @{N="ObjectId";E={$er.Guid}},`
        @{N="Name";E={$er.Name}},`
        @{N="RoleType";E={[string]::new('Exchange')}},`
        @{N="UserId";E={$_.Guid}}
}

# Subfunction: Remove user from MSOL & exchange roles
Function RemoveRoles {
$i = 0
foreach ($sr in $SrcRoles) {
    $i++

    # Remove 'source' user from each MSOL & Exchange role where they are a member
    switch ($sr.RoleType) {
        'MSOL' {
            Write-Progress "Remove '$Identity' from MSOL role '$($sr.Name)'" -PercentComplete ($i / $SrcRoles.Count * 100)
            Try {
                Remove-MsolRoleMember -RoleObjectId $sr.ObjectId -RoleMemberObjectId $SrcUser.ObjectId
                Write-Verbose "'$Identity' removed from MSOL role '$($sr.Name)'"
            }
            Catch {
                Write-Warning "'$Identity' could not be removed from MSOL role '$($sr.Name)'"
            }
        }
        'Exchange' {
            Write-Progress "Remove '$Identity' from Exchange role '$($sr.Name)'" -PercentComplete ($i / $SrcRoles.Count * 100)
            Try {
                Remove-RoleGroupMember -Identity $sr.ObjectId.Guid -Member $SrcUser.ObjectId.Guid -Confirm:$False
                Write-Verbose "'$Identity' removed from Exchange role '$($sr.Name)'"
            }
            Catch {
                Write-Warning "'$Identity' could not be removed from Exchange role '$($sr.Name)'"
            }
        }
    }
}
}

} # Begin

Process {

# Ensure that user specified in '$Identity' exists
$SrcUser = $null
$SrcUser = Get-MsolUser -UserPrincipalName $Identity -ErrorAction SilentlyContinue

If ($SrcUser) {

    # MSOL & Exchange roles where 'source' user is a member
    $SrcRoles = $RoleMembers | Where-Object {$_.UserId -eq $SrcUser.ObjectId}

    If ($SrcRoles) {
        
        switch ($Force) {
            $True {
                Write-Verbose "'-Force' specified, skipping confirmation"
                RemoveRoles
            }
            $False {
                $SrcRoles | Format-Table Name,RoleType
                Write-Warning "'$Identity' will be removed from *ALL* MSOL/Exchange roles above" -WarningAction Inquire
                RemoveRoles
            }
        }
    }
    Else {
        Write-Warning "'$Identity' is not a member of any MSOL or Exchange roles"
    }
}
Else {
    Write-Host "FAILURE: '$Identity' not found in MSOL!" -ForegroundColor Red
}

} # Process

}