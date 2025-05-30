Function Copy-MsolRoleMembership {
<#
.SYNOPSIS
Copies MSOL and Exchange role membership from one user to one or more users.

.DESCRIPTION
Copies MSOL and Exchange role membership from one user to one or more users.

.NOTES
Author: 
    DS
Notes:
    Revision 06
Revision:
    V01: 2024.02.05 by DS :: First revision.
    V02: 2024.02.07 by DS :: Added verbosity and try...catch for 'Add-MsolRoleMember' and 'Add-RoleGroupMember'.
    V03: 2024.02.12 by DS :: Updated so that 'Source' also accepts value from pipeline.
    V04: 2024.02.13 by DS :: Updated parameter names. Added 'End' block for the 'AuditManager' Exchange role group issue.
    V05: 2024.12.24 by DS :: Fixed issues identified by VS Code.
    V06: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ MSOnline and ExchangeOnlineManagement modules.

.PARAMETER Source
The UserPrincipalName of the user from which MSOL and Exchange roles will be copied.

.PARAMETER Destination
The UserPrincipalName(s) of the user(s) to which MSOL and Exchange roles will be copied. This parameter accepts values from the pipeline.

.EXAMPLE
Copy-MsolRoleMembership -Source 'James.Kirk@contoso.com' -Destination 'Spock@contoso.com'
Will copy all MSOL and Exchange role membership from 'James.Kirk@contoso.com' to 'Spock@contoso.com'

.EXAMPLE
$CSV = Import-Csv .\msol_copy.csv | Select-Object Source,Destination
$CSV | Copy-MsolRoleMembership
Will import the CSV file named 'msol_copy.csv' and copy MSOL and Exchange role membership from each unique 'Source' to its corresponding 'Desintation'. 
#>

[CmdletBinding(SupportsShouldProcess=$True)]
param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
    [Alias('CopyFrom')]
    [string]$Source,
    
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=1)]
    [Alias('CopyTo')]
    [string]$Destination
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
        Write-Warning "Not connected to MSOL service!"
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
        Write-Warning "Not connected to Exchange online!"
        Connect-IPPSSession -ErrorAction Stop
        $ExchangeRoles = Get-RoleGroup -ErrorAction Stop
    }
    Catch {
        Write-Host "FAILURE: Unable to connect to Exchange Online and/or Exchange roles!" -ForegroundColor Red
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

} # Begin

Process {

# 'Source' user
$SrcUser = $null
$SrcUser = Get-MsolUser -UserPrincipalName $Source -ErrorAction SilentlyContinue

# 'Destination' user
$DstUser = $null
$DstUser = Get-MsolUser -UserPrincipalName $Destination -ErrorAction SilentlyContinue

# MSOL & Exchange roles where 'source' user is a member
$SrcRoles = $RoleMembers | Where-Object {$_.UserId -eq $SrcUser.ObjectId}

# Add 'destination' user to each MSOL and Exchange role
If ($SrcUser -and $DstUser -and $SrcRoles) {
    $i = 0
    foreach ($sr in $SrcRoles) {
        $i++
        Try {
            Write-Progress "Add '$Destination' to $($sr.RoleType) role '$($sr.Name)'" -PercentComplete ($i / $SrcRoles.Count * 100)
        }
        Catch {}
    
        switch ($sr.RoleType) {
            'MSOL' {
                If ( ($RoleMembers | Where-Object {$_.ObjectId -eq $sr.ObjectId}).UserId -contains $DstUser.ObjectId ) {
                    Write-Host "MESSAGE: '$Destination' already a member of MSOL role '$($sr.Name)'" -ForegroundColor Gray
                }
                Else {
                    Try {
                        Add-MsolRoleMember -RoleObjectId $sr.ObjectId -RoleMemberObjectId $DstUser.ObjectId -ErrorAction Stop
                        Write-Host "SUCCESS: '$Destination' added to MSOL role '$($sr.Name)'" -ForegroundColor Green
                    }
                    Catch {
                        Write-Warning "'$Destination' could not be added to MSOL role '$($sr.Name)'"
                    }
                }
            }
            'Exchange' {
                If ( ($RoleMembers | Where-Object {$_.ObjectId -eq $sr.ObjectId}).UserId -contains $DstUser.ObjectId.Guid ) {
                    Write-Host "MESSAGE: '$Destination' already a member of Exchange role '$($sr.Name)'" -ForegroundColor Gray
                }
                Else {
                    Try {
                        # This fails on 'Audit Manager' role... figure out why
                        Add-RoleGroupMember -Identity $sr.Name -Member $DstUser.UserPrincipalName -ErrorAction Stop
                        Write-Host "SUCCESS: '$Destination' added to Exchange role '$($sr.Name)'" -ForegroundColor Green
                    }
                    Catch {
                        Write-Warning "'$Destination' could not be added to Exchange role '$($sr.Name)'"
                        $ExchangeError = 1
                    }
                }
            }
        }
    }
}

# 'Source' user does not exist
If (!$SrcUser) {
    Write-Host "FAILURE: '$Source' not found in Microsoft Online!" -ForegroundColor Red
}

# 'Destination' user does not exist
If (!$DstUser) {
    Write-Host "FAILURE: '$Destination' not found in Microsoft Online!" -ForegroundColor Red
}

# 'Source' user has no MSOL or Exchange role memberships
If (!$SrcRoles) {
    Write-Host "MESSAGE: '$Source' not a member of any MSOL or Exchange roles" -ForegroundColor Gray
}

} # Process

End {
    If ($ExchangeError -eq 1) {
        Write-Warning "There is an issue with adding users to the Exchange / Purview role group 'AuditManager' via PowerShell"
        Write-Warning "The PowerShell operation will fail with 'Recipient with id <GUID> does not exist' when it does."
    }
} #End

}