Function Get-MsolRoleReport {
<#
.SYNOPSIS
Retrieves Microsoft online & Exchange online role report.

.DESCRIPTION
Retrieves Microsoft online & Exchange online roles and members.

.NOTES
Author: 
    DS
Notes:
    Revision 04
Revision:
    V01: 2023.04.17 by DS :: First revision
    V02: 2024.02.05 by DS :: Added script header and expanded on comments
    V03: 2024.02.14 by DS :: Added 'MemberId' to output
    V04: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v4 or higher w/ 'MSOnline' and 'ExchangeOnlineManagement' modules

.EXAMPLE
Get-MsolRoleReport | Export-Csv -Path .\msol_roles.csv -NoTypeInformation
Will retrieve all Microsoft online & Exchange online roles and role members then exports results to a CSV in the current working directory.
#>

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

# Retrieve MSOL role members
$i = 0
$Results = foreach ($mr in $MsolRoles) {
    $i++
    Write-Progress "Determining role members for MSOL role '$($mr.Name)'" -PercentComplete ($i / $MsolRoles.Count * 100) -Id 1

    $mem = $null
    $mem = Get-MsolRoleMember -RoleObjectId $mr.ObjectId

    If ($mem) {
        $mem | Select-Object `
            @{N="RoleId";E={$mr.ObjectId}},`
            @{N="RoleName";E={$mr.Name}},`
            @{N="RoleType";E={[string]::new('MSOL')}},`
            @{N="RoleDescription";E={$mr.Description}},`
            @{N="MemberId";E={$_.ObjectId}},`
            RoleMemberType,`
            EmailAddress,`
            DisplayName
    }
    Else {
        $mr | Select-Object `
            @{N="RoleId";E={$mr.ObjectId}},`
            @{N="RoleName";E={$mr.Name}},`
            @{N="RoleType";E={[string]::new('MSOL')}},`
            @{N="RoleDescription";E={$mr.Description}},`
            @{N="MemberId";E={[string]::new("No members")}},`
            @{N="RoleMemberType";E={[string]::new("No members")}},`
            @{N="EmailAddress";E={[string]::new("No members")}},`
            @{N="DisplayName";E={[string]::new("No members")}}
    }
}

# Retrieve Exchange role members
$i = 0
$Results += foreach ($er in $ExchangeRoles) {
    $i++
    Write-Progress "Determining role members for Exchange Online role '$($er.Name)'" -PercentComplete ($i / $ExchangeRoles.Count * 100) -ParentId 1

    $mem = $null
    $mem = Get-RoleGroupMember -Identity $er.Guid

    If ($mem) {
        $mem | Select-Object `
            @{N="RoleId";E={$er.Guid}},`
            @{N="RoleName";E={$er.Name}},`
            @{N="RoleType";E={[string]::new('Exchange')}},`
            @{N="RoleDescription";E={$er.Description}},`
            @{N="MemberId";E={$_.Guid}},`
            @{N="RoleMemberType";E={$_.RecipientType}},`
            @{N="EmailAddress";E={$_.Alias}},`
            DisplayName
    }
    Else {
        $er | Select-Object `
            @{N="RoleId";E={$er.Guid}},`
            @{N="RoleName";E={$er.Name}},`
            @{N="RoleType";E={[string]::new('Exchange')}},`
            @{N="RoleDescription";E={$er.Description}},`
            @{N="MemberId";E={[string]::new("No members")}},`
            @{N="RoleMemberType";E={[string]::new("No members")}},`
            @{N="EmailAddress";E={[string]::new("No members")}},`
            @{N="DisplayName";E={[string]::new("No members")}}
    }
}

# Output results
$Results

}