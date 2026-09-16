#Requires -Modules ActiveDirectory
Function Get-ProtectedGroupMembers {
    <#
.SYNOPSIS
Retrieves members of protected AD groups.

.DESCRIPTION
Retrieves members of protected AD groups.

.NOTES
Author: 
    DS
Notes:
    Revision 01
Revision:
    V01: 2026.09.16 by DS :: First revision.
Call From:
    PowerShell v5.1 or higher w/ ActiveDirectory module.

.EXAMPLE
Get-ProtectedGroupMembers
Retrieves members of protected AD groups.
#>
    [CmdletBinding()]
    param ()

    # protected groups
    $protectedGroups = @(
        'Account Operators',
        'Administrators',
        'Backup Operators',
        'Domain Admins',
        'Domain Controllers',
        'Enterprise Admins',
        'Enterprise Key Admins',
        'Key Admins',
        'Print Operators',
        'Read-only Domain Controllers',
        'Replicator',
        'Schema Admins',
        'Server Operators'
    )

    # 'good' select within loop (no errors & group has members)
    $gSelect = @{
        'Property' = @(
            @{N = 'Group'; E = { $pg } },
            'DistinguishedName',
            'Enabled',
            'Name',
            'SamAccountName',
            'ObjectClass',
            'WhenCreated',
            'LastLogonDate'
        )
    }

    # 'bad' select within loop (error or group has no members)
    $bSelect = @{
        'Property' = @(
            @{N = 'Group'; E = { $pg } },
            @{N = 'DistinguishedName'; E = { $s } },
            @{N = 'Enabled'; E = { $s } },
            @{N = 'Name'; E = { $s } },
            @{N = 'SamAccountName'; E = { $s } },
            @{N = 'ObjectClass'; E = { $s } },
            @{N = 'WhenCreated'; E = { $s } },
            @{N = 'LastLogonDate'; E = { $s } }
        )
    }

    # 'main' foreach loop
    $i = 0
    $protectedMembers = foreach ($pg in $protectedGroups) {
        $i++
        Write-Progress "Processing $pg" -PercentComplete ($i / $protectedGroups.Count * 100) -Id 1
    
        # string variable for errors and group without members
        $s = $null

        try {
            Write-Verbose "$(Get-Date -Format 'yyyMMdd-HHmmss'): Get members of '$($pg)'"
            $members = $null
            $members = Get-ADGroupMember -Identity $pg -ErrorAction Stop
        }
        catch {
            # should catch FSPs
            try {
                $objects = $null
                $members = $null
        
                $objects = (Get-ADGroup -Identity $pg -Properties members -ErrorAction Stop).members
                $members = $objects | ForEach-Object { Get-ADObject $_ -ErrorAction Stop }
            }
            catch {
                Write-Warning "$(Get-Date -Format 'yyyMMdd-HHmmss'): Error retrieving members of '$($pg)'"
                $members = $null
                $s = 'Error'
                "" | Select-Object @bSelect
            }
        
        }
    
        if ($members) {
            $ii = 0
            foreach ($m in $members) {
                try {
                    $ii++
                    Write-Progress "Processing $($m.Name)" -PercentComplete ($ii / $members.Count * 100) -ParentId 1
                }
                catch {}

                switch ($m.objectClass) {
                    'user' {
                        $param = @{
                            'Identity'   = $m
                            'Properties' = @(
                                'WhenCreated',
                                'LastLogonDate'
                            )
                        }
                        Get-ADUser @param | Select-Object @gSelect
                    }
                    'group' {
                        $param = @{
                            'Identity'   = $m
                            'Properties' = @(
                                'WhenCreated'
                            )
                        }
                        Get-ADGroup @param | Select-Object @gSelect
                    }
                    'computer' {
                        $param = @{
                            'Identity'   = $m
                            'Properties' = @(
                                'WhenCreated',
                                'LastLogonDate'
                            )
                        }
                        Get-ADComputer @param | Select-Object @gSelect
                    }
                    'serviceAccount' {
                        $param = @{
                            'Identity'   = $m
                            'Properties' = @(
                                'WhenCreated',
                                'LastLogonDate'
                            )
                        }
                        Get-ADServiceAccount @param | Select-Object @gSelect
                    }
                    'msDS-ManagedServiceAccount' {
                        $param = @{
                            'Identity'   = $m
                            'Properties' = @(
                                'WhenCreated',
                                'LastLogonDate'
                            )
                        }
                        Get-ADServiceAccount @param | Select-Object @gSelect
                    }
                    default {
                        $param = @{
                            'Identity'   = $m
                            'Properties' = @(
                                '*'
                            )
                        }
                        Get-ADObject @param | Select-Object @gSelect
                    }
                }
            }
        }
        else {
            if (!($s)) {
                $s = 'No members'
                "" | Select-Object @bSelect
            }
        }
    }

    # output
    $protectedMembers
}