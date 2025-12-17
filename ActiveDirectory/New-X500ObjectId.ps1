Function New-X500ObjectId {
<#
.SYNOPSIS
Generates a new X500 Object ID (OID).

.DESCRIPTION
Generates a new X500 Object ID (OID) used for creation of AD schema attribute objects.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2025.05.15 by DS :: First iteration.
    V02: 2025.12.11 by DS :: Cleaned up header.
    V03: 2025.12.16 by DS :: Line lengths.
Call From:
    PowerShell v5.1+

.INPUTS
None

.OUTPUTS
None

.PARAMETER Prefix
The prefix for the X500 Object ID (OID). The Default value is '1.2.840.113556.1.8000.2554'.

.EXAMPLE
New-X500ObjectId
Will generate a new X500 Object ID (OID) used for the creation of AD schema attribute objects.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$False,Position=0)]
    [string]$Prefix = '1.2.840.113556.1.8000.2554'
)

$Guid = [System.Guid]::NewGuid().ToString()
$Uint = @()
$Subs = @(
    @(0,4),
    @(4,4),
    @(9,4),
    @(14,4),
    @(19,4),
    @(24,6),
    @(30,6)
)

foreach ($s in $Subs) {
    $Uint += [uint64]::Parse($Guid.Substring($s[0], $s[1]), "AllowHexSpecifier")
}

$Oid = [String]::Format(
    "{0}.{1}.{2}.{3}.{4}.{5}.{6}.{7}",$Prefix,$Uint[0],$Uint[1],$Uint[2],$Uint[3],$Uint[4],$Uint[5],$Uint[6]
)
$Oid

}