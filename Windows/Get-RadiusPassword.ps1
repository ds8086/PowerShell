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