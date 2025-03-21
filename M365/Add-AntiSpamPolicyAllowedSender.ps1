Function Add-AntiSpamPolicyAllowedSender {
<#
.SYNOPSIS
Adds an allowed sender address/domain to the default Exchange Online HostedContentFilterPolicy (spam).

.DESCRIPTION
Adds an allowed sender address/domain to the default Exchange Online HostedContentFilterPolicy (spam) and optionally releases quarantined messages from the sender.

.NOTES
Author: 
    DS
Notes:
    Revision 03
Revision:
    V01: 2024.02.22 by DS :: First revision
    V02: 2024.03.19 by DS :: Updated cmdlet name, header, and comments. Changed how allow lists are backed up to $env:TEMP. Added check for $SenderAddress already existing in policy allow lists.
    V03: 2025.03.21 by DS :: Updated comments and spacing.
Call From:
    PowerShell v5.1 or higher w/ ExchangeOnlineManagement module

.PARAMETER SenderAddress
The address or domain of the sender to allow and optionally release quarantined messages from, specify either as 'user@domain.tld' or 'domain.tld'.

.PARAMETER ReleaseQuarantined
Switched parameter which when specified, releases quarantined messages from the specified sender address.

.PARAMETER Force
Switched parameter which when specified, releases quarantined messages from the specified sender address without prompting for confirmation.

.EXAMPLE
Add-AntiSpamPolicyAllowedSender -SenderAddress 'James.Kirk@contoso.com'
Will add the sender address 'James.Kirk@contoso.com' as an allowed sender in the Exchange Online HostedContentFilterPolicy (spam).

.EXAMPLE
Add-AntiSpamPolicyAllowedSender -SenderAddress 'contoso.com'
Will add the sender domain 'contoso.com' as an allowed sender in the Exchange Online HostedContentFilterPolicy (spam).

.EXAMPLE
Add-AntiSpamPolicyAllowedSender -SenderAddress 'James.Kirk@contoso.com' -ReleaseQuarantined
Will add the sender address 'James.Kirk@contoso.com' as an allowed sender in the Exchange Online HostedContentFilterPolicy (spam) and release any messages from the sender address which have been quarantined as spam.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True,Position=0)]
    [string]$SenderAddress,

    [Parameter(Mandatory=$False)]
    [switch]$ReleaseQuarantined = $False,
    
    [Parameter(Mandatory=$False)]
    [switch]$Force = $False
)

Begin {

# Define and import required modules
$RequiredModules = "ExchangeOnlineManagement"
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

# Connect to Exchange Online if not already
Try {
    Get-HostedContentFilterPolicy -Identity Default | Out-Null
}
Catch [System.Management.Automation.CommandNotFoundException] {
    Write-Warning "Not connected to Exchange Online"
    Connect-ExchangeOnline
}

} # Begin

Process {

# Attempt to sanitize input if '@domain.tld' was specified
If ($SenderAddress -like "@*.*") {
    Write-Warning "SenderAddress '$SenderAddress' is invalid, use '$($SenderAddress.TrimStart('@'))' instead?" -WarningAction Inquire
    $SenderAddress = $SenderAddress.TrimStart('@')
}
If ($SenderAddress -notlike "*@*.*" -and $SenderAddress -notlike "*.*") {
    Write-Host "FAILURE: SenderAddress '$SenderAddress' is invalid. Specify SenderAddress as 'name@domain.tld' or 'domain.tld'. Exiting!" -ForegroundColor Red
    Break
}

# Default content filter policy
# |--> https://security.microsoft.com > Email & collaboration > Policies & rules > Threat policies > Anit-spam policies > Anti-spam inbound policy (Default)
$DefaultPolicy = Get-HostedContentFilterPolicy -Identity Default

switch ($SenderAddress) {
    
    # Specified sender is email address
    {$_ -like "*@*.*"} {
        If ( ($DefaultPolicy.AllowedSenders.Sender | Select-Object -ExpandProperty Address) -contains $SenderAddress ) {
            Write-Warning "'$SenderAddress' already present in AllowedSenders for hosted content filter policy '$($DefaultPolicy.Name)'"
        }
        Else {
            Write-Verbose "Export current AllowedSenders to '$env:TEMP\AllowedSenders_`$DATE.txt'"
            ($DefaultPolicy.AllowedSenders.Sender | Select-Object -ExpandProperty Address) + $SenderAddress | Out-File "$env:TEMP\AllowedSenders_$(Get-Date -Format 'yyyMMdd-HHmmss').txt" -Force
            Set-HostedContentFilterPolicy -Identity $DefaultPolicy.Guid -AllowedSenders @{Add="$SenderAddress"}
        }
    }

    # Specified sender is domain
    Default {
        If ($DefaultPolicy.AllowedSenderDomains.Domain -contains $SenderAddress) {
            Write-Warning "'$SenderAddress' already present in AllowedSenderDomains for hosted content filter policy '$($DefaultPolicy.Name)'"
        }
        Else {
            Write-Verbose "Export current AllowedSenderDomains to '$env:TEMP\AllowedSenderDomains_`$DATE.txt'"
            $DefaultPolicy.AllowedSenderDomains.Domain + $SenderAddress | Out-File "$env:TEMP\AllowedSenderDomains_$(Get-Date -Format 'yyyMMdd-HHmmss').txt" -Force
            Set-HostedContentFilterPolicy -Identity $DefaultPolicy.Guid -AllowedSenderDomains @{Add="$SenderAddress"}
        }
    }
}

# Retrieve and release quarantined messages if '-ReleaseQuarantined' used
If ($ReleaseQuarantined -eq $True) {
    
    switch ($SenderAddress) {

        # Specified sender is email address
        {$_ -like "*@*.*"} {
            $QuarantinedMessages = Get-QuarantineMessage -Direction Inbound -Type Spam -SenderAddress $SenderAddress
        }

        # Specified sender is domain
        Default {
            $QuarantinedMessages = Get-QuarantineMessage -Direction Inbound -Type Spam -SenderAddress "@$SenderAddress"
        }
    }

    # Less than 100 messages in spam quarantine
    If ($QuarantinedMessages -and ($QuarantinedMessages.Count -lt 100)) {
        
        # -Force switch used, release without confirmation
        If ($Force -eq $True) {
            $QuarantinedMessages | Release-QuarantineMessage -ReleaseToAll
        }

        # Display spam quarantined messages and prompt for release
        Else {
            $QuarantinedMessages | Format-Table ReceivedTime,SenderAddress,RecipientAddress,Subject
            $prompt = $null
            Do {
                $prompt = Read-Host -Prompt "Release quarantined spam messages shown above?(Y/n)"
            }
            Until (
                $prompt.ToLower() -in "y","n"
            )
            switch ($prompt.ToLower()) {
                'y' {
                    Write-Verbose "Releasing quarantined spam messages"
                    $QuarantinedMessages | Release-QuarantineMessage -ReleaseToAll
                }
                'n' {
                    Write-Host "MESSAGE: Not releasing spam quarantined messages" -ForegroundColor Gray
                }
            }
        }
    }

    # 100+ messages in spam quarantine
    ElseIf ($QuarantinedMessages -and ($QuarantinedMessages.Count -ge 100)) {
        Write-Warning "SenderAddress '$SenderAddress' has sent 100+ spam quarantined messages, no spam quarantined messages will be released!"
    }

    # No messages in spam quarantine
    Else {
        Write-Host "MESSAGE: SenderAddress '$SenderAddress' not found in spam quarantined messages, nothing to release" -ForegroundColor Gray
    }
}
Else {
    Write-Verbose "'-ReleaseQuarantined' not used, skip releasing spam quarantined messages"
}

} # Process

}