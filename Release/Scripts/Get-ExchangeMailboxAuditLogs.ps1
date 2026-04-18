[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $true)]
    [datetime]$StartDate,

    [Parameter(Mandatory = $true)]
    [datetime]$EndDate,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [ValidateSet('json', 'jsonl', 'csv')]
    [string]$OutputFormat = 'json',

    [string[]]$MailboxUPN,

    [ValidateSet('Admin', 'Delegate', 'Owner', 'External')]
    [string[]]$LogonTypes,

    [string[]]$Operations,

    [int]$ResultSize = 5000,

    [switch]$ManagedIdentity,

    [string]$AppId,

    [string]$CertificateThumbprint,

    [string]$CertificateFilePath,

    [securestring]$CertificatePassword
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ValidAuthParameters {
    if ($ManagedIdentity.IsPresent) {
        return
    }

    if ([string]::IsNullOrWhiteSpace($AppId)) {
        throw 'AppId is required when not using -ManagedIdentity.'
    }

    $hasThumbprint = -not [string]::IsNullOrWhiteSpace($CertificateThumbprint)
    $hasCertFile = -not [string]::IsNullOrWhiteSpace($CertificateFilePath)

    if ($hasThumbprint -eq $hasCertFile) {
        throw 'Provide exactly one of -CertificateThumbprint or -CertificateFilePath when using app-only authentication.'
    }

    if ($hasCertFile -and $null -eq $CertificatePassword) {
        throw 'CertificatePassword is required when using -CertificateFilePath.'
    }
}

function Connect-Exchange {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'ExchangeOnlineManagement module is not installed. Install with: Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }

    Import-Module ExchangeOnlineManagement -ErrorAction Stop | Out-Null

    $connectionParams = @{
        ShowBanner  = $false
        Organization = $Organization
        CommandName = @('Get-EXOMailbox', 'Search-MailboxAuditLog')
    }

    if ($ManagedIdentity.IsPresent) {
        $connectionParams.ManagedIdentity = $true
    }
    elseif (-not [string]::IsNullOrWhiteSpace($CertificateThumbprint)) {
        $connectionParams.AppId = $AppId
        $connectionParams.CertificateThumbprint = $CertificateThumbprint
    }
    else {
        $connectionParams.AppId = $AppId
        $connectionParams.CertificateFilePath = $CertificateFilePath
        $connectionParams.CertificatePassword = $CertificatePassword
    }

    Connect-ExchangeOnline @connectionParams | Out-Null
}

function Get-TargetMailboxes {
    if ($MailboxUPN -and $MailboxUPN.Count -gt 0) {
        return $MailboxUPN
    }

    Write-Verbose 'No mailbox filter provided. Discovering user/shared mailboxes via Get-EXOMailbox.'
    return Get-EXOMailbox -ResultSize Unlimited -RecipientTypeDetails UserMailbox, SharedMailbox |
        Select-Object -ExpandProperty UserPrincipalName
}

function Convert-AuditEntry {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Entry,

        [Parameter(Mandatory = $true)]
        [string]$Mailbox
    )

    $record = [ordered]@{}
    foreach ($property in $Entry.PSObject.Properties) {
        $record[$property.Name] = $property.Value
    }

    if (-not $record.Contains('MailboxOwnerUPN')) {
        $record['MailboxOwnerUPN'] = $Mailbox
    }
    if (-not $record.Contains('CreationTime')) {
        if ($record.Contains('LastAccessed')) {
            $record['CreationTime'] = $record['LastAccessed']
        }
        elseif ($record.Contains('RunDate')) {
            $record['CreationTime'] = $record['RunDate']
        }
    }

    $record['OriginFeed'] = 'Audit.ExchangeMailbox'

    return [pscustomobject]$record
}

function Export-AuditRecords {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records
    )

    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    switch ($OutputFormat.ToLowerInvariant()) {
        'csv' {
            if ($Records.Count -eq 0) {
                Set-Content -Path $OutputPath -Value '' -Encoding UTF8
            }
            else {
                $Records | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
            }
        }
        'jsonl' {
            if ($Records.Count -eq 0) {
                Set-Content -Path $OutputPath -Value '' -Encoding UTF8
            }
            else {
                $Records |
                    ForEach-Object { $_ | ConvertTo-Json -Depth 20 -Compress } |
                    Set-Content -Path $OutputPath -Encoding UTF8
            }
        }
        default {
            $json = $Records | ConvertTo-Json -Depth 20
            Set-Content -Path $OutputPath -Value $json -Encoding UTF8
        }
    }
}

Assert-ValidAuthParameters

$allRecords = New-Object System.Collections.Generic.List[object]

try {
    Write-Verbose 'Connecting to Exchange Online.'
    Connect-Exchange

    $mailboxes = Get-TargetMailboxes
    Write-Verbose ("Querying mailbox audit logs for {0} mailbox(es)." -f $mailboxes.Count)

    foreach ($mailbox in $mailboxes) {
        try {
            $searchParams = @{
                Identity   = $mailbox
                StartDate  = $StartDate
                EndDate    = $EndDate
                ShowDetails = $true
                ResultSize = $ResultSize
            }
            if ($LogonTypes -and $LogonTypes.Count -gt 0) {
                $searchParams.LogonTypes = $LogonTypes
            }
            if ($Operations -and $Operations.Count -gt 0) {
                $searchParams.Operations = $Operations
            }

            $entries = Search-MailboxAuditLog @searchParams
            foreach ($entry in $entries) {
                $allRecords.Add((Convert-AuditEntry -Entry $entry -Mailbox $mailbox))
            }
        }
        catch {
            Write-Warning ("Failed to retrieve mailbox audit logs for '{0}': {1}" -f $mailbox, $_.Exception.Message)
        }
    }

    Export-AuditRecords -Records $allRecords.ToArray()
    Write-Host ("Exported {0} Exchange mailbox audit record(s) to {1}" -f $allRecords.Count, $OutputPath)
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}
