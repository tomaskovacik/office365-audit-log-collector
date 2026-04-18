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

    [int]$MaxMailboxes = 0,

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

    Import-Module ExchangeOnlineManagement -ErrorAction Stop

    $connectionParams = @{
        ShowBanner   = $false
        Organization = $Organization
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

    Connect-ExchangeOnline @connectionParams
}

function Get-TargetMailboxes {
    if ($MailboxUPN -and $MailboxUPN.Count -gt 0) {
        return $MailboxUPN
    }

    $mailboxResultSize = if ($MaxMailboxes -gt 0) { $MaxMailboxes } else { 'Unlimited' }
    Write-Verbose ("No mailbox filter provided. Discovering user/shared mailboxes via Get-EXOMailbox (ResultSize={0})." -f $mailboxResultSize)
    return Get-EXOMailbox -ResultSize $mailboxResultSize -RecipientTypeDetails UserMailbox, SharedMailbox |
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

function Initialize-OutputWriter {
    $outputDirectory = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($outputDirectory) -and -not (Test-Path -Path $outputDirectory)) {
        New-Item -Path $outputDirectory -ItemType Directory -Force | Out-Null
    }

    $state = @{
        Format            = $OutputFormat.ToLowerInvariant()
        RecordsWritten    = 0
        JsonFirstRecord   = $true
        CsvInitialized    = $false
    }

    switch ($state.Format) {
        'json' {
            Set-Content -Path $OutputPath -Value '[' -Encoding UTF8
        }
        default {
            Set-Content -Path $OutputPath -Value '' -Encoding UTF8
        }
    }

    return $state
}

function Write-AuditRecord {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State,

        [Parameter(Mandatory = $true)]
        [object]$Record
    )

    switch ($State.Format) {
        'csv' {
            if (-not $State.CsvInitialized) {
                $Record | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
                $State.CsvInitialized = $true
            }
            else {
                $Record | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8 -Append
            }
        }
        'jsonl' {
            Add-Content -Path $OutputPath -Value ($Record | ConvertTo-Json -Depth 20 -Compress) -Encoding UTF8
        }
        default {
            $json = $Record | ConvertTo-Json -Depth 20 -Compress
            if (-not $State.JsonFirstRecord) {
                Add-Content -Path $OutputPath -Value ',' -Encoding UTF8
            }
            Add-Content -Path $OutputPath -Value $json -Encoding UTF8
            $State.JsonFirstRecord = $false
        }
    }

    $State.RecordsWritten++
}

function Complete-OutputWriter {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$State
    )

    if ($State.Format -eq 'json') {
        Add-Content -Path $OutputPath -Value ']' -Encoding UTF8
    }
}

Assert-ValidAuthParameters

$outputState = Initialize-OutputWriter

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
                $record = Convert-AuditEntry -Entry $entry -Mailbox $mailbox
                Write-AuditRecord -State $outputState -Record $record
            }
        }
        catch {
            Write-Warning ("Failed to retrieve mailbox audit logs for '{0}': {1}" -f $mailbox, $_.Exception.Message)
        }
    }

    Complete-OutputWriter -State $outputState
    Write-Host ("Exported {0} Exchange mailbox audit record(s) to {1}" -f $outputState.RecordsWritten, $OutputPath)
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
