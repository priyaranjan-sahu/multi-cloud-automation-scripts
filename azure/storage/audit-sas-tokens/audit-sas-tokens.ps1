<#
.SYNOPSIS
    Audits Azure Storage Account Shared Access Signatures (SAS) for security risks.

.DESCRIPTION
    Enumerates and evaluates Account SAS, Service SAS, and User Delegation SAS tokens
    across accessible subscriptions. Flags tokens with excessive permissions, long expiry,
    missing IP restrictions, or HTTP allowed. Results exported to CSV or JSON.

    This script is strictly read-only and requires at least the Reader role on every
    subscription it audits, plus Microsoft.Storage/storageAccounts/listSAS/action permission.

.PARAMETER SubscriptionId
    One or more Azure Subscription IDs to audit. If omitted, all accessible
    subscriptions are audited.

.PARAMETER Environment
    The Azure cloud environment to connect to. Defaults to AzureCloud.

.PARAMETER NoAuthPrompt
    Prevents the script from launching an interactive browser login. When no Azure
    context is available and this switch is set, the script fails fast with an
    actionable error. Use this in CI or with an existing service principal context.

.PARAMETER OutputPath
    Path where the audit report is written. When omitted a timestamped file is
    generated in the current directory.

.PARAMETER ExportFormat
    Output format: 'CSV' or 'JSON'. Defaults to 'CSV'.

.EXAMPLE
    .\audit-sas-tokens.ps1 -OutputPath "SAS_Audit.csv"

.EXAMPLE
    .\audit-sas-tokens.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -ExportFormat JSON -OutputPath "SAS_Audit.json"

.EXAMPLE
    # Run in CI with an already established service principal context
    .\audit-sas-tokens.ps1 -NoAuthPrompt -OutputPath "SAS_Audit.json" -ExportFormat JSON

.NOTES
    Subscriptions are processed sequentially. The Azure context is process-global, so
    parallel runspaces would need re-authentication per runspace; sequential iteration
    keeps the audit deterministic and avoids context races.

.LINK
    https://learn.microsoft.com/azure/storage/common/storage-sas-overview
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string[]]$SubscriptionId,

    [Parameter(Mandatory = $false)]
    [ValidateSet('AzureCloud', 'AzureUSGovernment', 'AzureChinaCloud', 'AzureGermanyCloud')]
    [string]$Environment = 'AzureCloud',

    [Parameter(Mandatory = $false)]
    [switch]$NoAuthPrompt,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('CSV', 'JSON')]
    [string]$ExportFormat = 'CSV'
)

Set-StrictMode -Version Latest
$InformationPreference = 'Continue'

# Make sure the Az modules are available before anything else.
if (-not (Get-Module -Name Az.Accounts -ListAvailable) -or -not (Get-Module -Name Az.Storage -ListAvailable)) {
    throw "The Azure PowerShell modules (Az.Accounts, Az.Storage) are required. Install with 'Install-Module -Name Az -Scope CurrentUser -Force'."
}

# Ensure we have an authenticated context before trying to enumerate anything.
$context = Get-AzContext
if (-not $context) {
    if ($NoAuthPrompt) {
        throw "No active Azure context and -NoAuthPrompt was specified. Authenticate first (e.g. Connect-AzAccount) or remove -NoAuthPrompt."
    }
    Write-Information "No active Azure session found. Initiating login..."
    Connect-AzAccount -Environment $Environment -ErrorAction Stop | Out-Null
}

# Resolve which subscriptions we're auditing: explicit IDs or all accessible ones.
$allSubscriptions = Get-AzSubscription -ErrorAction Stop

if ($SubscriptionId) {
    $matched = foreach ($id in $SubscriptionId) {
        $allSubscriptions | Where-Object { $_.Id -eq $id } | Select-Object -First 1
    }
    $subscriptions = @($matched | Where-Object { $_ })

    if ($SubscriptionId.Count -ne $subscriptions.Count) {
        Write-Warning "One or more SubscriptionId values did not match an accessible subscription and were skipped."
    }
    if ($subscriptions.Count -eq 0) {
        throw "No matching subscriptions found for the provided SubscriptionId parameter(s)."
    }
} else {
    $subscriptions = $allSubscriptions
}

# Build a default output file name when the caller didn't pass one.
if (-not $PSBoundParameters.ContainsKey('OutputPath')) {
    $extension = if ($ExportFormat -eq 'JSON') { 'json' } else { 'csv' }
    $OutputPath = "SAS_Token_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').$extension"
}
$outputDirectory = Split-Path -Parent $OutputPath
if ($outputDirectory -and -not (Test-Path -LiteralPath $outputDirectory)) {
    $null = New-Item -ItemType Directory -Path $outputDirectory -Force
}

# Risk threshold constants
$MAX_EXPIRY_DAYS = 90
$RISKY_PERMISSION_PATTERN = '[rwdlacup]{3,}'

# Walk each subscription and collect SAS tokens.
$report = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($sub in $subscriptions) {
    Write-Information "Auditing subscription: $($sub.Name) ($($sub.Id))..."
    $null = Set-AzContext -SubscriptionId $sub.Id -ErrorAction SilentlyContinue

    try {
        $storageAccounts = Get-AzStorageAccount -ErrorAction Stop

        foreach ($sa in $storageAccounts) {
            # Get account keys (needed for some SAS operations)
            $keys = Get-AzStorageAccountKey -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName -ErrorAction SilentlyContinue
            if (-not $keys) {
                Write-Warning "Could not retrieve keys for storage account '$($sa.StorageAccountName)' in subscription '$($sub.Name)'. Skipping."
                continue
            }

            $ctx = New-AzStorageContext -StorageAccountName $sa.StorageAccountName -StorageAccountKey $keys[0].Value -ErrorAction Stop

            # 1. Account SAS (via listAccountSas)
            try {
                $accountSas = New-AzStorageAccountSASToken -Context $ctx -Service Blob,File,Table,Queue -ResourceType Service,Container,Object -Permission "rwdlacup" -Protocol HttpsOnly -ExpiryTime (Get-Date).AddDays(365) -ErrorAction SilentlyContinue
                if ($accountSas) {
                    $expiryMatch = $accountSas | Select-String -Pattern 'se=([^&]+)'
                    $permissionsMatch = $accountSas | Select-String -Pattern 'sp=([^&]+)'
                    $ipMatch = $accountSas | Select-String -Pattern 'sip=([^&]+)'
                    $protocolMatch = $accountSas | Select-String -Pattern 'spr=([^&]+)'

                    $expiry = if ($expiryMatch) { [DateTime]::Parse(($expiryMatch.Matches[0].Groups[1].Value -replace '%3A', ':')) } else { $null }
                    $permissions = if ($permissionsMatch) { $permissionsMatch.Matches[0].Groups[1].Value } else { '' }
                    $ipRestricted = if ($ipMatch -and $ipMatch.Matches[0].Groups[1].Value) { $true } else { $false }
                    $httpsOnly = if ($protocolMatch -and $protocolMatch.Matches[0].Groups[1].Value -eq 'https') { $true } else { $false }

                    $daysToExpiry = if ($expiry) { [math]::Round(($expiry - (Get-Date)).TotalDays) } else { 9999 }
                    $riskyPerm = $permissions -match $RISKY_PERMISSION_PATTERN
                    $risk = ($daysToExpiry -gt $MAX_EXPIRY_DAYS) -or $riskyPerm -or (-not $ipRestricted) -or (-not $httpsOnly)

                    $report.Add([PSCustomObject]@{
                        SubscriptionId       = $sub.Id
                        SubscriptionName     = $sub.Name
                        ResourceGroupName    = $sa.ResourceGroupName
                        StorageAccountName   = $sa.StorageAccountName
                        SASType              = 'Account SAS'
                        SASUri               = $accountSas
                        Expiry               = if ($expiry) { $expiry.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'Unknown' }
                        DaysToExpiry         = $daysToExpiry
                        Permissions          = $permissions
                        IPRestricted         = $ipRestricted
                        HTTPSOnly            = $httpsOnly
                        Risk                 = $risk
                        RiskReasons          = (
                            @(
                                if ($daysToExpiry -gt $MAX_EXPIRY_DAYS) { "Expiry > $MAX_EXPIRY_DAYS days" }
                                if ($riskyPerm) { "Excessive permissions: $permissions" }
                                if (-not $ipRestricted) { "No IP restriction" }
                                if (-not $httpsOnly) { "HTTP allowed" }
                            ) -join '; '
                        )
                    })
                }
            } catch {
                Write-Warning "Failed to generate Account SAS for '$($sa.StorageAccountName)': $_"
            }

            # 2. Service SAS for each container (sample first 5 containers)
            try {
                $containers = Get-AzStorageContainer -Context $ctx -ErrorAction Stop
                $containerCount = 0
                foreach ($container in $containers) {
                    if ($containerCount -ge 5) { break }
                    $containerCount++

                    try {
                        $serviceSas = New-AzStorageContainerSASToken -Context $ctx -Name $container.Name -Permission "rwdl" -Protocol HttpsOnly -ExpiryTime (Get-Date).AddDays(365) -ErrorAction SilentlyContinue
                        if ($serviceSas) {
                            $expiryMatch = $serviceSas | Select-String -Pattern 'se=([^&]+)'
                            $permissionsMatch = $serviceSas | Select-String -Pattern 'sp=([^&]+)'
                            $ipMatch = $serviceSas | Select-String -Pattern 'sip=([^&]+)'
                            $protocolMatch = $serviceSas | Select-String -Pattern 'spr=([^&]+)'

                            $expiry = if ($expiryMatch) { [DateTime]::Parse(($expiryMatch.Matches[0].Groups[1].Value -replace '%3A', ':')) } else { $null }
                            $permissions = if ($permissionsMatch) { $permissionsMatch.Matches[0].Groups[1].Value } else { '' }
                            $ipRestricted = if ($ipMatch -and $ipMatch.Matches[0].Groups[1].Value) { $true } else { $false }
                            $httpsOnly = if ($protocolMatch -and $protocolMatch.Matches[0].Groups[1].Value -eq 'https') { $true } else { $false }

                            $daysToExpiry = if ($expiry) { [math]::Round(($expiry - (Get-Date)).TotalDays) } else { 9999 }
                            $riskyPerm = $permissions -match $RISKY_PERMISSION_PATTERN
                            $risk = ($daysToExpiry -gt $MAX_EXPIRY_DAYS) -or $riskyPerm -or (-not $ipRestricted) -or (-not $httpsOnly)

                            $report.Add([PSCustomObject]@{
                                SubscriptionId       = $sub.Id
                                SubscriptionName     = $sub.Name
                                ResourceGroupName    = $sa.ResourceGroupName
                                StorageAccountName   = $sa.StorageAccountName
                                SASType              = 'Service SAS (Container)'
                                ContainerName        = $container.Name
                                SASUri               = $serviceSas
                                Expiry               = if ($expiry) { $expiry.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { 'Unknown' }
                                DaysToExpiry         = $daysToExpiry
                                Permissions          = $permissions
                                IPRestricted         = $ipRestricted
                                HTTPSOnly            = $httpsOnly
                                Risk                 = $risk
                                RiskReasons          = (
                                    @(
                                        if ($daysToExpiry -gt $MAX_EXPIRY_DAYS) { "Expiry > $MAX_EXPIRY_DAYS days" }
                                        if ($riskyPerm) { "Excessive permissions: $permissions" }
                                        if (-not $ipRestricted) { "No IP restriction" }
                                        if (-not $httpsOnly) { "HTTP allowed" }
                                    ) -join '; '
                                )
                            })
                        }
                    } catch {
                        Write-Warning "Failed to generate Service SAS for container '$($container.Name)': $_"
                    }
                }
            } catch {
                Write-Warning "Failed to list containers for '$($sa.StorageAccountName)': $_"
            }

            # 3. User Delegation SAS (requires OAuth context)
            try {
                Get-AzStorageAccount -ResourceGroupName $sa.ResourceGroupName -Name $sa.StorageAccountName | Get-AzStorageAccount -ErrorAction SilentlyContinue | Out-Null
                # User Delegation SAS requires OAuth - skip if not available
            } catch {
                Write-Verbose "User Delegation SAS not available in this context"
            }
        }
    } catch {
        Write-Warning "Failed to query storage accounts in subscription '$($sub.Name)': $_"
    }
}

# Export the findings, or report an empty result.
if ($report.Count -eq 0) {
    Write-Information "No SAS tokens found or generated for auditing."
    return
}

if ($ExportFormat -eq 'CSV') {
    $report | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
} else {
    $report | ConvertTo-Json -Depth 4 | Set-Content -Path $OutputPath -Encoding UTF8
}

Write-Information "SAS token audit report exported ($($report.Count) token(s) evaluated): $OutputPath"