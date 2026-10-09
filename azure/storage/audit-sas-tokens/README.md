# Audit Azure Storage Account SAS Tokens

Identify and report on Shared Access Signature (SAS) tokens across Azure Storage Accounts
that pose security risks due to excessive permissions, long expiry, missing IP restrictions,
or HTTP allowed. Helps enforce the [Azure Storage security best practices](https://learn.microsoft.com/azure/storage/common/storage-sas-overview#security-best-practices).

---

## Files in this Module

| File Name | Language / Type | Description |
| :--- | :--- | :--- |
| [`audit-sas-tokens.ps1`](audit-sas-tokens.ps1) | PowerShell (`Az.Storage`) | Full audit generating and evaluating Account SAS, Service SAS (sampled containers). |
| [`audit-sas-tokens.sh`](audit-sas-tokens.sh) | Bash / Azure CLI | Resource Graph query for SAS policy configuration across subscriptions. |
| [`audit-sas-tokens.kql`](audit-sas-tokens.kql) | KQL | Same Resource Graph query for portal-based execution. |

---

## Detection Logic

A SAS token is flagged **risky** when any of the following is true:

1. **Expiry > 90 days** — Long-lived tokens increase blast radius if leaked.
2. **Excessive permissions** — Permissions string contains `rwdlacup` (full) or `rwdl` (container full).
3. **No IP restriction** — Token usable from any IP address.
4. **HTTP allowed** — Protocol not restricted to HTTPS only.

Additionally, the audit surfaces the SAS policy configuration on each storage account:

- `allowSharedKeyAccess` — Should be `false` to enforce SAS-only access.
- `minimumTlsVersion` — Should be `TLS1_2` or higher.
- `sasPolicy.sasExpirationPeriod` — Should be set and ≤ 90 days.
- `sasPolicy.expirationAction` — Should be `Log` or `Deny`.

---

## Quick Start

### PowerShell (Az module)

```powershell
# Generate and evaluate SAS tokens across all accessible subscriptions
.\azure\storage\audit-sas-tokens\audit-sas-tokens.ps1 -OutputPath "SAS_Audit.csv"

# Specific subscription, JSON output
.\azure\storage\audit-sas-tokens\audit-sas-tokens.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -ExportFormat JSON -OutputPath "SAS_Audit.json"

# Run in CI with an already established service principal context
.\azure\storage\audit-sas-tokens\audit-sas-tokens.ps1 -NoAuthPrompt -OutputPath "SAS_Audit.json" -ExportFormat JSON
```

### Bash / Azure CLI

```bash
# Table output on stdout
./azure/storage/audit-sas-tokens/audit-sas-tokens.sh table

# TSV export for spreadsheet analysis
./azure/storage/audit-sas-tokens/audit-sas-tokens.sh tsv sas-report.tsv
```

### KQL / Azure Resource Graph Explorer

Paste [`audit-sas-tokens.kql`](audit-sas-tokens.kql) into the Azure Portal → Resource Graph Explorer.

---

## Permissions

Read-only access is sufficient. The caller needs:

- **Reader** role on each subscription (or Management Group)
- **Microsoft.Storage/storageAccounts/listSAS/action** permission (for PowerShell SAS generation)
- **Microsoft.ResourceGraph/resources/query/action** (for Bash/KQL Resource Graph query)

Inline policy example:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "Microsoft.Storage/storageAccounts/read",
                "Microsoft.Storage/storageAccounts/listSAS/action",
                "Microsoft.Storage/storageAccounts/listKeys/action",
                "Microsoft.ResourceGraph/resources/query/action"
            ],
            "Resource": "*"
        }
    ]
}
```

---

## Output Fields

| Column | Meaning |
| :--- | :--- |
| `SubscriptionId` | Azure subscription identifier. |
| `SubscriptionName` | Subscription display name. |
| `ResourceGroupName` | Resource group containing the storage account. |
| `StorageAccountName` | Storage account name. |
| `SASType` | `Account SAS`, `Service SAS (Container)`, or `User Delegation SAS`. |
| `ContainerName` | (Service SAS only) Container name. |
| `SASUri` | The generated SAS URI (for validation). |
| `Expiry` | Expiry timestamp (ISO 8601). |
| `DaysToExpiry` | Days until expiry; > 90 = risky. |
| `Permissions` | SAS permission string (e.g., `rwdl`, `rwdlacup`). |
| `IPRestricted` | `true` if IP restriction present. |
| `HTTPSOnly` | `true` if protocol restricted to HTTPS. |
| `Risk` | `true` if any risk factor triggered. |
| `RiskReasons` | Semicolon-separated list of triggered risk factors. |

---

## Remediation

For any token flagged as `Risk = true`:

1. **Regenerate** the SAS with minimal required permissions (`r` for read-only, `rw` for read-write).
2. **Set expiry** ≤ 90 days (preferably ≤ 7 days for operational tokens).
3. **Add IP restriction** to your corporate egress CIDR.
4. **Enforce HTTPS** (`spr=https`).
5. **Configure account-level SAS policy** to enforce defaults:

    ```bash
    az storage account update -g <rg> -n <account> \
        --sas-policy expiration-period 7d \
        --sas-policy expiration-action Deny
    ```

6. **Disable shared key access** to enforce SAS-only:

    ```bash
    az storage account update -g <rg> -n <account> --allow-shared-key-access false
    ```
