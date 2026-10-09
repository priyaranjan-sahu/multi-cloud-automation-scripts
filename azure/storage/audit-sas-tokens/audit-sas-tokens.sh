#!/usr/bin/env bash
# Audits Azure Storage Account Shared Access Signatures (SAS) for security risks
# via Azure Resource Graph. Read-only; needs the resource-graph extension.
# Usage: ./audit-sas-tokens.sh [table|json|tsv] [output-file]
# Env:   SUBSCRIPTION_ID (limit to one subscription), PAGE_SIZE (default 1000)

set -euo pipefail

OUTPUT_FORMAT="${1:-table}"
OUTPUT_FILE="${2:-}"
PAGE_SIZE="${PAGE_SIZE:-1000}"

echo "Auditing Azure Storage Account SAS Tokens (Azure CLI / Resource Graph)"

if ! command -v az >/dev/null 2>&1; then
    echo "Error: Azure CLI (az) is not installed." >&2
    exit 1
fi

if ! az account show >/dev/null 2>&1; then
    echo "Error: Not logged into Azure CLI. Please run 'az login' first." >&2
    exit 1
fi

if ! az extension show --name resource-graph >/dev/null 2>&1; then
    echo "Installing Azure Resource Graph extension..."
    az extension add --name resource-graph --yes >/dev/null 2>&1 || true
fi

# KQL query to find storage accounts and their SAS-related configurations
KQL_QUERY="
resources
| where type =~ 'microsoft.storage/storageaccounts'
| extend 
    allowSharedKeyAccess = tobool(properties.allowSharedKeyAccess),
    minimumTlsVersion = tostring(properties.minimumTlsVersion),
    allowBlobPublicAccess = tobool(properties.allowBlobPublicAccess),
    publicNetworkAccess = tostring(properties.publicNetworkAccess),
    networkAcls = properties.networkAcls,
    sasPolicy = properties.sasPolicy
| project 
    subscriptionId,
    resourceGroup,
    storageAccountName = name,
    location,
    sku = sku.name,
    allowSharedKeyAccess,
    minimumTlsVersion,
    allowBlobPublicAccess,
    publicNetworkAccess,
    defaultAction = tostring(networkAcls.defaultAction),
    virtualNetworkRules = networkAcls.virtualNetworkRules,
    ipRules = networkAcls.ipRules,
    sasPolicyExpirationPeriod = tostring(sasPolicy.expirationAction),
    sasPolicySasExpirationPeriod = tostring(sasPolicy.sasExpirationPeriod)
| sort by resourceGroup asc, storageAccountName asc
"

SCOPE_ARGS=()
if [[ -n "${SUBSCRIPTION_ID:-}" ]]; then
    SCOPE_ARGS=(--subscriptions "$SUBSCRIPTION_ID")
fi

if [[ -n "$OUTPUT_FILE" ]]; then
    # Paginated export (complete data without truncation). Uses tsv so rows are
    # stable and mergeable regardless of the chosen display format.
    : > "$OUTPUT_FILE"
    offset=0
    total=0

    while :; do
        page="$(az graph query -q "$KQL_QUERY" "${SCOPE_ARGS[@]}" \
                --first "$PAGE_SIZE" --skip "$offset" --output tsv || true)"

        if [[ -z "$page" ]]; then
            break
        fi

        printf '%s\n' "$page" >> "$OUTPUT_FILE"
        rows="$(printf '%s\n' "$page" | wc -l | tr -d ' ')"
        total=$((total + rows))
        offset=$((offset + rows))

        if [[ "$rows" -lt "$PAGE_SIZE" ]]; then
            break
        fi
    done

    echo "Report saved to $OUTPUT_FILE ($total record(s))"
else
    echo "Executing Resource Graph query..."
    az graph query -q "$KQL_QUERY" "${SCOPE_ARGS[@]}" --output "$OUTPUT_FORMAT"
fi