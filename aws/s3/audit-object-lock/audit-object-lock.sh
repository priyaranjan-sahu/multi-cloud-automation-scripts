#!/usr/bin/env bash
# Checks S3 buckets for Object Lock configuration and immutability posture.
# Read-only. Usage: ./audit-object-lock.sh [table|json] [output-file]
# Credentials come from the AWS CLI standard chain (env or AWS_PROFILE).

set -euo pipefail

OUTPUT_FORMAT="${1:-table}"
OUTPUT_FILE="${2:-}"

echo "Auditing S3 Object Lock and immutability configuration (AWS CLI)"

for tool in aws jq; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Error: required tool '$tool' is not installed." >&2
        exit 1
    fi
done

if ! aws sts get-caller-identity >/dev/null 2>&1; then
    echo "Error: not authenticated with AWS. Please run 'aws configure' or set credentials." >&2
    exit 1
fi

ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
BUCKETS="$(aws s3api list-buckets --query 'Buckets[].Name' --output text)"

# Helpers return "false"/"0"/"NONE" when a control is missing so the bucket
# shows up as needing review rather than being silently skipped.

object_lock_config() {
    local bucket="$1"
    if output="$(aws s3api get-object-lock-configuration --bucket "$bucket" \
            --output json 2>/dev/null)"; then
        enabled="$(printf '%s' "$output" | jq -r '.ObjectLockConfiguration.ObjectLockEnabled // "Disabled"')"
        mode="$(printf '%s' "$output" | jq -r '.ObjectLockConfiguration.Rule.DefaultRetention.Mode // "NONE"')"
        days="$(printf '%s' "$output" | jq -r '.ObjectLockConfiguration.Rule.DefaultRetention.Days // 0')"
        years="$(printf '%s' "$output" | jq -r '.ObjectLockConfiguration.Rule.DefaultRetention.Years // 0')"
        printf '%s\t%s\t%s\t%s\n' "$enabled" "$mode" "$days" "$years"
    else
        printf 'Disabled\tNONE\t0\t0\n'
    fi
}

versioning_enabled() {
    local bucket="$1"
    if output="$(aws s3api get-bucket-versioning --bucket "$bucket" \
            --query 'Status' --output json 2>/dev/null)"; then
        if [[ "$output" == '"Enabled"' ]]; then printf 'true'; else printf 'false'; fi
    else
        printf 'false'
    fi
}

legal_hold_enabled() {
    local bucket="$1"
    if output="$(aws s3api get-object-legal-hold --bucket "$bucket" \
            --query 'LegalHold.Status' --output json 2>/dev/null)"; then
        if [[ "$output" == '"ON"' ]]; then printf 'true'; else printf 'false'; fi
    else
        printf 'false'
    fi
}

JSON_ROWS="[]"
PROTECTED_COUNT=0
TOTAL=0

for bucket in $BUCKETS; do
    IFS=$'\t' read -r enabled mode days years <<< "$(object_lock_config "$bucket")"
    versioning="$(versioning_enabled "$bucket")"
    legal_hold="$(legal_hold_enabled "$bucket")"

    total_days=$((days + years * 365))

    fully_protected="false"
    if [[ "$enabled" == "Enabled" && ( "$mode" == "GOVERNANCE" || "$mode" == "COMPLIANCE" ) && $total_days -gt 0 && "$versioning" == "true" ]]; then
        fully_protected="true"
        PROTECTED_COUNT=$((PROTECTED_COUNT + 1))
    fi
    TOTAL=$((TOTAL + 1))

    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        row="$(jq -n \
            --arg account "$ACCOUNT" \
            --arg bucket "$bucket" \
            --arg enabled "$enabled" \
            --arg mode "$mode" \
            --argjson days "$days" \
            --argjson years "$years" \
            --argjson versioning "$versioning" \
            --argjson legal_hold "$legal_hold" \
            --argjson fully_protected "$fully_protected" \
            '{account_id:$account,bucket:$bucket,object_lock_enabled:($enabled=="Enabled"),object_lock_retention_mode:$mode,object_lock_retention_days:($days+$years*365),default_retention_mode:$mode,default_retention_days:($days|tonumber),default_retention_years:($years|tonumber),legal_hold:($legal_hold=="true"),versioning_enabled:($versioning=="true"),fully_protected:($fully_protected=="true")}')"
        JSON_ROWS="$(printf '%s' "$JSON_ROWS" | jq --argjson row "$row" '. + [$row]')"
    else
        status="REVIEW"
        if [[ "$fully_protected" == "true" ]]; then status="PROTECTED"; fi
        printf '%-9s %-45s ol=%-8s mode=%-11s days=%-4s ver=%-5s lh=%-5s\n' \
            "$status" "$bucket" "$enabled" "$mode" "$total_days" "$versioning" "$legal_hold"
    fi
done

if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    if [[ -n "$OUTPUT_FILE" ]]; then
        printf '%s\n' "$JSON_ROWS" > "$OUTPUT_FILE"
        echo "Report saved to $OUTPUT_FILE"
    else
        printf '%s\n' "$JSON_ROWS"
    fi
fi

echo "Audited $TOTAL bucket(s), $PROTECTED_COUNT fully protected (Object Lock + Versioning)." >&2