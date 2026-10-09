# Audit S3 Object Lock and Immutability

Identify and report on S3 Object Lock configuration, retention modes, retention periods,
and Legal Hold across all buckets. Object Lock is the primary defense against ransomware —
immutable backups cannot be deleted or overwritten. Helps enforce
[AWS S3 ransomware protection best practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).

---

## Files in this Module

| File Name | Language / Type | Description |
| :--- | :--- | :--- |
| [`audit_object_lock.py`](audit_object_lock.py) | Python (`boto3`) | Full audit of Object Lock, retention, Legal Hold, and Versioning. |
| [`audit-object-lock.sh`](audit-object-lock.sh) | Bash / AWS CLI | CLI-native audit using `aws s3api` and `jq`. |

---

## Detection Logic

A bucket is considered **fully protected** (ransomware-immune) when **all** of the following are true:

1. **Object Lock enabled** on the bucket (`ObjectLockEnabled == Enabled`).
2. **Retention mode** set to `GOVERNANCE` or `COMPLIANCE` (not `NONE`).
3. **Retention period** > 0 days (via `DefaultRetention.Days` and/or `DefaultRetention.Years`).
4. **Versioning enabled** — required for Object Lock to function.

**Legal Hold** is reported separately — it provides an additional indefinite retention overlay
independent of the retention period.

---

## Quick Start

### Python (boto3)

```bash
pip install -r ../../requirements.txt

# Report every bucket's immutability posture
python audit_object_lock.py --output-file object_lock_report.csv

# Only buckets that are fully protected (Object Lock + Versioning)
python audit_object_lock.py --only-protected --format json --output-file protected.json
```

### Bash / AWS CLI

```bash
# Table output on stdout
./audit-object-lock.sh table

# JSON export for automation
./audit-object-lock.sh json object_lock_report.json
```

---

## Permissions

Read-only access is sufficient. The caller needs:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketObjectLockConfiguration",
                "s3:GetBucketVersioning",
                "s3:GetObjectLegalHold",
                "s3:GetBucketLocation"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*"
        }
    ]
}
```

---

## Output Fields

| Column | Meaning |
| :--- | :--- |
| `account_id` | AWS account identifier. |
| `bucket` | Bucket name. |
| `region` | Bucket region. |
| `object_lock_enabled` | `true` if Object Lock is enabled on the bucket. |
| `object_lock_retention_mode` | `GOVERNANCE`, `COMPLIANCE`, or `NONE`. |
| `object_lock_retention_days` | Total retention period in days (Days + Years × 365). |
| `default_retention_mode` | Same as `object_lock_retention_mode`. |
| `default_retention_days` | Retention days from `DefaultRetention`. |
| `default_retention_years` | Retention years from `DefaultRetention`. |
| `legal_hold` | `true` if bucket-level Legal Hold is `ON`. |
| `versioning_enabled` | `true` if bucket versioning is `Enabled`. |
| `fully_protected` | **Finding** — `true` only when Object Lock enabled, mode is GOVERNANCE/COMPLIANCE, retention > 0, AND versioning enabled. |

---

## Remediation

For any bucket where `fully_protected` is `false`:

1. **Enable Object Lock** (must be done at bucket creation — cannot be enabled on existing buckets):

    ```bash
    # Must be done at creation time
    aws s3api create-bucket --bucket my-bucket --object-lock-enabled-for-bucket
    ```

2. **Set default retention** (Governance mode allows privileged users to override; Compliance mode does not):

    ```bash
    # Governance mode, 90-day retention
    aws s3api put-object-lock-configuration \
        --bucket my-bucket \
        --object-lock-configuration "ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=GOVERNANCE,Days=90}}"
    ```

3. **Enable Versioning** (required for Object Lock):

    ```bash
    aws s3api put-bucket-versioning --bucket my-bucket --versioning-configuration Status=Enabled
    ```

4. **Apply Legal Hold** for indefinite retention on specific objects:

    ```bash
    aws s3api put-object-legal-hold --bucket my-bucket --key my-object --legal-hold Status=ON
    ```

5. **Transition to Compliance mode** for regulatory requirements (cannot be changed once set):

    ```bash
    aws s3api put-object-lock-configuration \
        --bucket my-bucket \
        --object-lock-configuration "ObjectLockEnabled=Enabled,Rule={DefaultRetention={Mode=COMPLIANCE,Days=365}}"
    ```

> **Critical**: Object Lock can only be enabled at bucket creation time. For existing buckets without Object Lock, you must create a new bucket with Object Lock enabled and migrate data.
