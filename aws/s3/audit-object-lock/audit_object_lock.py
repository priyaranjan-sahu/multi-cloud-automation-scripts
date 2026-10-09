#!/usr/bin/env python3
"""Audit S3 Object Lock and Immutability Configuration.

Reports the state of S3 Object Lock, retention modes, retention periods,
and Legal Hold for every bucket in the account. Object Lock is the primary
defense against ransomware — immutable backups cannot be deleted or overwritten.

Output is written as CSV or JSON. Read-only.

Dependencies: boto3  (pip install -r requirements.txt)
"""

from __future__ import annotations

import argparse
import csv
import json
import sys

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

COLUMNS = (
    "account_id",
    "bucket",
    "region",
    "object_lock_enabled",
    "object_lock_retention_mode",
    "object_lock_retention_days",
    "default_retention_mode",
    "default_retention_days",
    "default_retention_years",
    "legal_hold",
    "versioning_enabled",
    "fully_protected",
)


def resolve_account(session: boto3.Session) -> str:
    """Return the account ID of the current caller."""
    return session.client("sts").get_caller_identity()["Account"]


def bucket_region(s3, bucket: str) -> str:
    """Resolve a bucket's region (None location implies us-east-1)."""
    try:
        location = s3.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    except ClientError:
        return "us-east-1"
    return location or "us-east-1"


def object_lock_config(s3, bucket: str) -> dict:
    """Return Object Lock configuration for a bucket."""
    try:
        response = s3.get_object_lock_configuration(Bucket=bucket)
        config = response.get("ObjectLockConfiguration", {})
        rule = config.get("Rule", {})
        default_retention = rule.get("DefaultRetention", {})
        return {
            "object_lock_enabled": config.get("ObjectLockEnabled", "Disabled") == "Enabled",
            "retention_mode": default_retention.get("Mode", "NONE"),
            "retention_days": default_retention.get("Days", 0),
            "retention_years": default_retention.get("Years", 0),
        }
    except ClientError as e:
        if e.response["Error"]["Code"] in ("ObjectLockConfigurationNotFoundError", "NoSuchBucket"):
            return {
                "object_lock_enabled": False,
                "retention_mode": "NONE",
                "retention_days": 0,
                "retention_years": 0,
            }
        raise


def bucket_versioning(s3, bucket: str) -> bool:
    """Return True if bucket versioning is enabled."""
    try:
        status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
        return status == "Enabled"
    except ClientError:
        return False


def bucket_legal_hold(s3, bucket: str) -> bool:
    """Return True if bucket has Legal Hold enabled (at bucket level)."""
    try:
        response = s3.get_object_legal_hold(Bucket=bucket)
        return response.get("LegalHold", {}).get("Status") == "ON"
    except ClientError:
        return False


def audit_bucket(s3, account: str, bucket: str) -> dict:
    region = bucket_region(s3, bucket)
    regional = s3.meta.session.client("s3", region_name=region)

    ol_config = object_lock_config(regional, bucket)
    versioning = bucket_versioning(regional, bucket)
    legal_hold = bucket_legal_hold(regional, bucket)

    retention_days = ol_config["retention_days"]
    retention_years = ol_config["retention_years"]
    total_retention_days = retention_days + (retention_years * 365)

    fully_protected = (
        ol_config["object_lock_enabled"]
        and ol_config["retention_mode"] in ("GOVERNANCE", "COMPLIANCE")
        and total_retention_days > 0
        and versioning
    )

    return {
        "account_id": account,
        "bucket": bucket,
        "region": region,
        "object_lock_enabled": ol_config["object_lock_enabled"],
        "object_lock_retention_mode": ol_config["retention_mode"],
        "object_lock_retention_days": total_retention_days,
        "default_retention_mode": ol_config["retention_mode"],
        "default_retention_days": retention_days,
        "default_retention_years": retention_years,
        "legal_hold": legal_hold,
        "versioning_enabled": versioning,
        "fully_protected": fully_protected,
    }


def write_report(rows: list[dict], output_format: str, output_file: str | None) -> None:
    if output_format == "csv":
        handle = open(output_file, "w", newline="", encoding="utf-8") if output_file else sys.stdout
        writer = csv.DictWriter(handle, fieldnames=COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
        if output_file:
            handle.close()
    else:
        payload = json.dumps(rows, indent=2, default=str)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as handle:
                handle.write(payload + "\n")
        else:
            print(payload)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit S3 Object Lock and immutability configuration.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--profile", help="AWS CLI profile to use")
    parser.add_argument("--region", default="us-east-1", help="Default region for STS/control calls")
    parser.add_argument("--bucket", action="append", help="Restrict to specific bucket(s); repeatable")
    parser.add_argument("--only-protected", action="store_true", help="Report only fully protected buckets")
    parser.add_argument("--format", choices=("csv", "json"), default="csv", help="Report format")
    parser.add_argument("--output-file", help="Write report to file instead of stdout")
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        account = resolve_account(session)
    except (NoCredentialsError, ClientError) as exc:
        print(f"Error: unable to authenticate to AWS ({exc}).", file=sys.stderr)
        return 2

    s3 = session.client("s3")
    try:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]
    except ClientError as exc:
        print(f"Error: failed to list buckets ({exc}).", file=sys.stderr)
        return 2

    if args.bucket:
        requested = set(args.bucket)
        missing = requested - set(buckets)
        if missing:
            print(
                f"Warning: bucket(s) not found in this account: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
        buckets = [b for b in buckets if b in requested]

    rows = [audit_bucket(s3, account, bucket) for bucket in buckets]
    if args.only_protected:
        rows = [row for row in rows if row["fully_protected"]]

    write_report(rows, args.format, args.output_file)
    protected_count = sum(1 for r in rows if r["fully_protected"])
    print(
        f"Audited {len(buckets)} bucket(s), {protected_count} fully protected (Object Lock + Versioning).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
