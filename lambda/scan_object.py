"""Scan new data-bucket uploads and quarantine dangerous ones.

This is a lightweight content check, not a full antivirus engine. It flags:
  - blocked file extensions (for example .exe, .scr, .docm)
  - executable content (Windows PE, Linux ELF, Mach-O, shebang scripts), even if renamed
  - the standard EICAR antivirus test string
"""
import datetime
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

DATA_BUCKET = os.environ["DATA_BUCKET"]
QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
TOPIC_ARN = os.environ["TOPIC_ARN"]
BLOCKED_EXTENSIONS = {e.strip().lower() for e in os.environ.get("BLOCKED_EXTENSIONS", "").split(",") if e.strip()}
MAX_SCAN_BYTES = int(os.environ.get("MAX_SCAN_MB", "25")) * 1024 * 1024
HEAD_BYTES = 1024 * 1024

# Split in two so this source file itself is not flagged by antivirus tools
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

MAGIC = {
    b"MZ": "Windows executable (PE)",
    b"\x7fELF": "Linux executable (ELF)",
    b"\xfe\xed\xfa\xce": "Mach-O executable",
    b"\xfe\xed\xfa\xcf": "Mach-O executable",
    b"\xce\xfa\xed\xfe": "Mach-O executable",
    b"\xcf\xfa\xed\xfe": "Mach-O executable",
    b"#!": "script with shebang",
}


def notify(subject, message):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=message)


def set_tag(key, version, status):
    args = {"Bucket": DATA_BUCKET, "Key": key, "Tagging": {"TagSet": [{"Key": "ScanStatus", "Value": status}]}}
    if version:
        args["VersionId"] = version
    s3.put_object_tagging(**args)


def handler(event, context):
    detail = event.get("detail", {})
    bucket = detail.get("bucket", {}).get("name")
    obj = detail.get("object", {})
    key = obj.get("key")
    version = obj.get("version-id")
    size = obj.get("size", 0) or 0

    if bucket != DATA_BUCKET or not key:
        return {"action": "ignored"}

    findings = []
    ext = os.path.splitext(key.lower())[1]
    if ext in BLOCKED_EXTENSIONS:
        findings.append(f"blocked file type {ext}")

    partial = size > MAX_SCAN_BYTES
    get_args = {"Bucket": bucket, "Key": key}
    if version:
        get_args["VersionId"] = version
    if partial:
        get_args["Range"] = f"bytes=0-{HEAD_BYTES - 1}"

    try:
        data = s3.get_object(**get_args)["Body"].read()
    except ClientError as err:
        notify("Scan FAILED", f"Could not read s3://{bucket}/{key}: {err}")
        raise

    for signature, label in MAGIC.items():
        if data.startswith(signature):
            findings.append(label)
            break
    if EICAR in data:
        findings.append("EICAR test signature")

    if not findings:
        try:
            set_tag(key, version, "CLEAN")
        except ClientError:
            pass
        return {"action": "clean", "partial": partial}

    try:
        # Tag first: the bucket policy then blocks every reader except this function
        set_tag(key, version, "INFECTED")

        copy_source = {"Bucket": bucket, "Key": key}
        if version and version != "null":
            copy_source["VersionId"] = version
        day = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
        dest_key = f"{day}/{bucket}/{key}"
        s3.copy(copy_source, QUARANTINE_BUCKET, dest_key)

        delete_args = {"Bucket": bucket, "Key": key}
        if version:
            delete_args["VersionId"] = version
        s3.delete_object(**delete_args)
    except Exception as err:  # noqa: BLE001
        notify(
            "Containment FAILED: dangerous upload",
            f"s3://{bucket}/{key} was flagged ({'; '.join(findings)}) but could not be quarantined: {err}. "
            "Reads are blocked by the bucket policy if tagging succeeded.",
        )
        raise

    notify(
        "Containment: dangerous upload quarantined",
        f"Findings: {'; '.join(findings)}\n"
        f"Source: s3://{bucket}/{key} (version {version})\n"
        f"Moved to: s3://{QUARANTINE_BUCKET}/{dest_key}\n"
        + ("Only the first 1 MB was scanned because the file is large.\n" if partial else "")
        + "Check AWS Backup recovery points taken before detection; they may hold the same file.",
    )
    return {"action": "quarantined", "destination": dest_key, "findings": findings}
