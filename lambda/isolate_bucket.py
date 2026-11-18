"""Isolate a bucket whose protection was weakened by an unexpected principal.

Triggered by CloudTrail events (via EventBridge) such as PutBucketPolicy,
DeleteBucketPolicy, DeletePublicAccessBlock or PutBucketVersioning.
"""
import json
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
MODE = os.environ.get("MODE", "enforce")
ISOLATABLE = {b for b in os.environ["ISOLATABLE_BUCKETS"].split(",") if b}
EXEMPT = [a for a in os.environ["EXEMPT_PRINCIPAL_ARNS"].split(",") if a]
PROTECTED = {p for p in os.environ.get("PROTECTED_PRINCIPALS", "").split(",") if p}
NAME_PREFIX = os.environ["NAME_PREFIX"]
SID = "CloudShieldIsolateBucket"


def notify(subject, message):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=message)


def actor_name(detail):
    identity = detail.get("userIdentity", {})
    user_type = identity.get("type")
    if user_type == "IAMUser":
        return identity.get("userName") or ""
    if user_type == "AssumedRole":
        return identity.get("sessionContext", {}).get("sessionIssuer", {}).get("userName") or ""
    if user_type == "AWSService":
        return "AWSService"
    return identity.get("arn", "") or ""


def handler(event, context):
    detail = event.get("detail", {})
    bucket = detail.get("requestParameters", {}).get("bucketName")
    name = actor_name(detail)
    what = (
        f"{detail.get('eventName')} on bucket {bucket} by {name or 'unknown'} "
        f"from {detail.get('sourceIPAddress')}"
    )

    if bucket not in ISOLATABLE:
        return {"action": "ignored"}

    # Silent skips: protected admins (Terraform), the project's own roles and AWS services
    if name in PROTECTED or name.startswith(NAME_PREFIX) or name == "AWSService":
        return {"action": "protected", "actor": name}

    if MODE != "enforce":
        notify("Containment DRY RUN: would isolate bucket", f"{what}\nWould isolate bucket {bucket}.")
        return {"action": "dry_run"}

    try:
        try:
            policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchBucketPolicy":
                raise
            policy = {"Version": "2012-10-17", "Statement": []}

        statements = [s for s in policy.get("Statement", []) if s.get("Sid") != SID]
        statements.append(
            {
                "Sid": SID,
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"ArnNotLike": {"aws:PrincipalArn": EXEMPT}},
            }
        )
        policy["Statement"] = statements
        s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))
    except ClientError as err:
        notify("Containment FAILED: bucket", f"{what}\nCould not isolate bucket {bucket}: {err}. Isolate it manually.")
        raise

    notify(
        "Containment: bucket isolated",
        f"{what}\nBucket {bucket} is isolated. Only response, backup and automation roles can reach it now.\n"
        "Do not run terraform apply until the investigation is done; apply restores the original policy.",
    )
    return {"action": "isolated", "bucket": bucket}
