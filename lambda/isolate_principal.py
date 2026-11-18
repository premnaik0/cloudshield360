"""Deny-all a principal that tried to tamper with backups or audit logging.

Triggered by CloudTrail events (via EventBridge) such as DeleteBackupVault,
DeleteRecoveryPoint, DeleteBackupPlan, StopLogging or DeleteTrail.
"""
import datetime
import json
import os

import boto3
from botocore.exceptions import ClientError

iam = boto3.client("iam")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
MODE = os.environ.get("MODE", "enforce")
PROTECTED = {p for p in os.environ.get("PROTECTED_PRINCIPALS", "").split(",") if p}
NAME_PREFIX = os.environ["NAME_PREFIX"]

DENY_ALL = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}],
}


def notify(subject, message):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=message)


def actor(detail):
    identity = detail.get("userIdentity", {})
    user_type = identity.get("type")
    if user_type == "IAMUser":
        return user_type, identity.get("userName"), identity.get("accessKeyId"), identity.get("arn", "")
    if user_type == "AssumedRole":
        issuer = identity.get("sessionContext", {}).get("sessionIssuer", {})
        return user_type, issuer.get("userName"), None, issuer.get("arn", "")
    return user_type, None, None, ""


def handler(event, context):
    detail = event.get("detail", {})
    what = (
        f"{detail.get('eventName')} on {detail.get('eventSource')} "
        f"from {detail.get('sourceIPAddress')}"
    )
    user_type, name, key_id, arn = actor(detail)

    if user_type not in ("IAMUser", "AssumedRole") or not name:
        notify("Containment: manual action needed", f"{what}\nPrincipal type {user_type!r} cannot be isolated automatically.")
        return {"action": "manual"}

    # Silent skips: the project's own roles, AWS service roles and protected admins
    if name in PROTECTED or name.startswith(NAME_PREFIX) or name.startswith("AWSServiceRole") or "/aws-service-role/" in arn:
        return {"action": "protected", "principal": name}

    if MODE != "enforce":
        notify(
            "Containment DRY RUN: would isolate principal",
            f"{what}\nWould isolate {user_type} {name} (access key {key_id}).",
        )
        return {"action": "dry_run"}

    try:
        if user_type == "IAMUser":
            iam.put_user_policy(
                UserName=name,
                PolicyName="CloudShieldQuarantineDenyAll",
                PolicyDocument=json.dumps(DENY_ALL),
            )
            if key_id:
                iam.update_access_key(UserName=name, AccessKeyId=key_id, Status="Inactive")
            done = f"IAM user {name}: deny-all policy attached, access key {key_id} deactivated."
        else:
            now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": "*",
                        "Resource": "*",
                        "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}},
                    }
                ],
            }
            iam.put_role_policy(
                RoleName=name,
                PolicyName="CloudShieldRevokeOlderSessions",
                PolicyDocument=json.dumps(policy),
            )
            done = f"IAM role {name}: all sessions issued before {now} are now denied."
    except ClientError as err:
        notify("Containment FAILED: principal", f"{what}\nCould not isolate {user_type} {name}: {err}. Isolate it manually.")
        raise

    notify("Containment: principal isolated", f"{what}\n{done}")
    return {"action": "isolated", "principal": name}
