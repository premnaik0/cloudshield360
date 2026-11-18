"""Isolate a suspect EC2 instance of the app tier.

Steps: swap its security groups for a no-traffic group, tag it, snapshot its disks for forensics,
and detach it from the Auto Scaling group (which launches a clean replacement and removes the
instance from the load balancer).

Triggered by tagging an instance SecurityIsolate=true (CloudTrail CreateTags event),
or by invoking the function with {"instance_id": "i-..."}.
"""
import os

import boto3
from botocore.exceptions import ClientError

ec2 = boto3.client("ec2")
autoscaling = boto3.client("autoscaling")
sns = boto3.client("sns")

TOPIC_ARN = os.environ["TOPIC_ARN"]
MODE = os.environ.get("MODE", "enforce")
QUARANTINE_SG = os.environ["QUARANTINE_SG_ID"]
VPC_ID = os.environ["VPC_ID"]
ASG_NAME = os.environ["ASG_NAME"]


def notify(subject, message):
    sns.publish(TopicArn=TOPIC_ARN, Subject=subject[:100], Message=message)


def instance_ids(event):
    ids = []
    items = event.get("detail", {}).get("requestParameters", {}).get("resourcesSet", {}).get("items", [])
    for item in items:
        resource_id = item.get("resourceId", "")
        if resource_id.startswith("i-"):
            ids.append(resource_id)
    if event.get("instance_id"):
        ids.append(event["instance_id"])
    return ids


def handler(event, context):
    ids = instance_ids(event)
    if not ids:
        return {"action": "ignored"}

    requested_by = event.get("detail", {}).get("userIdentity", {}).get("arn", "manual invoke")
    results = []

    for instance_id in ids:
        try:
            reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
            instance = reservations[0]["Instances"][0]
        except (ClientError, IndexError) as err:
            notify("Containment FAILED: instance lookup", f"Could not describe {instance_id}: {err}")
            results.append({"instance": instance_id, "action": "lookup_failed"})
            continue

        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        if instance.get("VpcId") != VPC_ID or tags.get("Project") != "CloudShield360":
            results.append({"instance": instance_id, "action": "not_project_instance"})
            continue

        if MODE != "enforce":
            notify(
                "Containment DRY RUN: would isolate instance",
                f"Requested by {requested_by}\nWould isolate {instance_id}: quarantine security group, "
                "forensic snapshots, detach from the Auto Scaling group.",
            )
            results.append({"instance": instance_id, "action": "dry_run"})
            continue

        steps = []
        try:
            ec2.modify_instance_attribute(InstanceId=instance_id, Groups=[QUARANTINE_SG])
            steps.append("security group replaced by the quarantine group (no traffic in or out)")
            ec2.create_tags(Resources=[instance_id], Tags=[{"Key": "Quarantined", "Value": "true"}])

            snapshots = []
            for mapping in instance.get("BlockDeviceMappings", []):
                volume_id = mapping.get("Ebs", {}).get("VolumeId")
                if not volume_id:
                    continue
                snap = ec2.create_snapshot(
                    VolumeId=volume_id,
                    Description=f"CloudShield forensic copy of {instance_id}",
                    TagSpecifications=[
                        {
                            "ResourceType": "snapshot",
                            "Tags": [
                                {"Key": "Project", "Value": "CloudShield360"},
                                {"Key": "Forensics", "Value": instance_id},
                            ],
                        }
                    ],
                )
                snapshots.append(snap["SnapshotId"])
            steps.append(f"snapshots started: {', '.join(snapshots) or 'none'}")

            try:
                autoscaling.detach_instances(
                    InstanceIds=[instance_id],
                    AutoScalingGroupName=ASG_NAME,
                    ShouldDecrementDesiredCapacity=False,
                )
                steps.append("detached from the Auto Scaling group; a clean replacement is launching")
            except ClientError as err:
                steps.append(f"could not detach from the Auto Scaling group: {err}")
        except ClientError as err:
            notify(
                "Containment FAILED: instance",
                f"{instance_id}: {err}\nCompleted so far: {'; '.join(steps) or 'nothing'}. Isolate it manually.",
            )
            raise

        notify(
            "Containment: instance isolated",
            f"Requested by {requested_by}\nInstance {instance_id}:\n- " + "\n- ".join(steps)
            + "\nThe instance is still running for investigation. Terminate it when finished.",
        )
        results.append({"instance": instance_id, "action": "isolated"})

    return {"results": results}
