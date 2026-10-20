#!/usr/bin/env python3
"""
Teardown script — terminates demo EC2 instances and deletes demo EBS volumes.
"""

from __future__ import annotations

import logging
import os
import time
import boto3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def teardown_environment(region: str = "ap-south-1"):
    """Clean up resources with Project=finops-demo."""
    logger.info("Tearing down FinOps demo environment in region %s...", region)
    ec2 = boto3.client("ec2", region_name=region)

    # 1. Terminate instances
    resp = ec2.describe_instances(
        Filters=[{"Name": "tag:Project", "Values": ["finops-demo"]}]
    )
    instance_ids = []
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            if inst["State"]["Name"] != "terminated":
                instance_ids.append(inst["InstanceId"])

    if instance_ids:
        logger.info("Terminating EC2 instances: %s", instance_ids)
        ec2.terminate_instances(InstanceIds=instance_ids)
    else:
        logger.info("No active EC2 instances found to terminate.")

    # 2. Delete volumes
    vols = ec2.describe_volumes(
        Filters=[{"Name": "tag:Project", "Values": ["finops-demo"]}]
    )
    for vol in vols.get("Volumes", []):
        vol_id = vol["VolumeId"]
        # If attached, attempt detach
        attachments = vol.get("Attachments", [])
        for att in attachments:
            try:
                ec2.detach_volume(VolumeId=vol_id, Force=True)
            except Exception as e:
                logger.debug("Detach exception for %s: %s", vol_id, e)

        try:
            logger.info("Deleting EBS volume: %s", vol_id)
            ec2.delete_volume(VolumeId=vol_id)
        except Exception as e:
            logger.warning("Could not delete volume %s: %s", vol_id, e)

    logger.info("Teardown completed successfully!")


if __name__ == "__main__":
    region = os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")
    teardown_environment(region)
