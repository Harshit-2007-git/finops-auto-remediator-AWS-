#!/usr/bin/env python3
"""
seed_real_aws.py - create the PixelForge demo resources in a REAL AWS account.

Why this exists: scripts/seed.py uses the fake AMI id "ami-12345678" (fine for moto, fails on real
AWS), launches nothing that actually burns CPU, and does not put volumes in the instances' AZ.

Creates (all tagged Project=finops-demo): 5 x t3.micro (dev-api-01, qa-runner-01, qa-loadtest-02,
prod-report-01, prod-api-01 [kept busy]) and 3 x 1 GB gp3 volumes (vol-dev-orphan, vol-prod-orphan,
vol-prod-data [attached to prod-api-01]). Orphan volumes get a back-dated FinOpsFirstSeenUnattached
tag so they qualify on the first scan.

Run from the project root:   python seed_real_aws.py [region]      (default ap-south-1)
Remove everything later with: python scripts/teardown.py   (then delete leftover snapshots by hand)
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
if (ROOT.parent / "demo").exists():  # allow running from scripts/ as well
    sys.path.insert(0, str(ROOT.parent))

from demo.demo_scenario import CANONICAL_SPEC  # noqa: E402

AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
BUSY_USER_DATA = (
    "#!/bin/bash\n"
    "nohup sh -c 'while true; do :; done' >/dev/null 2>&1 &\n"
    "nohup sh -c 'while true; do :; done' >/dev/null 2>&1 &\n"
)


def main(region: str) -> None:
    ec2 = boto3.client("ec2", region_name=region)
    ssm = boto3.client("ssm", region_name=region)

    ami = ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]
    print(f"Using Amazon Linux 2023 AMI {ami} in {region}")

    itype = CANONICAL_SPEC["instances"][0]["instance_type"]
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [itype]}],
        )["InstanceTypeOfferings"]
    }
    subnets = ec2.describe_subnets(Filters=[{"Name": "default-for-az", "Values": ["true"]}])["Subnets"]
    subnets = sorted((s for s in subnets if s["AvailabilityZone"] in offered), key=lambda s: s["AvailabilityZone"])
    if not subnets:
        sys.exit(f"No default subnet offering {itype} found. Create a default VPC (VPC console > Actions > Create default VPC).")
    subnet = subnets[0]
    az = subnet["AvailabilityZone"]
    print(f"Using subnet {subnet['SubnetId']} in {az}")

    instances: dict[str, str] = {}
    for spec in CANONICAL_SPEC["instances"]:
        tags = [
            {"Key": "Name", "Value": spec["name"]},
            {"Key": "Project", "Value": "finops-demo"},
            {"Key": "env", "Value": spec["env"]},
            {"Key": "owner", "Value": spec["owner"]},
        ]
        if spec.get("keep"):
            tags.append({"Key": "keep", "Value": spec["keep"]})
        kwargs = dict(
            ImageId=ami,
            InstanceType=spec["instance_type"],
            MinCount=1,
            MaxCount=1,
            SubnetId=subnet["SubnetId"],
            CreditSpecification={"CpuCredits": "standard"},  # no surprise unlimited-credit charges
            MetadataOptions={"HttpTokens": "required"},
            TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
        )
        if spec["name"] == "prod-api-01":  # the busy false-positive control
            kwargs["UserData"] = BUSY_USER_DATA
        resp = ec2.run_instances(**kwargs)
        instances[spec["name"]] = resp["Instances"][0]["InstanceId"]
        print(f"  launched {spec['name']:16s} {instances[spec['name']]}")

    first_seen = (datetime.now(timezone.utc) - timedelta(hours=5)).isoformat()
    volumes: dict[str, str] = {}
    for spec in CANONICAL_SPEC["volumes"]:
        tags = [
            {"Key": "Name", "Value": spec["name"]},
            {"Key": "Project", "Value": "finops-demo"},
            {"Key": "env", "Value": spec["env"]},
            {"Key": "owner", "Value": spec["owner"]},
        ]
        if spec["attached_to"] is None:
            tags.append({"Key": "FinOpsFirstSeenUnattached", "Value": first_seen})
        resp = ec2.create_volume(
            AvailabilityZone=az,
            Size=spec["size"],
            VolumeType=spec["volume_type"],
            TagSpecifications=[{"ResourceType": "volume", "Tags": tags}],
        )
        volumes[spec["name"]] = resp["VolumeId"]
        print(f"  created  {spec['name']:16s} {volumes[spec['name']]}")

    print("Waiting for instances to reach 'running'...")
    ec2.get_waiter("instance_running").wait(InstanceIds=list(instances.values()))
    print("Waiting for volumes to become 'available'...")
    ec2.get_waiter("volume_available").wait(VolumeIds=list(volumes.values()))

    for spec in CANONICAL_SPEC["volumes"]:
        if spec["attached_to"]:
            ec2.attach_volume(
                VolumeId=volumes[spec["name"]],
                InstanceId=instances[spec["attached_to"]],
                Device="/dev/sdf",
            )
            print(f"  attached {spec['name']} -> {spec['attached_to']}")

    print("\nDone. Wait about 75-90 minutes so CloudWatch has an hour of idle CPU data, then run the scanner.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "ap-south-1")
