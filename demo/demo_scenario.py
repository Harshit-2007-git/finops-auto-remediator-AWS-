"""
Canonical 8-Resource Demo Scenario Specification for PixelForge Studios.

Defines the exact 8 resources used across the test suite, interactive web console,
offline simulation runner, and real AWS seeding scripts:

| Resource         | Type      | Env  | Config / Situation             | Expected Outcome |
|------------------|-----------|------|--------------------------------|------------------|
| dev-api-01       | EC2       | dev  | t3.micro, idle 5h, CPU 1.0%    | AUTO_REMEDIATE   |
| qa-runner-01     | EC2       | qa   | t3.micro, idle 5h, CPU 2.0%    | AUTO_REMEDIATE   |
| qa-loadtest-02   | EC2       | qa   | t3.micro, idle 5h, keep=true   | LOG_ONLY         |
| prod-report-01   | EC2       | prod | t3.micro, idle 5h, CPU 0.8%    | ESCALATE         |
| prod-api-01      | EC2       | prod | t3.micro, busy 5h, CPU 85.0%   | UNTOUCHED        |
| vol-dev-orphan   | EBS 1 GB  | dev  | gp3, unattached 5h             | AUTO_REMEDIATE   |
| vol-prod-orphan  | EBS 1 GB  | prod | gp3, unattached 5h             | ESCALATE         |
| vol-prod-data    | EBS 1 GB  | prod | gp3, attached to prod-api-01   | UNTOUCHED        |

Note: This file is located in demo/ (outside src/) so it is NEVER packaged into
AWS Lambda function artifacts (enforced via .samignore).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import boto3

logger = logging.getLogger(__name__)

CANONICAL_SPEC = {
    "instances": [
        {
            "name": "dev-api-01",
            "env": "dev",
            "owner": "alice@pixelforge.io",
            "instance_type": "t3.micro",
            "keep": None,
            "cpu": 1.0,
            "net_bytes": 1024,
            "expected_decision": "AUTO_REMEDIATE",
            "expected_action": "stop",
        },
        {
            "name": "qa-runner-01",
            "env": "qa",
            "owner": "bob@pixelforge.io",
            "instance_type": "t3.micro",
            "keep": None,
            "cpu": 2.0,
            "net_bytes": 1500,
            "expected_decision": "AUTO_REMEDIATE",
            "expected_action": "stop",
        },
        {
            "name": "qa-loadtest-02",
            "env": "qa",
            "owner": "bob@pixelforge.io",
            "instance_type": "t3.micro",
            "keep": "true",
            "cpu": 0.8,
            "net_bytes": 800,
            "expected_decision": "LOG_ONLY",
            "expected_action": "skip",
        },
        {
            "name": "prod-report-01",
            "env": "prod",
            "owner": "carol@pixelforge.io",
            "instance_type": "t3.micro",
            "keep": None,
            "cpu": 0.8,
            "net_bytes": 1200,
            "expected_decision": "ESCALATE",
            "expected_action": "approval_required",
        },
        {
            "name": "prod-api-01",
            "env": "prod",
            "owner": "carol@pixelforge.io",
            "instance_type": "t3.micro",
            "keep": None,
            "cpu": 85.0,
            "net_bytes": 500000,
            "expected_decision": "UNTOUCHED",
            "expected_action": "none",
        },
    ],
    "volumes": [
        {
            "name": "vol-dev-orphan",
            "env": "dev",
            "owner": "alice@pixelforge.io",
            "size": 1,
            "volume_type": "gp3",
            "attached_to": None,
            "expected_decision": "AUTO_REMEDIATE",
            "expected_action": "delete",
        },
        {
            "name": "vol-prod-orphan",
            "env": "prod",
            "owner": "carol@pixelforge.io",
            "size": 1,
            "volume_type": "gp3",
            "attached_to": None,
            "expected_decision": "ESCALATE",
            "expected_action": "approval_required",
        },
        {
            "name": "vol-prod-data",
            "env": "prod",
            "owner": "carol@pixelforge.io",
            "size": 1,
            "volume_type": "gp3",
            "attached_to": "prod-api-01",
            "expected_decision": "UNTOUCHED",
            "expected_action": "none",
        },
    ],
}


def seed_canonical_scenario(
    region: str = "ap-south-1",
    is_mock: bool = True,
    session: Any = None,
) -> dict[str, Any]:
    """Seed the canonical 8-resource scenario.

    Args:
        region: AWS region.
        is_mock: If True, uses moto backend to backdate launch/create times by 5h.
        session: Optional boto3 Session.

    Returns:
        Dict with created instance IDs, volume IDs, and resource mapping.
    """
    if session is not None:
        ec2 = session.client("ec2", region_name=region)
        cw = session.client("cloudwatch", region_name=region)
        sts = session.client("sts", region_name=region)
    else:
        ec2 = boto3.client("ec2", region_name=region)
        cw = boto3.client("cloudwatch", region_name=region)
        sts = boto3.client("sts", region_name=region)

    now = datetime.now(timezone.utc)
    past_5h = now - timedelta(hours=5)

    created_instances: dict[str, str] = {}
    created_volumes: dict[str, str] = {}

    # 1. Create EC2 Instances
    for inst_spec in CANONICAL_SPEC["instances"]:
        tags = [
            {"Key": "Name", "Value": inst_spec["name"]},
            {"Key": "Project", "Value": "finops-demo"},
            {"Key": "env", "Value": inst_spec["env"]},
            {"Key": "owner", "Value": inst_spec["owner"]},
        ]
        if inst_spec["keep"] is not None:
            tags.append({"Key": "keep", "Value": inst_spec["keep"]})

        resp = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType=inst_spec["instance_type"],
            MinCount=1,
            MaxCount=1,
            TagSpecifications=[{"ResourceType": "instance", "Tags": tags}],
        )
        instance_id = resp["Instances"][0]["InstanceId"]
        created_instances[inst_spec["name"]] = instance_id

    # 2. Create EBS Volumes
    for vol_spec in CANONICAL_SPEC["volumes"]:
        tags = [
            {"Key": "Name", "Value": vol_spec["name"]},
            {"Key": "Project", "Value": "finops-demo"},
            {"Key": "env", "Value": vol_spec["env"]},
            {"Key": "owner", "Value": vol_spec["owner"]},
            {"Key": "FinOpsFirstSeenUnattached", "Value": past_5h.isoformat()},
        ]
        v_resp = ec2.create_volume(
            AvailabilityZone=f"{region}a",
            Size=vol_spec["size"],
            VolumeType=vol_spec["volume_type"],
            TagSpecifications=[{"ResourceType": "volume", "Tags": tags}],
        )
        vol_id = v_resp["VolumeId"]
        created_volumes[vol_spec["name"]] = vol_id

    # 3. Attach vol-prod-data to prod-api-01
    prod_api_inst_id = created_instances.get("prod-api-01")
    prod_data_vol_id = created_volumes.get("vol-prod-data")
    if prod_api_inst_id and prod_data_vol_id:
        ec2.attach_volume(
            VolumeId=prod_data_vol_id,
            InstanceId=prod_api_inst_id,
            Device="/dev/sdf",
        )

    # 4. In mock mode, backdate timestamps in moto backend
    if is_mock:
        try:
            from moto.ec2 import ec2_backends
            account_id = sts.get_caller_identity().get("Account", "123456789012")
            backend = ec2_backends.get(account_id, {}).get(region)
            if not backend and ec2_backends:
                # Find any matching backend
                for acct_backends in ec2_backends.values():
                    if region in acct_backends:
                        backend = acct_backends[region]
                        break

            if backend:
                for inst_name, inst_id in created_instances.items():
                    m_inst = backend.get_instance(inst_id)
                    if m_inst:
                        m_inst.launch_time = past_5h
                for vol_name, vol_id in created_volumes.items():
                    m_vol = backend.get_volume(vol_id)
                    if m_vol:
                        m_vol.create_time = past_5h
        except Exception as e:
            logger.warning("Could not backdate moto resources: %s", e)

    # 5. Seed CloudWatch metrics across the 5h window
    metric_timestamps = [
        past_5h + timedelta(hours=1),
        past_5h + timedelta(hours=3),
        now - timedelta(minutes=15),
        now - timedelta(seconds=30),
    ]

    for inst_spec in CANONICAL_SPEC["instances"]:
        inst_id = created_instances[inst_spec["name"]]
        for ts in metric_timestamps:
            cw.put_metric_data(
                Namespace="AWS/EC2",
                MetricData=[
                    {
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "InstanceId", "Value": inst_id}],
                        "Timestamp": ts,
                        "Value": inst_spec["cpu"],
                        "Unit": "Percent",
                    },
                    {
                        "MetricName": "NetworkIn",
                        "Dimensions": [{"Name": "InstanceId", "Value": inst_id}],
                        "Timestamp": ts,
                        "Value": float(inst_spec["net_bytes"]),
                        "Unit": "Bytes",
                    },
                    {
                        "MetricName": "NetworkOut",
                        "Dimensions": [{"Name": "InstanceId", "Value": inst_id}],
                        "Timestamp": ts,
                        "Value": float(inst_spec["net_bytes"]),
                        "Unit": "Bytes",
                    },
                ],
            )

    logger.info(
        "Seeded canonical scenario: %d EC2 instances, %d EBS volumes (all 1 GB)",
        len(created_instances),
        len(created_volumes),
    )

    return {
        "instances": created_instances,
        "volumes": created_volumes,
        "total_resources": len(created_instances) + len(created_volumes),
    }
