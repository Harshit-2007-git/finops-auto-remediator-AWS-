"""Regression test for the real-AWS error:
'not authorized to perform: ec2:CreateSnapshot on resource: arn:aws:ec2:ap-south-1::snapshot/*'.

Snapshot ARNs contain NO account id. A policy that lists snapshot/* with an account id never matches,
and moto does not enforce IAM, so only a static check can catch it.
"""
from __future__ import annotations

import re
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parent.parent / "template.yaml").read_text()


def test_no_snapshot_arn_contains_an_account_id():
    arns = re.findall(r"arn:[^'\"\s]*:snapshot/\*", TEMPLATE)
    assert arns, "expected snapshot ARNs in the template"
    for arn in arns:
        assert "AccountId" not in arn, f"snapshot ARN must not include the account id: {arn}"
        assert re.search(r":ec2:\$\{AWS::Region\}::snapshot/\*", arn), arn
