"""Regression test: CloudWatch alarms publish to the KMS-encrypted escalation topic.

In the first real-AWS run the alarm history showed: 'CloudWatch Alarms does not have authorization to
access the SNS topic encryption key.' The key policy must allow the cloudwatch.amazonaws.com principal.
"""
from __future__ import annotations

from pathlib import Path

import yaml


def _load_template():
    class L(yaml.SafeLoader):
        pass

    def multi(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            v = loader.construct_scalar(node)
        elif isinstance(node, yaml.SequenceNode):
            v = loader.construct_sequence(node)
        else:
            v = loader.construct_mapping(node)
        return {("Ref" if suffix == "Ref" else "Fn::" + suffix): v}

    L.add_multi_constructor("!", multi)
    return yaml.load((Path(__file__).resolve().parent.parent / "template.yaml").read_text(), Loader=L)


def test_key_policy_lets_cloudwatch_alarms_use_the_cmk():
    tpl = _load_template()
    stmts = tpl["Resources"]["FinOpsKey"]["Properties"]["KeyPolicy"]["Statement"]
    allowed = False
    for s in stmts:
        svc = (s.get("Principal") or {}).get("Service")
        svcs = svc if isinstance(svc, list) else [svc]
        acts = s.get("Action", [])
        acts = acts if isinstance(acts, list) else [acts]
        if s.get("Effect") == "Allow" and "cloudwatch.amazonaws.com" in svcs \
                and "kms:Decrypt" in acts and any(a.startswith("kms:GenerateDataKey") for a in acts):
            allowed = True
    assert allowed, "cloudwatch.amazonaws.com must be allowed kms:Decrypt + kms:GenerateDataKey* on the CMK"


def test_alarms_notify_the_encrypted_topic():
    tpl = _load_template()
    alarm = tpl["Resources"]["RemediationFailuresAlarm"]["Properties"]
    assert {"Ref": "EscalationTopic"} in alarm["AlarmActions"]
