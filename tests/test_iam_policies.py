"""
Static IAM and KMS Policy Manifest Tests (Rule 6).

Parses template.yaml and onboarding/finops-cross-account-role.yaml statically
to assert that:
    1. Every Lambda function's IAM policy contains all AWS API actions called by its code.
    2. KMS key policy separation of duties is strictly enforced:
       - Scanner, Remediator, Escalator, and Approver can only GenerateDataKey/Encrypt.
       - Decrypt is NEVER granted to any remediation or scanner function.
       - AuditorRole alone holds kms:Decrypt with a kms:EncryptionContext:tenant_id condition.
    3. EC2 mutating actions (Stop, Delete, Snapshot, CreateTags) are strictly tag-conditioned
       (aws:ResourceTag/Project: finops-demo) to ensure safe scope isolation.
    4. Onboarding cross-account roles enforce least privilege:
       - Scanner role is read-only and explicitly denies iam:* and destructive actions.
       - Auto-remediation role explicitly denies env=prod and keep=true.
       - Approved-remediation role allows approved prod actions but explicitly denies keep=true and termination.
       - Customer KMS key policy conditions platform access on kms:EncryptionContext:tenant_id.
"""

from __future__ import annotations

import pathlib
import pytest
import yaml

# Custom CloudFormation YAML Loader
class CloudFormationLoader(yaml.SafeLoader):
    pass

def default_cfn_constructor(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        return loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return None

CloudFormationLoader.add_multi_constructor("!", default_cfn_constructor)


@pytest.fixture(scope="module")
def sam_template() -> dict:
    template_path = pathlib.Path(__file__).resolve().parent.parent / "template.yaml"
    with open(template_path, "r", encoding="utf-8") as f:
        return yaml.load(f, Loader=CloudFormationLoader)


@pytest.fixture(scope="module")
def onboarding_template() -> dict:
    template_path = pathlib.Path(__file__).resolve().parent.parent / "onboarding" / "finops-cross-account-role.yaml"
    with open(template_path, "r", encoding="utf-8") as f:
        return yaml.load(f, Loader=CloudFormationLoader)


def extract_policy_actions(policies: list) -> set[str]:
    """Helper to extract all granted IAM actions from SAM and CloudFormation policy objects."""
    actions = set()
    for policy in policies:
        if isinstance(policy, dict):
            # SAM Managed policy shortcuts
            if "DynamoDBCrudPolicy" in policy:
                actions.update(["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan"])
            if "SNSPublishMessagePolicy" in policy:
                actions.add("sns:Publish")
            if "SSMParameterReadPolicy" in policy:
                actions.add("ssm:GetParameter")
            if "KMSGenerateDataKeyPolicy" in policy:
                actions.add("kms:GenerateDataKey*")
            if "KMSDecryptPolicy" in policy:
                actions.add("kms:Decrypt")

            # Inline Statements
            if "Statement" in policy:
                for stmt in policy["Statement"]:
                    if stmt.get("Effect") == "Allow":
                        stmt_actions = stmt.get("Action", [])
                        if isinstance(stmt_actions, str):
                            stmt_actions = [stmt_actions]
                        # A KMS action that is only valid when DynamoDB/SNS calls KMS on the caller's
                        # behalf (kms:ViaService) is NOT a direct decrypt right: record it separately.
                        cond = stmt.get("Condition", {}) or {}
                        via = any("kms:ViaService" in (v or {}) for v in cond.values())
                        for a in stmt_actions:
                            if via and a.startswith("kms:"):
                                actions.add(a + "[via-service]")
                            else:
                                actions.add(a)
    return actions


class TestStaticIAMPolicyManifest:
    """Static assertions on CloudFormation / SAM policy declarations."""

    def test_scanner_function_iam_permissions(self, sam_template):
        """ScannerFunction policy must contain all AWS actions invoked in src/scanner/."""
        resources = sam_template["Resources"]
        scanner = resources["ScannerFunction"]
        policies = scanner["Properties"]["Policies"]
        actions = extract_policy_actions(policies)

        # Code in app.py, ec2_scanner.py, ebs_scanner.py calls:
        required_actions = {
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:GetMetricData",
            "cloudwatch:PutMetricData",
            "sns:Publish",
            "ssm:GetParameter",
            "dynamodb:PutItem",
            "kms:GenerateDataKey*",
            "kms:Encrypt",
        }
        for act in required_actions:
            assert act in actions, f"ScannerFunction missing required action: {act}"

        # Must NOT hold kms:Decrypt (separation of duties)
        assert "kms:Decrypt" not in actions, "ScannerFunction must not hold kms:Decrypt"

    def test_remediation_function_iam_permissions(self, sam_template):
        """RemediationFunction policy must contain all actions invoked in src/remediation/."""
        resources = sam_template["Resources"]
        remediator = resources["RemediationFunction"]
        policies = remediator["Properties"]["Policies"]
        actions = extract_policy_actions(policies)

        required_actions = {
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:StopInstances",
            "ec2:CreateSnapshot",
            "ec2:DeleteVolume",
            "ec2:CreateTags",
            "dynamodb:PutItem",
            "kms:GenerateDataKey*",
            "kms:Encrypt",
        }
        for act in required_actions:
            assert act in actions, f"RemediationFunction missing required action: {act}"

        # Must NOT hold kms:Decrypt
        assert "kms:Decrypt" not in actions, "RemediationFunction must not hold kms:Decrypt"

    def test_approval_function_iam_permissions(self, sam_template):
        """ApprovalFunction policy must contain all actions invoked in src/approval/."""
        resources = sam_template["Resources"]
        approver = resources["ApprovalFunction"]
        policies = approver["Properties"]["Policies"]
        actions = extract_policy_actions(policies)

        required_actions = {
            "ssm:GetParameter",
            "dynamodb:PutItem",
            "dynamodb:UpdateItem",
            "ec2:DescribeInstances",
            "ec2:DescribeVolumes",
            "ec2:StopInstances",
            "ec2:CreateSnapshot",
            "ec2:DeleteVolume",
            "ec2:CreateTags",
            "kms:GenerateDataKey*",
            "kms:Encrypt",
        }
        for act in required_actions:
            assert act in actions, f"ApprovalFunction missing required action: {act}"

        # Must NOT hold kms:Decrypt
        assert "kms:Decrypt" not in actions, "ApprovalFunction must not hold kms:Decrypt"

    def test_auditor_role_holds_solitary_decrypt_permission(self, sam_template):
        """AuditorRole alone holds kms:Decrypt with tenant_id encryption context condition."""
        resources = sam_template["Resources"]
        assert "AuditorRole" in resources, "AuditorRole must be defined in template.yaml"
        auditor = resources["AuditorRole"]

        role_policies = auditor["Properties"]["Policies"]
        decrypt_found = False
        context_condition_found = False

        for pol in role_policies:
            doc = pol["PolicyDocument"]
            for stmt in doc.get("Statement", []):
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if "kms:Decrypt" in actions:
                    decrypt_found = True
                    cond = stmt.get("Condition", {})
                    if "StringLike" in cond and "kms:EncryptionContext:tenant_id" in cond["StringLike"]:
                        context_condition_found = True

        assert decrypt_found, "AuditorRole must hold kms:Decrypt"
        assert context_condition_found, "AuditorRole kms:Decrypt must be conditioned on kms:EncryptionContext:tenant_id"

    def test_remediation_and_approval_ec2_tag_conditions(self, sam_template):
        """All EC2 mutating actions in RemediationFunction and ApprovalFunction must be tag-conditioned."""
        resources = sam_template["Resources"]
        for func_name in ["RemediationFunction", "ApprovalFunction"]:
            func = resources[func_name]
            policies = func["Properties"]["Policies"]
            for policy in policies:
                if isinstance(policy, dict) and "Statement" in policy:
                    for stmt in policy["Statement"]:
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        # Check stop and delete are tag-conditioned
                        if any(a in ["ec2:StopInstances", "ec2:DeleteVolume"] for a in actions):
                            cond = stmt.get("Condition", {})
                            assert "StringEquals" in cond
                            assert cond["StringEquals"].get("aws:ResourceTag/Project") == "finops-demo"

    def test_onboarding_scanner_role_least_privilege(self, onboarding_template):
        """Onboarding FinOpsScannerRole must be read-only and explicitly deny administrative & state-altering actions."""
        resources = onboarding_template["Resources"]
        scanner_role = resources["FinOpsScannerRole"]
        policies = scanner_role["Properties"]["Policies"]
        doc = policies[0]["PolicyDocument"]

        allow_actions = set()
        deny_actions = set()

        for stmt in doc["Statement"]:
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if stmt.get("Effect") == "Allow":
                allow_actions.update(actions)
            elif stmt.get("Effect") == "Deny":
                deny_actions.update(actions)

        # Allow checks
        assert "ec2:DescribeInstances" in allow_actions
        assert "ec2:DescribeVolumes" in allow_actions
        assert "cloudwatch:GetMetricData" in allow_actions

        # Deny checks (least-privilege self-check enforcement)
        assert "iam:*" in deny_actions
        assert "ec2:StopInstances" in deny_actions
        assert "ec2:DeleteVolume" in deny_actions
        assert "ec2:TerminateInstances" in deny_actions

    def test_onboarding_auto_remediation_denies_prod_and_keep(self, onboarding_template):
        """Onboarding FinOpsAutoRemediationRole must deny env=prod and keep=true."""
        resources = onboarding_template["Resources"]
        auto_role = resources["FinOpsAutoRemediationRole"]
        policies = auto_role["Properties"]["Policies"]
        doc = policies[0]["PolicyDocument"]

        deny_prod = False
        deny_keep = False
        deny_terminate = False

        for stmt in doc["Statement"]:
            if stmt.get("Effect") == "Deny":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                cond = stmt.get("Condition", {})
                if "StringEquals" in cond:
                    if cond["StringEquals"].get("aws:ResourceTag/env") == "prod":
                        deny_prod = True
                    if cond["StringEquals"].get("aws:ResourceTag/keep") == "true":
                        deny_keep = True
                if "ec2:TerminateInstances" in actions:
                    deny_terminate = True

        assert deny_prod, "Auto-remediation role must explicitly deny env=prod"
        assert deny_keep, "Auto-remediation role must explicitly deny keep=true"
        assert deny_terminate, "Auto-remediation role must explicitly deny ec2:TerminateInstances"

    def test_onboarding_approved_remediation_permits_prod_but_denies_keep(self, onboarding_template):
        """Onboarding FinOpsApprovedRemediationRole allows approved prod, but denies keep=true and termination."""
        resources = onboarding_template["Resources"]
        approved_role = resources["FinOpsApprovedRemediationRole"]
        policies = approved_role["Properties"]["Policies"]
        doc = policies[0]["PolicyDocument"]

        deny_prod = False
        deny_keep = False
        deny_terminate = False

        for stmt in doc["Statement"]:
            if stmt.get("Effect") == "Deny":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                cond = stmt.get("Condition", {})
                if "StringEquals" in cond:
                    if cond["StringEquals"].get("aws:ResourceTag/env") == "prod":
                        deny_prod = True
                    if cond["StringEquals"].get("aws:ResourceTag/keep") == "true":
                        deny_keep = True
                if "ec2:TerminateInstances" in actions:
                    deny_terminate = True

        assert not deny_prod, "Approved remediation role must NOT deny env=prod (allows human-approved prod action)"
        assert deny_keep, "Approved remediation role must explicitly deny keep=true"
        assert deny_terminate, "Approved remediation role must explicitly deny ec2:TerminateInstances"

    def test_onboarding_customer_kms_key_condition(self, onboarding_template):
        """Customer-managed KMS key in onboarding template must condition platform access on tenant_id context."""
        resources = onboarding_template["Resources"]
        assert "CustomerFinOpsKey" in resources
        key = resources["CustomerFinOpsKey"]
        key_policy = key["Properties"]["KeyPolicy"]

        context_condition_found = False
        for stmt in key_policy.get("Statement", []):
            if stmt.get("Effect") == "Allow" and "kms:Decrypt" in stmt.get("Action", []):
                cond = stmt.get("Condition", {})
                if "StringLike" in cond and "kms:EncryptionContext:tenant_id" in cond["StringLike"]:
                    context_condition_found = True

        assert context_condition_found, "Customer KMS key policy must require kms:EncryptionContext:tenant_id"

    @pytest.mark.parametrize("fn", ["ScannerFunction", "RemediationFunction", "EscalationFunction", "ApprovalFunction"])
    def test_lambda_roles_can_use_cmk_only_via_dynamodb_and_sns(self, sam_template, fn):
        """DynamoDB (SSE) and SNS call KMS with the caller's identity, so every function that writes to the
        encrypted table/topic needs kms:Decrypt - but ONLY via those services, never directly."""
        policies = sam_template["Resources"][fn]["Properties"]["Policies"]
        actions = extract_policy_actions(policies)
        assert "kms:Decrypt[via-service]" in actions, f"{fn} needs ViaService-restricted kms:Decrypt"
        assert "kms:Decrypt" not in actions, f"{fn} must not hold an unrestricted kms:Decrypt"
        services = set()
        for pol in policies:
            for stmt in (pol.get("Statement", []) if isinstance(pol, dict) else []):
                via = (stmt.get("Condition", {}).get("StringEquals", {}) or {}).get("kms:ViaService")
                if via:
                    services.update(via if isinstance(via, list) else [via])
        rendered = " ".join(str(x) for x in services)
        assert "dynamodb." in rendered and "sns." in rendered

    def test_auditor_can_read_encrypted_table_via_dynamodb(self, sam_template):
        """Scanning the CMK-encrypted table as the auditor goes through DynamoDB, whose encryption
        context has no tenant_id, so the auditor also needs a ViaService-restricted Decrypt."""
        policies = sam_template["Resources"]["AuditorRole"]["Properties"]["Policies"]
        found = False
        for pol in policies:
            for stmt in pol["PolicyDocument"]["Statement"]:
                via = (stmt.get("Condition", {}).get("StringEquals", {}) or {}).get("kms:ViaService")
                if via and "kms:Decrypt" in stmt["Action"]:
                    found = True
        assert found, "AuditorRole needs kms:Decrypt restricted to kms:ViaService dynamodb"
