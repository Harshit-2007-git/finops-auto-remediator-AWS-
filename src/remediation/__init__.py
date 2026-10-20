"""
Remediation package for automated AWS resource cleanup.
"""

from src.remediation.handler import handler, remediate_resource

__all__ = ["remediate_resource", "handler"]
