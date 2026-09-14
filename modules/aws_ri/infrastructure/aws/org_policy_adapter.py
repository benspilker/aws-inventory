"""AWS Organizations policy adapter."""

import logging
from typing import Optional, List

import boto3
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError

from aws_ri.application.ports.aws_ports import OrgPolicyPort
from aws_ri.application.ports.exceptions import OrgPolicyError
from aws_ri.domain.org.policies import OrgPolicy, OrgPolicySummary


logger = logging.getLogger(__name__)

POLICY_TYPES = [
    'SERVICE_CONTROL_POLICY',
    'TAG_POLICY',
    'BACKUP_POLICY',
    'AISERVICES_OPT_OUT_POLICY',
]


class OrgPolicyAdapter(OrgPolicyPort):
    """Collects organization policy data via AWS Organizations."""

    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()
        self.region = self.session.region_name or 'us-east-1'
        self.client = self.session.client('organizations', region_name=self.region)

    def fetch_policies(self) -> OrgPolicySummary:
        try:
            policies_by_type = {}

            for policy_type in POLICY_TYPES:
                policies: List[OrgPolicy] = []
                paginator = self.client.get_paginator('list_policies')
                for page in paginator.paginate(Filter=policy_type):
                    for policy in page.get('Policies', []):
                        policy_id = policy['Id']
                        targets = self._list_targets(policy_id)
                        policies.append(
                            OrgPolicy(
                                policy_id=policy_id,
                                name=policy.get('Name', 'Unnamed Policy'),
                                description=policy.get('Description', ''),
                                type=policy_type,
                                target_count=len(targets),
                                targets=targets[:50],
                            )
                        )
                if policies:
                    policies_by_type[policy_type] = policies

            return OrgPolicySummary(policies_by_type=policies_by_type)
        except EndpointConnectionError as exc:
            if self.region != 'us-east-1':
                logger.warning(
                    "Organizations endpoint not available in %s, retrying us-east-1",
                    self.region,
                )
                self.region = 'us-east-1'
                self.client = self.session.client('organizations', region_name=self.region)
                return self.fetch_policies()
            raise OrgPolicyError(
                "Failed to fetch organization policies: Organizations endpoint is unreachable. "
                "Ensure internet access or specify a supported region via profiles.yaml."
            ) from exc
        except (ClientError, BotoCoreError) as exc:
            raise OrgPolicyError(f"Failed to fetch organization policies: {exc}") from exc

    def _list_targets(self, policy_id: str) -> List[str]:
        targets: List[str] = []
        paginator = self.client.get_paginator('list_targets_for_policy')
        for page in paginator.paginate(PolicyId=policy_id):
            for target in page.get('Targets', []):
                label = f"{target.get('Type')}:{target.get('Name')}"
                targets.append(label)
        return targets
