"""IAM Identity Center adapter."""

import logging
from typing import Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, EndpointConnectionError

from aws_ri.application.ports.aws_ports import IdentityCenterPort
from aws_ri.application.ports.exceptions import IdentityCenterError
from aws_ri.domain.posture.identity_center import (
    IdentityCenterAssignment,
    IdentityCenterGroup,
    IdentityCenterInstance,
    IdentityCenterSummary,
    IdentityCenterUser,
)


logger = logging.getLogger(__name__)

MAX_PERMISSION_SET_SAMPLES = 50
MAX_USER_SAMPLES = 50
MAX_GROUP_SAMPLES = 50
MAX_ASSIGNMENT_SAMPLES = 150


class IdentityCenterAdapter(IdentityCenterPort):
    """Adapter using SSO Admin and Identity Store APIs to summarize IAM Identity Center."""

    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()
        self.region = self.session.region_name or 'us-east-1'
        self._init_clients(self.region)

    def fetch_summary(self) -> IdentityCenterSummary:
        try:
            instances: List[IdentityCenterInstance] = []
            for inst in self._paginate('list_instances', 'Instances', {}):
                instance_arn = inst.get('InstanceArn')
                identity_store_id = inst.get('IdentityStoreId')
                region = inst.get('Region') or self.session.region_name or 'us-east-1'

                permission_sets = list(
                    self._paginate(
                        'list_permission_sets',
                        'PermissionSets',
                        {'InstanceArn': instance_arn},
                    )
                )

                user_total, user_samples, user_lookup = self._list_users(identity_store_id)
                group_total, group_samples, group_lookup = self._list_groups(identity_store_id)
                assignment_count, assignments = self._collect_assignments(
                    instance_arn,
                    permission_sets,
                    user_lookup,
                    group_lookup,
                )

                instances.append(
                    IdentityCenterInstance(
                        instance_arn=instance_arn,
                        identity_store_id=identity_store_id,
                        region=region,
                        permission_set_count=len(permission_sets),
                        account_assignment_count=assignment_count,
                        permission_sets=permission_sets[:MAX_PERMISSION_SET_SAMPLES],
                        user_count=user_total,
                        group_count=group_total,
                        users=user_samples,
                        groups=group_samples,
                        assignments=assignments,
                    )
                )

            return IdentityCenterSummary(instances=instances)
        except EndpointConnectionError as exc:
            if self.region != 'us-east-1':
                logger.warning(
                    "IAM Identity Center endpoint not reachable in %s, retrying us-east-1",
                    self.region,
                )
                self._init_clients('us-east-1')
                return self.fetch_summary()
            raise IdentityCenterError(
                "Failed to collect Identity Center data: endpoint unreachable. "
                "Specify a supported Identity Center region via profiles.yaml or enable IAM Identity Center."
            ) from exc
        except (ClientError, BotoCoreError) as exc:
            raise IdentityCenterError(f"Failed to collect Identity Center data: {exc}") from exc

    def _init_clients(self, region: str) -> None:
        self.region = region
        self.client = self.session.client('sso-admin', region_name=region)
        self.identitystore = self.session.client('identitystore', region_name=region)

    def _list_users(
        self,
        identity_store_id: Optional[str],
    ) -> Tuple[int, List[IdentityCenterUser], Dict[str, str]]:
        if not identity_store_id:
            return 0, [], {}

        total = 0
        samples: List[IdentityCenterUser] = []
        lookup: Dict[str, str] = {}

        paginator = self.identitystore.get_paginator('list_users')
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for user in page.get('Users', []):
                user_id = user.get('UserId')
                if not user_id:
                    continue
                total += 1
                username = user.get('UserName')
                display_name = user.get('DisplayName') or username
                email = self._extract_email(user.get('Emails', []))
                lookup[user_id] = display_name or email or username or user_id

                if len(samples) < MAX_USER_SAMPLES:
                    samples.append(
                        IdentityCenterUser(
                            user_id=user_id,
                            username=username,
                            display_name=display_name,
                            email=email,
                        )
                    )

        return total, samples, lookup

    def _list_groups(
        self,
        identity_store_id: Optional[str],
    ) -> Tuple[int, List[IdentityCenterGroup], Dict[str, str]]:
        if not identity_store_id:
            return 0, [], {}

        total = 0
        samples: List[IdentityCenterGroup] = []
        lookup: Dict[str, str] = {}

        paginator = self.identitystore.get_paginator('list_groups')
        for page in paginator.paginate(IdentityStoreId=identity_store_id):
            for group in page.get('Groups', []):
                group_id = group.get('GroupId')
                if not group_id:
                    continue
                total += 1
                display_name = group.get('DisplayName')
                description = group.get('Description')
                lookup[group_id] = display_name or description or group_id

                if len(samples) < MAX_GROUP_SAMPLES:
                    samples.append(
                        IdentityCenterGroup(
                            group_id=group_id,
                            display_name=display_name,
                            description=description,
                        )
                    )

        return total, samples, lookup

    def _collect_assignments(
        self,
        instance_arn: str,
        permission_sets: List[str],
        user_lookup: Dict[str, str],
        group_lookup: Dict[str, str],
    ) -> Tuple[int, List[IdentityCenterAssignment]]:
        total = 0
        samples: List[IdentityCenterAssignment] = []

        for permission_set in permission_sets:
            account_ids = list(
                self._paginate(
                    'list_accounts_for_provisioned_permission_set',
                    'AccountIds',
                    {
                        'InstanceArn': instance_arn,
                        'PermissionSetArn': permission_set,
                    },
                )
            )
            for account_id in account_ids:
                for assignment in self._paginate(
                    'list_account_assignments',
                    'AccountAssignments',
                    {
                        'InstanceArn': instance_arn,
                        'AccountId': account_id,
                        'PermissionSetArn': permission_set,
                    },
                ):
                    if not isinstance(assignment, dict):
                        continue
                    total += 1
                    if len(samples) >= MAX_ASSIGNMENT_SAMPLES:
                        continue
                    principal_type = assignment.get('PrincipalType', '')
                    principal_id = assignment.get('PrincipalId', '')
                    principal_name = self._resolve_principal_name(
                        principal_type,
                        principal_id,
                        user_lookup,
                        group_lookup,
                    )
                    samples.append(
                        IdentityCenterAssignment(
                            instance_arn=instance_arn,
                            account_id=account_id,
                            permission_set_arn=permission_set,
                            principal_type=principal_type,
                            principal_name=principal_name,
                        )
                    )

        return total, samples

    def _resolve_principal_name(
        self,
        principal_type: str,
        principal_id: str,
        user_lookup: Dict[str, str],
        group_lookup: Dict[str, str],
    ) -> str:
        if principal_type == 'USER':
            return user_lookup.get(principal_id, principal_id)
        if principal_type == 'GROUP':
            return group_lookup.get(principal_id, principal_id)
        return principal_id

    @staticmethod
    def _extract_email(email_entries: List[dict]) -> Optional[str]:
        primary = None
        fallback = None
        for entry in email_entries:
            value = entry.get('Value')
            if entry.get('Primary'):
                primary = value
                break
            if not fallback:
                fallback = value
        return primary or fallback

    def _paginate(self, method: str, field: str, params: dict):
        client_method = getattr(self.client, method)
        token_key = 'NextToken'
        while True:
            response = client_method(**params)
            for item in response.get(field, []):
                yield item
            token = response.get(token_key)
            if not token:
                params.pop(token_key, None)
                break
            params[token_key] = token
