"""AWS Organizations adapter implementation."""

import logging
from typing import Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from aws_ri.application.ports.aws_ports import OrganizationPort
from aws_ri.application.ports.exceptions import OrganizationError
from aws_ri.domain.org.account import Account, AccountId, AccountStatus
from aws_ri.domain.org.ou import OrgHierarchy, OrganizationalUnit


logger = logging.getLogger(__name__)


class OrganizationsAdapter(OrganizationPort):
    """Adapter for AWS Organizations using boto3."""

    def __init__(self, session: Optional[boto3.Session] = None):
        """Initialize Organizations adapter.

        Args:
            session: Optional boto3 session. If None, uses default session.
        """
        self.session = session or boto3.Session()
        self.client = self.session.client('organizations')

    def list_accounts(self) -> list[Account]:
        """List all accounts in the organization.

        Returns:
            List of Account entities.

        Raises:
            OrganizationError: If unable to list accounts.
        """
        try:
            accounts = []
            paginator = self.client.get_paginator('list_accounts')

            for page in paginator.paginate():
                for aws_account in page['Accounts']:
                    try:
                        account = self._map_to_domain(aws_account)
                        accounts.append(account)
                    except ValueError as e:
                        logger.warning(f"Skipping invalid account: {e}")
                        continue

            logger.info(f"Listed {len(accounts)} accounts from organization")
            return accounts

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise OrganizationError(
                    "Access denied to AWS Organizations. Ensure you have "
                    "'organizations:ListAccounts' permission."
                ) from e
            elif error_code == 'AWSOrganizationsNotInUseException':
                raise OrganizationError(
                    "AWS Organizations is not enabled for this account."
                ) from e
            else:
                raise OrganizationError(f"Failed to list accounts: {e}") from e

        except BotoCoreError as e:
            raise OrganizationError(f"AWS API error: {e}") from e

    def fetch_org_hierarchy(self) -> OrgHierarchy:
        """Fetch OU hierarchy including roots and account attachments."""
        try:
            response = self.client.list_roots()
            roots = response.get('Roots', [])
            root_ids: list[str] = []
            units: dict[str, OrganizationalUnit] = {}

            for root in roots:
                root_id = root['Id']
                root_ids.append(root_id)
                self._collect_unit_tree(
                    parent_id=root_id,
                    name=root.get('Name', 'Root'),
                    parent=None,
                    store=units,
                )

            return OrgHierarchy(roots=tuple(root_ids), units=units)
        except (ClientError, BotoCoreError) as exc:
            raise OrganizationError(f"Failed to fetch organization hierarchy: {exc}") from exc

    def _collect_unit_tree(
        self,
        parent_id: str,
        name: str,
        parent: Optional[str],
        store: dict[str, OrganizationalUnit],
    ) -> None:
        child_descriptors: list[dict] = []
        paginator = self.client.get_paginator('list_organizational_units_for_parent')
        for page in paginator.paginate(ParentId=parent_id):
            for child in page.get('OrganizationalUnits', []):
                child_descriptors.append(child)

        child_ids = [child['Id'] for child in child_descriptors]
        account_ids = self._list_accounts_for_parent(parent_id)

        store[parent_id] = OrganizationalUnit(
            id=parent_id,
            name=name,
            parent_id=parent,
            child_ou_ids=tuple(child_ids),
            account_ids=tuple(account_ids),
        )

        for child in child_descriptors:
            self._collect_unit_tree(
                parent_id=child['Id'],
                name=child.get('Name', 'OrganizationalUnit'),
                parent=parent_id,
                store=store,
            )

    def _list_accounts_for_parent(self, parent_id: str) -> list[str]:
        account_ids: list[str] = []
        paginator = self.client.get_paginator('list_accounts_for_parent')
        for page in paginator.paginate(ParentId=parent_id):
            for account in page.get('Accounts', []):
                account_ids.append(account['Id'])
        return account_ids

    def _map_to_domain(self, aws_account: dict) -> Account:
        """Map AWS API response to domain Account entity.

        Args:
            aws_account: Account dict from AWS API.

        Returns:
            Account entity.

        Raises:
            ValueError: If account data is invalid.
        """
        return Account(
            id=AccountId(aws_account['Id']),
            name=aws_account.get('Name', 'Unknown'),
            email=aws_account.get('Email', ''),
            status=AccountStatus(aws_account['Status']),
            joined_timestamp=aws_account.get('JoinedTimestamp'),
        )
