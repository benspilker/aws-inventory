"""Application ports (interfaces) for AWS data collection.

These are abstractions that the domain/application layers depend on.
Infrastructure adapters implement these interfaces.
"""

from abc import ABC, abstractmethod
from datetime import date, datetime
from typing import Optional

from aws_ri.domain.org.account import Account
from aws_ri.domain.org.ou import OrgHierarchy
from aws_ri.domain.inventory.resource import Resource
from aws_ri.domain.cost.cost_record import CostRecord, CostData
from aws_ri.domain.posture.compliance import ConfigRuleCompliance, AdvisorFinding
from aws_ri.domain.posture.securityhub import SecurityHubFinding
from aws_ri.domain.posture.identity_center import IdentityCenterSummary
from aws_ri.domain.org.policies import OrgPolicySummary


class OrganizationPort(ABC):
    """Port for AWS Organizations operations."""

    @abstractmethod
    def list_accounts(self) -> list[Account]:
        """List all accounts in the organization.

        Returns:
            List of Account entities.

        Raises:
            OrganizationError: If unable to list accounts.
        """
        pass

    @abstractmethod
    def fetch_org_hierarchy(self) -> OrgHierarchy:
        """Fetch the AWS Organizations hierarchy (roots + OUs)."""
        pass


class InventoryPort(ABC):
    """Port for AWS Config Aggregator inventory operations."""

    @abstractmethod
    def fetch_resources(
        self,
        aggregator_name: str,
        account_ids: Optional[list[str]] = None,
        regions: Optional[list[str]] = None,
        resource_types: Optional[list[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[Resource]:
        """Fetch resources from Config Aggregator.

        Args:
            aggregator_name: Name of the Config Aggregator.
            account_ids: Optional filter by account IDs.
            regions: Optional filter by regions.
            resource_types: Optional filter by resource types.
            start_time: Optional inclusive UTC datetime for configuration capture time lower bound.
            end_time: Optional inclusive UTC datetime for configuration capture time upper bound.

        Returns:
            List of Resource entities.

        Raises:
            InventoryError: If unable to fetch resources.
        """
        pass

    @abstractmethod
    def get_aggregator_name(self) -> Optional[str]:
        """Get the first available Config Aggregator name.

        Returns:
            Aggregator name or None if not configured.
        """
        pass


class CostPort(ABC):
    """Port for AWS Cost Explorer operations."""

    @abstractmethod
    def fetch_costs(
        self,
        start_date: date,
        end_date: date,
        account_ids: Optional[list[str]] = None,
    ) -> CostData:
        """Fetch cost records from Cost Explorer.

        Args:
            start_date: Start date for cost query.
            end_date: End date for cost query.
            account_ids: Optional filter by account IDs.

        Returns:
            CostData containing cost records and region aggregates.

        Raises:
            CostError: If unable to fetch costs.
        """
        pass


class PosturePort(ABC):
    """Port for AWS Config compliance operations."""

    @abstractmethod
    def fetch_compliance(
        self,
        account_ids: Optional[list[str]] = None,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
    ) -> list[ConfigRuleCompliance]:
        """Fetch Config rule compliance summary.

        Args:
            account_ids: Optional filter by account IDs.
            start_date: Optional inclusive start date for evaluations.
            end_date: Optional inclusive end date for evaluations.

        Returns:
            List of ConfigRuleCompliance entities.

        Raises:
            PostureError: If unable to fetch compliance data.
        """
        pass


class AdvisorPort(ABC):
    """Port for AWS Trusted Advisor operations."""

    @abstractmethod
    def fetch_findings(self) -> list[AdvisorFinding]:
        """Fetch Trusted Advisor findings.

        Returns:
            List of AdvisorFinding entities.

        Raises:
            AdvisorError: If unable to fetch findings (e.g., unsupported support plan).
        """
        pass


class SecurityHubPort(ABC):
    """Port for AWS Security Hub operations."""

    @abstractmethod
    def fetch_findings(
        self,
        start_date: Optional[date] = None,
        end_date: Optional[date] = None,
        account_ids: Optional[list[str]] = None,
    ) -> list[SecurityHubFinding]:
        """Fetch Security Hub findings."""
        pass


class IdentityCenterPort(ABC):
    """Port for IAM Identity Center data."""

    @abstractmethod
    def fetch_summary(self) -> IdentityCenterSummary:
        """Fetch Identity Center summary."""
        pass


class OrgPolicyPort(ABC):
    """Port for AWS Organizations policies."""

    @abstractmethod
    def fetch_policies(self) -> OrgPolicySummary:
        """Fetch organization policies grouped by type."""
        pass


class ResourceExplorerPort(ABC):
    """Port for AWS Resource Explorer inventory."""

    @abstractmethod
    def fetch_resources(
        self,
        view_name: str,
        account_ids: Optional[list[str]] = None,
        regions: Optional[list[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[Resource]:
        """Fetch indexed resources from a Resource Explorer view."""
        pass
