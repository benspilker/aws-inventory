"""Report domain model - aggregates all bounded contexts."""

from dataclasses import dataclass, field
from datetime import datetime, date
from typing import Optional

from aws_ri import __version__
from aws_ri.domain.org.account import AccountScope
from aws_ri.domain.inventory.resource import ResourceInventory
from aws_ri.domain.cost.cost_record import CostSummary
from aws_ri.domain.posture.compliance import ComplianceSummary, AdvisorSummary
from aws_ri.domain.posture.securityhub import SecurityHubSummary
from aws_ri.domain.posture.account_posture import AccountPostureSummary
from aws_ri.domain.posture.identity_center import IdentityCenterSummary
from aws_ri.domain.org.policies import OrgPolicySummary
from aws_ri.domain.org.ou import OrgHierarchy


@dataclass
class ReportMetadata:
    """Report generation metadata."""
    generated_at: datetime
    time_window_days: int
    included_regions: list[str]
    aggregator_name: Optional[str] = None
    lite_mode: bool = False
    tool_version: str = __version__
    aws_account_id: Optional[str] = None
    aws_principal_arn: Optional[str] = None
    processing_duration_seconds: Optional[float] = None
    data_collection_seconds: Optional[float] = None
    data_processing_seconds: Optional[float] = None
    data_reporting_seconds: Optional[float] = None
    cost_start_date: Optional[date] = None
    cost_end_date: Optional[date] = None


@dataclass
class ReportModel:
    """Complete AWS Resource Inventory report.

    Aggregates all bounded contexts into a single report model.
    This is the domain model passed to the report writer.
    """
    metadata: ReportMetadata
    accounts: AccountScope
    inventory: ResourceInventory
    costs: Optional[CostSummary] = None
    compliance: Optional[ComplianceSummary] = None
    advisor: Optional[AdvisorSummary] = None
    security_hub: Optional[SecurityHubSummary] = None
    identity_center: Optional[IdentityCenterSummary] = None
    policies: Optional[OrgPolicySummary] = None
    org_hierarchy: Optional[OrgHierarchy] = None
    collection_status: dict[str, str] = field(default_factory=dict)
    account_posture: Optional[AccountPostureSummary] = None

    def has_costs(self) -> bool:
        """Check if cost data is included."""
        return self.costs is not None

    def has_posture(self) -> bool:
        """Check if posture data is included."""
        return (
            self.compliance is not None
            or self.advisor is not None
            or self.security_hub is not None
        )

    def summary_kpis(self) -> dict[str, any]:
        """Calculate summary KPIs for dashboard.

        Domain calculation: aggregates metrics across all contexts.
        """
        kpis = {
            "total_accounts": len(self.accounts),
            "active_accounts": len(self.accounts.active_accounts()),
            "total_resources": self.inventory.total_count(),
            "tag_coverage_pct": self.inventory.tag_coverage(),
            "generated_at": self.metadata.generated_at.isoformat(),
            "time_window_days": self.metadata.time_window_days,
        }

        if self.costs:
            kpis["total_cost_usd"] = float(self.costs.total_cost())
            kpis["top_cost_account"] = self.costs.top_accounts(1)[0] if self.costs.top_accounts(1) else None
            kpis["top_cost_service"] = self.costs.top_services(1)[0] if self.costs.top_services(1) else None

        if self.compliance:
            kpis["compliance_rate_pct"] = self.compliance.overall_compliance_rate()
            kpis["total_violations"] = self.compliance.total_violations()
            kpis["total_config_rules"] = self.compliance.total_rules()

        if self.advisor:
            kpis["total_advisor_checks"] = self.advisor.total_checks()
            kpis["advisor_flagged_resources"] = self.advisor.total_flagged_resources()

        if self.security_hub:
            kpis["security_hub_findings"] = self.security_hub.total_findings()
            kpis["security_hub_open_findings"] = self.security_hub.open_findings()

        if self.identity_center:
            kpis["identity_center_instances"] = self.identity_center.total_instances()
            kpis["identity_center_permission_sets"] = self.identity_center.total_permission_sets()

        if self.policies:
            kpis["policy_types"] = len(self.policies.types())
            kpis["total_policies"] = self.policies.total_policies()

        return kpis
