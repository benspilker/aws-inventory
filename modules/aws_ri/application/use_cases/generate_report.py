"""Generate Report Use Case - orchestrates the entire report generation flow."""

import logging
import time
from dataclasses import dataclass
from datetime import datetime, date, timedelta, time as dt_time, timezone
from pathlib import Path
from typing import Optional

from aws_ri.domain.org.account import AccountScope, AccountId, Account, AccountStatus
from aws_ri.domain.org.ou import OrgHierarchy
from aws_ri.domain.inventory.resource import ResourceInventory
from aws_ri.domain.cost.cost_record import CostSummary
from aws_ri.domain.posture.compliance import ComplianceSummary, AdvisorSummary
from aws_ri.domain.posture.securityhub import SecurityHubSummary
from aws_ri.domain.posture.identity_center import IdentityCenterSummary
from aws_ri.domain.org.policies import OrgPolicySummary
from aws_ri.domain.report_model import ReportModel, ReportMetadata
from aws_ri.domain.posture.account_posture import AccountPostureSummary

from aws_ri.application.ports.aws_ports import (
    OrganizationPort,
    InventoryPort,
    CostPort,
    PosturePort,
    AdvisorPort,
    SecurityHubPort,
    IdentityCenterPort,
    OrgPolicyPort,
    ResourceExplorerPort,
)
from aws_ri.application.ports.report_port import ReportWriterPort
from aws_ri.application.ports.exceptions import (
    InventoryError,
    CostError,
    PostureError,
    AdvisorError,
    SecurityHubError,
    IdentityCenterError,
    OrgPolicyError,
    OrganizationError,
)


logger = logging.getLogger(__name__)


@dataclass
class GenerateReportInput:
    """Input parameters for generate report use case."""
    output_path: Optional[Path] = None
    time_window_days: int = 30
    regions: Optional[list[str]] = None
    include_inventory: bool = True
    include_costs: bool = True
    include_posture: bool = True
    lite_mode: bool = False
    aggregator_name: Optional[str] = None
    resource_explorer_view: Optional[str] = None
    account_local_fallback: bool = False
    account_name: Optional[str] = None
    aws_account_id: Optional[str] = None
    aws_principal_arn: Optional[str] = None
    cost_start_date: Optional[date] = None
    cost_end_date: Optional[date] = None
    write_output: bool = True


@dataclass
class GenerateReportOutput:
    """Output from generate report use case."""
    report_path: Path
    summary: dict[str, any]
    report_model: Optional[ReportModel] = None


class GenerateReportUseCase:
    """Use case for generating AWS Resource Inventory report.

    Orchestrates the entire report generation flow:
    1. Discover accounts
    2. Collect inventory
    3. Collect costs (optional)
    4. Collect posture (optional)
    5. Build report model
    6. Write Excel report
    """

    def __init__(
        self,
        org_port: OrganizationPort,
        inventory_port: InventoryPort,
        cost_port: CostPort,
        posture_port: PosturePort,
        advisor_port: AdvisorPort,
        report_writer: ReportWriterPort,
        security_hub_port: SecurityHubPort,
        identity_center_port: Optional[IdentityCenterPort] = None,
        resource_explorer_port: Optional['ResourceExplorerPort'] = None,
        policies_port: Optional[OrgPolicyPort] = None,
        account_local_inventory_port: Optional[InventoryPort] = None,
        account_posture_port=None,
    ):
        self.org_port = org_port
        self.inventory_port = inventory_port
        self.cost_port = cost_port
        self.posture_port = posture_port
        self.advisor_port = advisor_port
        self.report_writer = report_writer
        self.security_hub_port = security_hub_port
        self.identity_center_port = identity_center_port
        self.resource_explorer_port = resource_explorer_port
        self.policies_port = policies_port
        self.account_local_inventory_port = account_local_inventory_port
        self.account_posture_port = account_posture_port

    def execute(self, input_params: GenerateReportInput) -> GenerateReportOutput:
        """Execute the use case.

        Args:
            input_params: Input parameters.

        Returns:
            GenerateReportOutput with report path and summary.

        Raises:
            ApplicationError: If report generation fails.
        """
        start_time = time.time()
        logger.info("Starting AWS Resource Inventory report generation")

        # Step 1: Discover accounts
        logger.info("Discovering organization accounts...")
        using_account_local_fallback = False
        try:
            accounts = self._discover_accounts()
            logger.info(f"Found {len(accounts)} accounts")
            org_hierarchy = self._collect_org_hierarchy()
        except OrganizationError:
            if not input_params.account_local_fallback:
                raise
            if not self.account_local_inventory_port or not input_params.aws_account_id:
                raise OrganizationError(
                    "Organization lookup failed and account-local fallback is not configured"
                )
            account_id = input_params.aws_account_id
            accounts = AccountScope(accounts=(Account(
                id=AccountId(account_id),
                name=input_params.account_name or f"Account {account_id}",
                email="",
                status=AccountStatus.ACTIVE,
            ),))
            using_account_local_fallback = True
            org_hierarchy = None
            logger.warning(
                "Organization lookup failed; continuing with account-local inventory for %s",
                account_id,
            )
            logger.info(
                "Account-local fallback is active for account %s; authenticated service collection will continue",
                account_id,
            )

        # Step 2: Determine aggregator name
        aggregator_name = input_params.aggregator_name
        if input_params.include_inventory:
            if using_account_local_fallback:
                if not aggregator_name:
                    aggregator_name = self.inventory_port.get_aggregator_name()
                if not aggregator_name:
                    self.inventory_port = self.account_local_inventory_port
                    aggregator_name = "Account-local service APIs"

            if not aggregator_name:
                aggregator_name = self.inventory_port.get_aggregator_name()
                if not aggregator_name:
                    raise InventoryError(
                        "No Config Aggregator found. Please configure AWS Config Aggregator "
                        "or specify aggregator name with --aggregator-name"
                    )
        else:
            if not aggregator_name:
                aggregator_name = "Inventory skipped"

        collection_start = time.time()

        # Step 3: Collect inventory
        try:
            inventory_start_date, inventory_end_date = self._resolve_window(
                days=input_params.time_window_days,
                custom_start=input_params.cost_start_date,
                custom_end=input_params.cost_end_date,
            )
        except ValueError as e:
            logger.warning(f"Invalid inventory window: {e}")
            inventory_start_date = inventory_end_date = None

        inventory = ResourceInventory(resources=[])
        if input_params.include_inventory:
            collected = None
            if input_params.resource_explorer_view and self.resource_explorer_port:
                logger.info(
                    "Collecting inventory from Resource Explorer view '%s'...",
                    input_params.resource_explorer_view,
                )
                try:
                    collected = self._collect_inventory_resource_explorer(
                        view_name=input_params.resource_explorer_view,
                        accounts=accounts,
                        regions=input_params.regions,
                        start_date=inventory_start_date,
                        end_date=inventory_end_date,
                    )
                    logger.info(
                        "Collected %s resources from Resource Explorer view '%s'",
                        collected.total_count(),
                        input_params.resource_explorer_view,
                    )
                except InventoryError as exc:
                    logger.warning(
                        "Resource Explorer inventory failed (%s). Falling back to Config Aggregator.",
                        exc,
                    )

            if collected is None:
                logger.info(f"Collecting inventory from aggregator '{aggregator_name}'...")
                try:
                    collected = self._collect_inventory(
                        aggregator_name=aggregator_name,
                        accounts=accounts,
                        regions=input_params.regions,
                        start_date=inventory_start_date,
                        end_date=inventory_end_date,
                    )
                except InventoryError:
                    if not using_account_local_fallback or not self.account_local_inventory_port:
                        raise
                    logger.warning("Config inventory failed; falling back to account-local service APIs")
                    self.inventory_port = self.account_local_inventory_port
                    aggregator_name = "Account-local service APIs"
                    collected = self._collect_inventory(
                        aggregator_name=aggregator_name,
                        accounts=accounts,
                        regions=input_params.regions,
                        start_date=inventory_start_date,
                        end_date=inventory_end_date,
                    )

            inventory = collected
            logger.info(f"Collected {inventory.total_count()} resources")
        else:
            logger.info("Skipping inventory collection (--no-inventory)")

        # Step 4: Collect costs (optional)
        costs = None
        cost_start_date = None
        cost_end_date = None
        if input_params.include_costs:
            costs, cost_start_date, cost_end_date = self._collect_costs(
                accounts=accounts,
                days=input_params.time_window_days,
                custom_start=input_params.cost_start_date,
                custom_end=input_params.cost_end_date,
            )
            if costs:
                logger.info(
                    f"Collected {len(costs.records)} cost records "
                    f"({cost_start_date} to {cost_end_date}), total: ${costs.total_cost():.2f}"
                )

        # Step 5: Collect posture (optional)
        compliance = None
        advisor = None
        security_hub = None
        identity_center = None
        policies = None
        account_posture = None
        collection_status = {}
        posture_start, posture_end = self._determine_posture_window(
            input_params=input_params,
            cost_start_date=cost_start_date,
            cost_end_date=cost_end_date,
        )

        if input_params.include_posture:
            logger.info("Collecting security posture data...")
            compliance = self._collect_compliance(
                accounts=accounts,
                start_date=posture_start,
                end_date=posture_end,
            )
            advisor = self._collect_advisor()
            security_hub = self._collect_security_hub(
                accounts=accounts,
                start_date=posture_start,
                end_date=posture_end,
            )
            identity_center = self._collect_identity_center()
            policies = self._collect_policies()
            if self.account_posture_port and using_account_local_fallback:
                try:
                    account_posture = self.account_posture_port.fetch()
                    collection_status.update(self.account_posture_port.collection_status)
                except Exception as exc:
                    logger.warning("Failed to collect account posture extensions: %s", exc)

            if compliance:
                logger.info(f"Collected compliance for {compliance.total_rules()} Config rules")
            if advisor:
                logger.info(f"Collected {advisor.total_checks()} Trusted Advisor checks")
            if security_hub:
                logger.info(f"Collected {security_hub.total_findings()} Security Hub findings")

        # Step 6: Build report model
        logger.info("Building report model...")
        data_collection_duration = time.time() - collection_start
        processing_duration = time.time() - start_time
        if using_account_local_fallback:
            collection_status.update(getattr(self.account_local_inventory_port, "collection_status", {}))
            collection_status.setdefault(
                "AWS Config Aggregator",
                "Collected" if aggregator_name != "Account-local service APIs" else "Unavailable",
            )

        report = self._build_report_model(
            accounts=accounts,
            inventory=inventory,
            costs=costs,
            compliance=compliance,
            advisor=advisor,
            security_hub=security_hub,
            identity_center=identity_center,
            policies=policies,
            org_hierarchy=org_hierarchy,
            input_params=input_params,
            aggregator_name=aggregator_name,
            processing_duration=processing_duration,
            collection_duration=data_collection_duration,
            cost_start_date=cost_start_date,
            cost_end_date=cost_end_date,
            collection_status=collection_status,
            account_posture=account_posture,
        )

        # Step 7: Determine output path
        output_path = self._determine_output_path(input_params.output_path)

        # Step 8: Write Excel report
        if input_params.write_output:
            logger.info(f"Writing report to {output_path}...")
            write_start = time.time()
            self.report_writer.write_report(report, output_path)
            report.metadata.data_reporting_seconds = time.time() - write_start

        logger.info("Report generation completed successfully")

        return GenerateReportOutput(
            report_path=output_path,
            summary=report.summary_kpis(),
            report_model=report,
        )

    def _discover_accounts(self) -> AccountScope:
        """Discover organization accounts."""
        accounts = self.org_port.list_accounts()
        return AccountScope(accounts=tuple(accounts))

    def _collect_inventory(
        self,
        aggregator_name: str,
        accounts: AccountScope,
        regions: Optional[list[str]],
        start_date: Optional[date],
        end_date: Optional[date],
    ) -> ResourceInventory:
        """Collect resource inventory."""
        account_ids = [str(acc.id) for acc in accounts.active_accounts()]

        start_dt = self._date_to_utc_datetime(start_date, is_start=True)
        end_dt = self._date_to_utc_datetime(end_date, is_start=False)

        resources = self.inventory_port.fetch_resources(
            aggregator_name=aggregator_name,
            account_ids=account_ids,
            regions=regions,
            start_time=start_dt,
            end_time=end_dt,
        )

        return ResourceInventory(resources=resources)

    def _collect_inventory_resource_explorer(
        self,
        view_name: str,
        accounts: AccountScope,
        regions: Optional[list[str]],
        start_date: Optional[date],
        end_date: Optional[date],
    ) -> ResourceInventory:
        if not self.resource_explorer_port:
            raise InventoryError("Resource Explorer port not configured")
        account_ids = [str(acc.id) for acc in accounts.active_accounts()]
        start_dt = self._date_to_utc_datetime(start_date, is_start=True)
        end_dt = self._date_to_utc_datetime(end_date, is_start=False)
        resources = self.resource_explorer_port.fetch_resources(
            view_name=view_name,
            account_ids=account_ids,
            regions=regions,
            start_time=start_dt,
            end_time=end_dt,
        )
        return ResourceInventory(resources=resources)

    def _collect_costs(
        self,
        accounts: AccountScope,
        days: int,
        custom_start: Optional[date],
        custom_end: Optional[date],
    ) -> tuple[Optional[CostSummary], Optional[date], Optional[date]]:
        """Collect cost data."""
        try:
            start_inclusive, end_inclusive = self._resolve_window(days, custom_start, custom_end)

            query_end = end_inclusive + timedelta(days=1)
            account_ids = [str(acc.id) for acc in accounts.active_accounts()]

            cost_data = self.cost_port.fetch_costs(
                start_date=start_inclusive,
                end_date=query_end,
                account_ids=account_ids,
            )

            return (
                CostSummary(
                    records=cost_data.records,
                    region_totals=cost_data.region_totals,
                ),
                start_inclusive,
                end_inclusive,
            )

        except CostError as e:
            logger.warning(f"Failed to collect costs: {e}")
            return None, None, None
        except ValueError as e:
            logger.warning(f"Invalid cost collection parameters: {e}")
            return None, None, None

    def _resolve_window(
        self,
        days: int,
        custom_start: Optional[date],
        custom_end: Optional[date],
    ) -> tuple[date, date]:
        """Resolve reporting window dates."""
        if (custom_start and not custom_end) or (custom_end and not custom_start):
            raise ValueError("Both --start-date and --end-date must be provided together")

        if custom_start and custom_end:
            start_inclusive = custom_start
            end_inclusive = custom_end
        else:
            if days <= 0:
                raise ValueError("time_window_days must be greater than zero")
            end_inclusive = date.today() - timedelta(days=1)
            start_inclusive = end_inclusive - timedelta(days=days - 1)

        if start_inclusive > end_inclusive:
            raise ValueError("start date must be on or before end date")
        return start_inclusive, end_inclusive

    @staticmethod
    def _date_to_utc_datetime(source: Optional[date], is_start: bool) -> Optional[datetime]:
        if not source:
            return None
        base_time = dt_time.min if is_start else dt_time.max
        combined = datetime.combine(source, base_time)
        return combined.replace(tzinfo=timezone.utc)

    def _collect_compliance(
        self,
        accounts: AccountScope,
        start_date: Optional[date],
        end_date: Optional[date],
    ) -> Optional[ComplianceSummary]:
        """Collect Config compliance data."""
        try:
            account_ids = [str(acc.id) for acc in accounts.active_accounts()]
            compliance_records = self.posture_port.fetch_compliance(
                account_ids=account_ids,
                start_date=start_date,
                end_date=end_date,
            )

            if not compliance_records:
                logger.warning("No Config compliance data found")
                return None

            return ComplianceSummary(config_rules=compliance_records)

        except PostureError as e:
            logger.warning(f"Failed to collect compliance data: {e}")
            return None

    def _collect_advisor(self) -> Optional[AdvisorSummary]:
        """Collect Trusted Advisor findings."""
        try:
            findings = self.advisor_port.fetch_findings()

            if not findings:
                logger.warning("No Trusted Advisor findings found")
                return None

            return AdvisorSummary(findings=findings)

        except AdvisorError as e:
            logger.warning(f"Failed to collect Trusted Advisor data: {e}")
            return None

    def _collect_security_hub(
        self,
        accounts: AccountScope,
        start_date: Optional[date],
        end_date: Optional[date],
    ) -> Optional[SecurityHubSummary]:
        """Collect Security Hub findings."""
        try:
            account_ids = [str(acc.id) for acc in accounts.active_accounts()]
            findings = self.security_hub_port.fetch_findings(
                start_date=start_date,
                end_date=end_date,
                account_ids=account_ids,
            )

            if not findings:
                logger.warning("No Security Hub findings found")
                return None

            return SecurityHubSummary(findings=findings)

        except SecurityHubError as e:
            logger.warning(f"Failed to collect Security Hub findings: {e}")
            return None
        except Exception as e:
            logger.warning(f"Failed to collect Security Hub findings: {e}")
            return None

    def _collect_identity_center(self) -> Optional[IdentityCenterSummary]:
        """Collect IAM Identity Center summary."""
        if not self.identity_center_port:
            return None

        try:
            summary = self.identity_center_port.fetch_summary()
            if not summary or summary.total_instances() == 0:
                logger.warning("No IAM Identity Center instances found")
                return None
            return summary
        except IdentityCenterError as e:
            logger.warning(f"Failed to collect Identity Center data: {e}")
            return None

    def _collect_policies(self) -> Optional[OrgPolicySummary]:
        """Collect AWS Organizations policy summary."""
        if not self.policies_port:
            return None

        try:
            summary = self.policies_port.fetch_policies()
            if not summary or summary.total_policies() == 0:
                logger.info("No organization policies detected")
                return None
            return summary
        except OrgPolicyError as e:
            logger.warning(f"Failed to collect organization policies: {e}")
            return None

    def _collect_org_hierarchy(self) -> Optional[OrgHierarchy]:
        """Collect AWS Organizations hierarchy."""
        if not hasattr(self.org_port, 'fetch_org_hierarchy'):
            return None
        try:
            hierarchy = self.org_port.fetch_org_hierarchy()
            if hierarchy and hierarchy.total_units() > 0:
                logger.info("Collected AWS Organizations hierarchy")
            return hierarchy
        except OrganizationError as e:
            logger.warning(f"Failed to collect organization hierarchy: {e}")
            return None

    def _determine_posture_window(
        self,
        input_params: GenerateReportInput,
        cost_start_date: Optional[date],
        cost_end_date: Optional[date],
    ) -> tuple[date, date]:
        """Determine the reporting window for posture collectors."""
        if cost_start_date and cost_end_date:
            return cost_start_date, cost_end_date

        if input_params.cost_start_date and input_params.cost_end_date:
            return input_params.cost_start_date, input_params.cost_end_date

        days = max(1, input_params.time_window_days)
        end_inclusive = date.today() - timedelta(days=1)
        start_inclusive = end_inclusive - timedelta(days=days - 1)
        return start_inclusive, end_inclusive

    def _build_report_model(
        self,
        accounts: AccountScope,
        inventory: ResourceInventory,
        costs: Optional[CostSummary],
        compliance: Optional[ComplianceSummary],
        advisor: Optional[AdvisorSummary],
        security_hub: Optional[SecurityHubSummary],
        identity_center: Optional[IdentityCenterSummary],
        policies: Optional[OrgPolicySummary],
        org_hierarchy: Optional[OrgHierarchy],
        input_params: GenerateReportInput,
        aggregator_name: str,
        processing_duration: float,
        collection_duration: float,
        cost_start_date: Optional[date],
        cost_end_date: Optional[date],
        collection_status: dict[str, str],
        account_posture: Optional[AccountPostureSummary],
    ) -> ReportModel:
        """Build the complete report model."""
        window_days = input_params.time_window_days
        if input_params.cost_start_date and input_params.cost_end_date:
            window_days = (input_params.cost_end_date - input_params.cost_start_date).days + 1

        metadata = ReportMetadata(
            generated_at=datetime.now(),
            time_window_days=window_days,
            included_regions=input_params.regions or [],
            aggregator_name=aggregator_name,
            lite_mode=input_params.lite_mode,
            aws_account_id=input_params.aws_account_id,
            aws_principal_arn=input_params.aws_principal_arn,
            processing_duration_seconds=processing_duration,
            data_collection_seconds=collection_duration,
            data_processing_seconds=processing_duration,
            cost_start_date=cost_start_date,
            cost_end_date=cost_end_date,
        )

        return ReportModel(
            metadata=metadata,
            accounts=accounts,
            inventory=inventory,
            costs=costs,
            compliance=compliance,
            advisor=advisor,
            security_hub=security_hub,
            identity_center=identity_center,
            policies=policies,
            org_hierarchy=org_hierarchy,
            collection_status=collection_status,
            account_posture=account_posture,
        )

    def _determine_output_path(self, requested_path: Optional[Path]) -> Path:
        """Determine final output path."""
        if requested_path:
            requested_path.parent.mkdir(parents=True, exist_ok=True)
            return requested_path

        # Generate timestamped filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H_%M")
        filename = f"AWS_Resource_Inventory_Report_{timestamp}.xlsx"
        output_dir = Path.cwd() / "reports"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir / filename
