"""AWS Support (Trusted Advisor) adapter implementation."""

import logging
from typing import Optional
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from aws_ri.application.ports.aws_ports import AdvisorPort
from aws_ri.application.ports.exceptions import AdvisorError
from aws_ri.domain.posture.compliance import AdvisorFinding, AdvisorSeverity


logger = logging.getLogger(__name__)


class SupportAdvisorAdapter(AdvisorPort):
    """Adapter for AWS Trusted Advisor using boto3 Support API.

    Note: Trusted Advisor requires Business or Enterprise support plan.
    Support API must be called in us-east-1 region.
    """

    def __init__(self, session: Optional[boto3.Session] = None):
        """Initialize Support adapter.

        Args:
            session: Optional boto3 session. If None, uses default session.
        """
        self.session = session or boto3.Session()
        # Support API only available in us-east-1
        self.client = self.session.client('support', region_name='us-east-1')

    def fetch_findings(self) -> list[AdvisorFinding]:
        """Fetch Trusted Advisor findings.

        Returns:
            List of AdvisorFinding entities.

        Raises:
            AdvisorError: If unable to fetch findings (e.g., unsupported support plan).
        """
        try:
            findings = []

            # First, get list of available checks
            checks_response = self.client.describe_trusted_advisor_checks(
                language='en'
            )

            checks = checks_response.get('checks', [])
            logger.info(f"Found {len(checks)} Trusted Advisor checks")

            # Fetch results for each check
            for check in checks:
                try:
                    check_id = check['id']
                    check_name = check['name']
                    category = check['category']

                    # Get check result
                    result_response = self.client.describe_trusted_advisor_check_result(
                        checkId=check_id,
                        language='en',
                    )

                    result = result_response.get('result', {})
                    finding = self._map_to_domain(
                        check_id=check_id,
                        check_name=check_name,
                        category=category,
                        result=result,
                    )

                    findings.append(finding)

                except ClientError as e:
                    logger.warning(f"Failed to fetch result for check {check_id}: {e}")
                    continue

            logger.info(f"Fetched {len(findings)} Trusted Advisor findings")
            return findings

        except ClientError as e:
            error_code = e.response['Error']['Code']

            if error_code == 'SubscriptionRequiredException':
                raise AdvisorError(
                    "Trusted Advisor requires Business or Enterprise support plan. "
                    "Current support plan does not have access to Trusted Advisor API."
                ) from e
            elif error_code == 'AccessDeniedException':
                raise AdvisorError(
                    "Access denied to Trusted Advisor. Ensure you have "
                    "'support:DescribeTrustedAdvisorChecks' permission."
                ) from e
            else:
                raise AdvisorError(f"Failed to fetch Trusted Advisor findings: {e}") from e

        except BotoCoreError as e:
            raise AdvisorError(f"AWS API error: {e}") from e

    def _map_to_domain(
        self,
        check_id: str,
        check_name: str,
        category: str,
        result: dict,
    ) -> AdvisorFinding:
        """Map Support API response to domain AdvisorFinding entity.

        Args:
            check_id: Trusted Advisor check ID.
            check_name: Trusted Advisor check name.
            category: Check category.
            result: Check result dict from Support API.

        Returns:
            AdvisorFinding entity.
        """
        # Parse status
        status_str = result.get('status', 'ok')
        try:
            status = AdvisorSeverity(status_str)
        except ValueError:
            status = AdvisorSeverity.OK

        # Parse resource counts
        resources_summary = result.get('resourcesSummary', {})
        resources_flagged = resources_summary.get('resourcesFlagged', 0)
        resources_ignored = resources_summary.get('resourcesIgnored', 0)
        resources_suppressed = resources_summary.get('resourcesSuppressed', 0)

        return AdvisorFinding(
            check_id=check_id,
            check_name=check_name,
            category=category,
            status=status,
            resources_flagged=resources_flagged,
            resources_ignored=resources_ignored,
            resources_suppressed=resources_suppressed,
            description=None,  # Could extract from check metadata if needed
        )
