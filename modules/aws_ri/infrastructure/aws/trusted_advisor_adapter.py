"""Trusted Advisor adapter supporting both new and legacy APIs."""

import logging
from typing import Optional

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from aws_ri.application.ports.aws_ports import AdvisorPort
from aws_ri.application.ports.exceptions import AdvisorError
from aws_ri.domain.posture.compliance import AdvisorFinding, AdvisorSeverity
from aws_ri.infrastructure.aws.support_adapter import SupportAdvisorAdapter


logger = logging.getLogger(__name__)


class TrustedAdvisorAdapter(AdvisorPort):
    """Adapter that uses the new Trusted Advisor API with Support fallback."""

    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()
        self.ta_client = self.session.client('trustedadvisor', region_name='us-east-1')
        self.support_adapter = SupportAdvisorAdapter(session=self.session)

    def fetch_findings(self) -> list[AdvisorFinding]:
        """Fetch findings using v2 API, falling back to Support if unavailable."""
        try:
            findings = self._fetch_v2_findings()
            if findings:
                return findings
        except AdvisorError as e:
            logger.warning(f"Trusted Advisor v2 API unavailable: {e}")

        return self.support_adapter.fetch_findings()

    def _fetch_v2_findings(self) -> list[AdvisorFinding]:
        try:
            recommendations: list[AdvisorFinding] = []
            next_token = None

            while True:
                params = {'maxResults': 100}
                if next_token:
                    params['nextToken'] = next_token
                response = self.ta_client.list_recommendations(**params)

                for summary in response.get('recommendationSummaries', []):
                    try:
                        recommendations.append(self._map_summary(summary))
                    except (KeyError, ValueError) as exc:
                        logger.warning(f"Skipping invalid Trusted Advisor recommendation: {exc}")
                        continue

                next_token = response.get('nextToken')
                if not next_token:
                    break

            if not recommendations:
                raise AdvisorError("Trusted Advisor v2 API returned no recommendations")

            logger.info(f"Fetched {len(recommendations)} recommendations from Trusted Advisor v2 API")
            return recommendations

        except (ClientError, BotoCoreError) as exc:
            raise AdvisorError(f"Failed to query Trusted Advisor v2 API: {exc}") from exc

    def _map_summary(self, summary: dict) -> AdvisorFinding:
        resources = summary.get('resourcesAggregates', {})
        error_count = resources.get('errorCount', 0)
        warning_count = resources.get('warningCount', 0)

        if error_count > 0:
            severity = AdvisorSeverity.ERROR
        elif warning_count > 0:
            severity = AdvisorSeverity.WARNING
        else:
            severity = AdvisorSeverity.OK

        flagged = error_count + warning_count

        return AdvisorFinding(
            check_id=summary.get('checkArn', summary.get('arn', 'unknown-check')),
            check_name=summary.get('name', 'Trusted Advisor Recommendation'),
            category=','.join(summary.get('pillars', [])) or 'general',
            status=severity,
            resources_flagged=flagged,
            resources_ignored=0,
            resources_suppressed=resources.get('okCount', 0),
            description=summary.get('type', 'Trusted Advisor recommendation'),
        )
