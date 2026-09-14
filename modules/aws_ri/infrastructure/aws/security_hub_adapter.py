"""AWS Security Hub adapter implementation."""

import copy
import logging
from datetime import date
from typing import Optional
import time

import boto3
from botocore.exceptions import ClientError, BotoCoreError, EndpointConnectionError
from aws_ri.application.ports.aws_ports import SecurityHubPort
from aws_ri.application.ports.exceptions import SecurityHubError
from aws_ri.domain.posture.securityhub import (
    SecurityHubFinding,
    SecurityHubSeverity,
)


logger = logging.getLogger(__name__)


class SecurityHubAdapter(SecurityHubPort):
    """Adapter for AWS Security Hub using boto3."""

    ACCOUNT_CHUNK_SIZE = 1

    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()
        self.region = self.session.region_name or 'us-east-1'

    def fetch_findings(
        self,
        start_date: Optional[date] = None,  # unused but retained for interface compatibility
        end_date: Optional[date] = None,    # unused but retained for interface compatibility
        account_ids: Optional[list[str]] = None,
    ) -> list[SecurityHubFinding]:
        try:
            filters = self._base_filters()
            findings: list[SecurityHubFinding] = []

            if account_ids:
                chunks = [
                    account_ids[i:i + self.ACCOUNT_CHUNK_SIZE]
                    for i in range(0, len(account_ids), self.ACCOUNT_CHUNK_SIZE)
                ]
                for chunk in chunks:
                    findings.extend(self._fetch_findings_for_filters(filters, chunk))
            else:
                findings.extend(self._fetch_findings_for_filters(filters, None))

            logger.info(f"Fetched {len(findings)} Security Hub findings")
            return findings

        except SecurityHubError:
            raise
        except EndpointConnectionError as e:
            raise SecurityHubError(
                "AWS API error: Security Hub endpoint unavailable. "
                "Ensure the service is enabled in the specified region or override the region via profiles.yaml."
            ) from e
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise SecurityHubError(
                    "Access denied to Security Hub. Ensure you have securityhub:GetFindings permission."
                ) from e
            elif error_code == 'InvalidAccessException':
                raise SecurityHubError(
                    "Security Hub is not enabled in this account/region."
                ) from e
            else:
                raise SecurityHubError(f"Failed to fetch Security Hub findings: {e}") from e
        except BotoCoreError as e:
            raise SecurityHubError(f"AWS API error: {e}") from e

    def _fetch_findings_for_filters(
        self,
        base_filters: Optional[dict],
        account_chunk: Optional[list[str]],
    ) -> list[SecurityHubFinding]:
        """Fetch findings for a subset of accounts."""
        filters = self._merge_filters(base_filters, account_chunk)
        client = self.session.client('securityhub', region_name=self.region)

        try:
            return self._paged_findings(client, filters)
        except EndpointConnectionError:
            if self.region != 'us-east-1':
                fallback_client = self.session.client('securityhub', region_name='us-east-1')
                return self._paged_findings(fallback_client, filters)
            raise

    def _paged_findings(
        self,
        client,
        filters: Optional[dict],
    ) -> list[SecurityHubFinding]:
        results: list[SecurityHubFinding] = []
        next_token = None
        while True:
            params = {'MaxResults': 100}
            if filters:
                params['Filters'] = filters
            if next_token:
                params['NextToken'] = next_token

            attempts = 0
            delay = 1.0
            while True:
                try:
                    response = client.get_findings(**params)
                    break
                except ClientError as exc:
                    error_code = exc.response.get('Error', {}).get('Code')
                    if error_code in {'TooManyRequestsException', 'ThrottlingException'} and attempts < 5:
                        attempts += 1
                        logger.warning(
                            "Throttled fetching Security Hub findings (attempt %s), retrying in %.1fs",
                            attempts,
                            delay,
                        )
                        time.sleep(delay)
                        delay = min(delay * 2, 30)
                        continue
                    raise

            for finding in response.get('Findings', []):
                try:
                    results.append(self._map_finding(finding))
                except (KeyError, ValueError) as exc:
                    logger.warning(f"Skipping Security Hub finding due to parse error: {exc}")
                    continue

            next_token = response.get('NextToken')
            if not next_token:
                break
        return results

    def _base_filters(self) -> dict:
        return {
            'WorkflowStatus': [
                {'Comparison': 'EQUALS', 'Value': 'NEW'}
            ]
        }

    def _merge_filters(
        self,
        base_filters: Optional[dict],
        account_chunk: Optional[list[str]],
    ) -> Optional[dict]:
        filters = copy.deepcopy(base_filters) if base_filters else {}
        if account_chunk:
            filters.setdefault('AwsAccountId', [])
            filters['AwsAccountId'].extend(
                {'Comparison': 'EQUALS', 'Value': account_id}
                for account_id in account_chunk
            )
        return filters or None

    def _map_finding(self, finding: dict) -> SecurityHubFinding:
        """Map AWS finding dict to domain entity."""
        severity_label = finding.get('Severity', {}).get('Label', 'INFORMATIONAL')
        try:
            severity = SecurityHubSeverity(severity_label)
        except ValueError:
            severity = SecurityHubSeverity.INFORMATIONAL

        resources = finding.get('Resources', [])
        primary_resource = resources[0] if resources else {}

        return SecurityHubFinding(
            finding_id=finding['Id'],
            title=finding.get('Title', 'Security Hub Finding'),
            severity=severity,
            workflow_status=finding.get('WorkflowState', 'NEW'),
            account_id=finding.get('AwsAccountId', 'Unknown'),
            region=finding.get('Region'),
            resource_type=primary_resource.get('Type'),
            resource_id=primary_resource.get('Id'),
        )
