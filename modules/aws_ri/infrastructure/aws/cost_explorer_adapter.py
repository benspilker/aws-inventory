"""AWS Cost Explorer adapter implementation."""

import logging
from typing import Optional
from datetime import date
from decimal import Decimal
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from aws_ri.application.ports.aws_ports import CostPort
from aws_ri.application.ports.exceptions import CostError
from aws_ri.domain.cost.cost_record import CostRecord, CostData


logger = logging.getLogger(__name__)


# Cost Explorer may return human-readable region labels while inventory APIs
# use canonical region IDs. Keep the summary join stable across both forms.
_COST_EXPLORER_REGION_NAMES = {
    "US East (N. Virginia)": "us-east-1",
    "US East (Ohio)": "us-east-2",
    "US West (N. California)": "us-west-1",
    "US West (Oregon)": "us-west-2",
    "Canada (Central)": "ca-central-1",
    "Canada West (Calgary)": "ca-west-1",
    "Europe (Ireland)": "eu-west-1",
    "Europe (London)": "eu-west-2",
    "Europe (Paris)": "eu-west-3",
    "Europe (Frankfurt)": "eu-central-1",
    "Europe (Stockholm)": "eu-north-1",
    "Europe (Milan)": "eu-south-1",
    "Europe (Spain)": "eu-south-2",
    "Asia Pacific (Tokyo)": "ap-northeast-1",
    "Asia Pacific (Seoul)": "ap-northeast-2",
    "Asia Pacific (Osaka)": "ap-northeast-3",
    "Asia Pacific (Singapore)": "ap-southeast-1",
    "Asia Pacific (Sydney)": "ap-southeast-2",
    "Asia Pacific (Mumbai)": "ap-south-1",
    "Asia Pacific (Hong Kong)": "ap-east-1",
    "South America (Sao Paulo)": "sa-east-1",
    "Middle East (Bahrain)": "me-south-1",
    "Middle East (UAE)": "me-central-1",
    "Africa (Cape Town)": "af-south-1",
    "Israel (Tel Aviv)": "il-central-1",
    "No region": "global",
    "Global": "global",
}


class CostExplorerAdapter(CostPort):
    """Adapter for AWS Cost Explorer using boto3."""

    def __init__(self, session: Optional[boto3.Session] = None):
        """Initialize Cost Explorer adapter.

        Args:
            session: Optional boto3 session. If None, uses default session.
        """
        self.session = session or boto3.Session()
        # Cost Explorer API is only available in us-east-1
        self.client = self.session.client('ce', region_name='us-east-1')

    def fetch_costs(
        self,
        start_date: date,
        end_date: date,
        account_ids: Optional[list[str]] = None,
    ) -> CostData:
        """Fetch cost records from Cost Explorer.

        Groups by LINKED_ACCOUNT, REGION, and SERVICE.

        Args:
            start_date: Start date for cost query.
            end_date: End date for cost query.
            account_ids: Optional filter by account IDs.

        Returns:
            List of CostRecord entities.

        Raises:
            CostError: If unable to fetch costs.
        """
        try:
            filter_expr = self._build_account_filter(account_ids)

            account_service_records = self._fetch_account_service_costs(
                start_date=start_date,
                end_date=end_date,
                filter_expr=filter_expr,
            )

            region_totals = self._fetch_region_totals(
                start_date=start_date,
                end_date=end_date,
                filter_expr=filter_expr,
            )

            logger.info(
                f"Fetched {len(account_service_records)} cost records across "
                f"{len(region_totals)} regions"
            )

            return CostData(
                records=account_service_records,
                region_totals=region_totals,
            )

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'AccessDeniedException':
                raise CostError(
                    "Access denied to Cost Explorer. Ensure you have "
                    "'ce:GetCostAndUsage' permission."
                ) from e
            else:
                raise CostError(f"Failed to fetch costs: {e}") from e

        except BotoCoreError as e:
            raise CostError(f"AWS API error: {e}") from e

    def _build_account_filter(self, account_ids: Optional[list[str]]):
        if not account_ids:
            return None

        return {
            'Dimensions': {
                'Key': 'LINKED_ACCOUNT',
                'Values': account_ids,
            }
        }

    def _fetch_account_service_costs(
        self,
        start_date: date,
        end_date: date,
        filter_expr: Optional[dict],
    ) -> list[CostRecord]:
        """Fetch costs grouped by linked account and service."""
        request_params = {
            'TimePeriod': {
                'Start': start_date.isoformat(),
                'End': end_date.isoformat(),
            },
            'Granularity': 'MONTHLY',
            'Metrics': ['UnblendedCost'],
            # Cost Explorer permits at most two GroupBy dimensions. Keep the
            # detailed worksheet at account/service granularity and obtain
            # canonical region totals with the separate query below.
            'GroupBy': [
                {'Type': 'DIMENSION', 'Key': 'LINKED_ACCOUNT'},
                {'Type': 'DIMENSION', 'Key': 'SERVICE'},
            ],
        }

        if filter_expr:
            request_params['Filter'] = filter_expr

        cost_records: list[CostRecord] = []
        next_page_token = None

        while True:
            if next_page_token:
                request_params['NextPageToken'] = next_page_token

            response = self.client.get_cost_and_usage(**request_params)

            for result_by_time in response.get('ResultsByTime', []):
                period_start = result_by_time['TimePeriod']['Start']
                period_end = result_by_time['TimePeriod']['End']

                for group in result_by_time.get('Groups', []):
                    try:
                        record = self._map_account_service_to_record(
                            group=group,
                            period_start=period_start,
                            period_end=period_end,
                        )
                        if record.amount > Decimal('0'):
                            cost_records.append(record)
                    except (ValueError, KeyError) as e:
                        logger.warning(f"Failed to parse account/service cost record: {e}")
                        continue

            next_page_token = response.get('NextPageToken')
            if not next_page_token:
                break

        return cost_records

    def _fetch_region_totals(
        self,
        start_date: date,
        end_date: date,
        filter_expr: Optional[dict],
    ) -> dict[str, Decimal]:
        """Fetch cost totals grouped by region."""
        request_params = {
            'TimePeriod': {
                'Start': start_date.isoformat(),
                'End': end_date.isoformat(),
            },
            'Granularity': 'MONTHLY',
            'Metrics': ['UnblendedCost'],
            'GroupBy': [
                {'Type': 'DIMENSION', 'Key': 'REGION'},
            ],
        }

        if filter_expr:
            request_params['Filter'] = filter_expr

        region_totals: dict[str, Decimal] = {}
        next_page_token = None

        while True:
            if next_page_token:
                request_params['NextPageToken'] = next_page_token

            response = self.client.get_cost_and_usage(**request_params)

            for result_by_time in response.get('ResultsByTime', []):
                for group in result_by_time.get('Groups', []):
                    try:
                        region, amount = self._map_region_group(group)
                        if amount > Decimal('0'):
                            region_totals[region] = (
                                region_totals.get(region, Decimal('0')) + amount
                            )
                    except (ValueError, KeyError) as e:
                        logger.warning(f"Failed to parse region cost record: {e}")
                        continue

            next_page_token = response.get('NextPageToken')
            if not next_page_token:
                break

        return region_totals

    def _map_account_service_to_record(
        self,
        group: dict,
        period_start: str,
        period_end: str,
    ) -> CostRecord:
        """Map a LINKED_ACCOUNT/REGION/SERVICE grouping to CostRecord.

        Two-key responses remain supported for compatibility with older mocked
        responses and older Cost Explorer integrations; those records retain
        the explicit ``ALL_REGIONS`` marker.
        """
        keys = group.get('Keys', [])
        account_id = keys[0] if len(keys) > 0 else 'Unknown'
        if len(keys) > 2:
            region = self._normalize_region(keys[1])
            service = keys[2]
        else:
            region = "ALL_REGIONS"
            service = keys[1] if len(keys) > 1 else 'Unknown'

        metrics = group.get('Metrics', {})
        amount_str = metrics.get('UnblendedCost', {}).get('Amount', '0')
        amount = Decimal(amount_str)

        return CostRecord(
            account_id=account_id,
            service=service,
            region=region,
            amount=amount,
            start_date=date.fromisoformat(period_start),
            end_date=date.fromisoformat(period_end),
            unit='USD',
        )

    def _map_region_group(self, group: dict) -> tuple[str, Decimal]:
        """Extract region and cost amount from a region grouping."""
        keys = group.get('Keys', [])
        region = self._normalize_region(keys[0] if keys else 'Unknown')
        metrics = group.get('Metrics', {})
        amount_str = metrics.get('UnblendedCost', {}).get('Amount', '0')
        amount = Decimal(amount_str)
        return region, amount

    @staticmethod
    def _normalize_region(region: str) -> str:
        """Convert Cost Explorer region labels to inventory region IDs."""
        value = str(region or "Unknown").strip()
        if value in _COST_EXPLORER_REGION_NAMES:
            return _COST_EXPLORER_REGION_NAMES[value]
        return value.lower() if value.startswith(("us-", "eu-", "ap-", "ca-", "sa-", "me-", "af-", "il-")) else value
