"""AWS Config adapter implementation for inventory and compliance."""

import logging
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Any
from datetime import datetime
import boto3
from botocore.exceptions import ClientError, BotoCoreError

from aws_ri.application.ports.aws_ports import InventoryPort, PosturePort
from aws_ri.application.ports.exceptions import InventoryError, PostureError
from aws_ri.domain.inventory.resource import Resource, ResourceTag
from aws_ri.domain.posture.compliance import ConfigRuleCompliance


logger = logging.getLogger(__name__)


class ConfigInventoryAdapter(InventoryPort):
    """Adapter for AWS Config Aggregator inventory using boto3."""

    def __init__(self, session: Optional[boto3.Session] = None):
        """Initialize Config adapter.

        Args:
            session: Optional boto3 session. If None, uses default session.
        """
        self.session = session or boto3.Session()
        self.client = self.session.client('config')

    def get_aggregator_name(self) -> Optional[str]:
        """Get the first available Config Aggregator name.

        Returns:
            Aggregator name or None if not configured.
        """
        try:
            response = self.client.describe_configuration_aggregators()
            aggregators = response.get('ConfigurationAggregators', [])

            if not aggregators:
                return None

            return aggregators[0]['ConfigurationAggregatorName']

        except ClientError as e:
            logger.warning(f"Failed to describe aggregators: {e}")
            return None

    def fetch_resources(
        self,
        aggregator_name: str,
        account_ids: Optional[list[str]] = None,
        regions: Optional[list[str]] = None,
        resource_types: Optional[list[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[Resource]:
        """Fetch resources from Config Aggregator using advanced query.

        Args:
            aggregator_name: Name of the Config Aggregator.
            account_ids: Optional filter by account IDs.
            regions: Optional filter by regions.
            resource_types: Optional filter by resource types.

        Returns:
            List of Resource entities.

        Raises:
            InventoryError: If unable to fetch resources.
        """
        try:
            # Build SQL query for SelectAggregateResourceConfig
            query = self._build_query(account_ids, regions, resource_types)
            logger.info(f"Executing Config query: {query}")

            resources = []
            paginator = self.client.get_paginator('select_aggregate_resource_config')

            page_count = 0
            for page in paginator.paginate(
                Expression=query,
                ConfigurationAggregatorName=aggregator_name,
            ):
                page_count += 1
                results = page.get('Results', [])

                for result_json in results:
                    try:
                        result = json.loads(result_json)
                        resource = self._map_to_domain(result)
                        if not self._within_window(resource, start_time, end_time):
                            continue
                        resources.append(resource)
                    except (json.JSONDecodeError, ValueError, KeyError) as e:
                        logger.warning(f"Failed to parse resource: {e}")
                        continue

                if page_count % 10 == 0:
                    logger.info(f"Fetched {len(resources)} resources so far...")

            logger.info(f"Fetched {len(resources)} total resources from Config Aggregator")
            return resources

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'NoSuchConfigurationAggregatorException':
                raise InventoryError(
                    f"Config Aggregator '{aggregator_name}' not found. "
                    "Please configure AWS Config Aggregator."
                ) from e
            elif error_code == 'InvalidExpressionException':
                raise InventoryError(f"Invalid query expression: {e}") from e
            else:
                raise InventoryError(f"Failed to fetch resources: {e}") from e

        except BotoCoreError as e:
            raise InventoryError(f"AWS API error: {e}") from e

    def _build_query(
        self,
        account_ids: Optional[list[str]],
        regions: Optional[list[str]],
        resource_types: Optional[list[str]],
    ) -> str:
        """Build SQL query for Config Aggregator.

        Example queries:
        - SELECT * WHERE resourceType IN ('AWS::EC2::Instance', 'AWS::S3::Bucket')
        - SELECT accountId, awsRegion, resourceType, resourceId, resourceName, tags
          WHERE accountId = '123456789012'
        """
        # Select commonly used fields
        fields = [
            "accountId",
            "awsRegion",
            "resourceType",
            "resourceId",
            "resourceName",
            "arn",
            "tags",
            "configuration",
            "resourceCreationTime",
            "configurationItemCaptureTime",
            "configurationItemStatus",
        ]

        query = f"SELECT {', '.join(fields)}"

        # Build WHERE conditions
        conditions = []

        if account_ids:
            account_list = "', '".join(account_ids)
            conditions.append(f"accountId IN ('{account_list}')")

        if regions:
            region_list = "', '".join(regions)
            conditions.append(f"awsRegion IN ('{region_list}')")

        if resource_types:
            type_list = "', '".join(resource_types)
            conditions.append(f"resourceType IN ('{type_list}')")

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        return query

    def _map_to_domain(self, config_item: dict) -> Resource:
        """Map Config API response to domain Resource entity.

        Args:
            config_item: Resource dict from Config API.

        Returns:
            Resource entity.

        Raises:
            ValueError: If resource data is invalid.
        """
        tags = self._parse_tags(config_item.get('tags'))

        # Parse timestamps
        creation_time = self._parse_time(config_item.get('resourceCreationTime'))
        capture_time = self._parse_time(config_item.get('configurationItemCaptureTime'))

        # Parse configuration (may be JSON string or dict)
        configuration = config_item.get('configuration')
        if isinstance(configuration, str):
            try:
                configuration = json.loads(configuration)
            except json.JSONDecodeError:
                configuration = None

        return Resource(
            resource_type=config_item['resourceType'],
            account_id=config_item['accountId'],
            region=config_item['awsRegion'],
            resource_id=config_item['resourceId'],
            resource_name=config_item.get('resourceName'),
            arn=config_item.get('arn'),
            tags=tuple(tags),
            configuration=configuration,
            creation_time=creation_time,
            capture_time=capture_time,
            status=config_item.get('configurationItemStatus'),
        )

    def _parse_tags(self, raw_tags: Any) -> list[ResourceTag]:
        tags: list[ResourceTag] = []
        if not raw_tags:
            return tags

        if isinstance(raw_tags, dict):
            for key, value in raw_tags.items():
                if key:
                    tags.append(ResourceTag(key=str(key), value=str(value or "")))
            return tags

        if isinstance(raw_tags, list):
            for entry in raw_tags:
                if isinstance(entry, dict):
                    key = entry.get('key') or entry.get('Key')
                    value = entry.get('value') or entry.get('Value')
                    if not key and 'tag' in entry and isinstance(entry['tag'], str):
                        potential = entry['tag']
                        if '=' in potential:
                            possible_key, possible_value = potential.split('=', 1)
                            key = key or possible_key
                            value = value or possible_value
                    if key:
                        tags.append(ResourceTag(key=str(key), value=str(value or "")))
                elif isinstance(entry, str) and '=' in entry:
                    key, value = entry.split('=', 1)
                    tags.append(ResourceTag(key=key, value=value))
        return tags

    @staticmethod
    def _parse_time(value: Any) -> Optional[datetime]:
        if not value:
            return None
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace('Z', '+00:00'))
            except ValueError:
                return None
        if isinstance(value, datetime):
            return value
        return None

    @staticmethod
    def _within_window(
        resource: Resource,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> bool:
        status = (resource.status or "").lower()
        if 'deleted' in status:
            return False

        if not start_time and not end_time:
            return True

        reference = resource.capture_time or resource.creation_time
        if not reference:
            return False
        if start_time and reference < start_time:
            return False
        if end_time and reference > end_time:
            return False
        return True


class ConfigPostureAdapter(PosturePort):
    """Adapter for AWS Config compliance data."""

    MAX_WORKERS = 8

    def __init__(self, session: Optional[boto3.Session] = None):
        """Initialize Config posture adapter.

        Args:
            session: Optional boto3 session. If None, uses default session.
        """
        self.session = session or boto3.Session()
        self.client = self.session.client('config')

    def fetch_compliance(
        self,
        account_ids: Optional[list[str]] = None,
        start_date=None,  # retained for interface compatibility
        end_date=None,    # retained for interface compatibility
    ) -> list[ConfigRuleCompliance]:
        """Fetch Config rule compliance summary.

        Aggregates compliance using the Config Aggregator so that all accounts
        participating in the aggregator are included. Requires the caller to
        have access to the aggregator (e.g., delegated administrator).

        Args:
            account_ids: Optional filter by account IDs. When omitted, all
                accounts covered by the aggregator are queried sequentially.

        Returns:
            List of ConfigRuleCompliance entities.

        Raises:
            PostureError: If unable to fetch compliance data.
        """
        try:
            aggregator_name = self._get_aggregator_name()
            if not aggregator_name:
                raise PostureError(
                    "No Config Aggregator found. Ensure an aggregator is configured for compliance collection."
                )

            targets = account_ids or self._discover_accounts()
            if not targets:
                logger.warning("No accounts available when collecting Config compliance")
                return []

            compliance_data = self._fetch_compliance_summary(aggregator_name, targets)
            logger.info(
                "Fetched compliance for %s Config rules across %s accounts",
                len(compliance_data),
                len(targets),
            )
            return compliance_data

        except ClientError as e:
            raise PostureError(f"Failed to fetch compliance data: {e}") from e
        except BotoCoreError as e:
            raise PostureError(f"AWS API error: {e}") from e

    def _fetch_compliance_summary(
        self,
        aggregator_name: str,
        account_ids: list[str],
    ) -> list[ConfigRuleCompliance]:
        """Fetch compliance via DescribeAggregateComplianceByConfigRules."""

        def _fetch_for_account(account_id: str) -> list[ConfigRuleCompliance]:
            attempts = 0
            delay = 1.0
            while True:
                try:
                    records: list[ConfigRuleCompliance] = []
                    filters = {'AccountId': account_id}
                    paginator = self.client.get_paginator('describe_aggregate_compliance_by_config_rules')
                    for page in paginator.paginate(
                        ConfigurationAggregatorName=aggregator_name,
                        Filters=filters,
                    ):
                        for aggregate in page.get('AggregateComplianceByConfigRules', []):
                            try:
                                records.append(self._map_aggregate_to_domain(aggregate, account_id))
                            except (ValueError, KeyError) as exc:
                                logger.warning(f"Failed to parse aggregate compliance data: {exc}")
                                continue
                    return records
                except ClientError as exc:
                    error_code = exc.response.get('Error', {}).get('Code')
                    if error_code == 'ThrottlingException' and attempts < 5:
                        attempts += 1
                        logger.warning(
                            "Throttled fetching compliance for account %s (attempt %s), retrying in %.1fs",
                            account_id,
                            attempts,
                            delay,
                        )
                        time.sleep(delay)
                        delay = min(delay * 2, 15)
                        continue
                    raise

        compliance_data: list[ConfigRuleCompliance] = []
        max_workers = min(self.MAX_WORKERS, len(account_ids)) or 1
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(_fetch_for_account, account_id): account_id for account_id in account_ids}
            for future in as_completed(futures):
                try:
                    compliance_data.extend(future.result())
                except Exception as exc:
                    logger.warning(f"Failed to fetch compliance for account {futures[future]}: {exc}")
        return compliance_data

    def _map_to_domain(
        self,
        rule_compliance: dict,
        account_id: str,
    ) -> ConfigRuleCompliance:
        """Map Config compliance API response to domain entity.

        Args:
            rule_compliance: Compliance dict from Config API.
            account_id: AWS account ID.

        Returns:
            ConfigRuleCompliance entity.
        """
        compliance = rule_compliance.get('Compliance', {})
        compliance_type = compliance.get('ComplianceType', 'INSUFFICIENT_DATA')

        # Config API returns compliance type, but not counts per rule
        # We'll use 1/0 counts based on the overall rule status
        # For detailed counts, would need DescribeComplianceByResource
        compliant = 1 if compliance_type == 'COMPLIANT' else 0
        non_compliant = 1 if compliance_type == 'NON_COMPLIANT' else 0
        not_applicable = 1 if compliance_type == 'NOT_APPLICABLE' else 0
        insufficient = 1 if compliance_type == 'INSUFFICIENT_DATA' else 0

        return ConfigRuleCompliance(
            rule_name=rule_compliance['ConfigRuleName'],
            account_id=account_id,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            not_applicable_count=not_applicable,
            insufficient_data_count=insufficient,
        )

    def _map_aggregate_to_domain(
        self,
        aggregate_compliance: dict,
        account_id: str,
    ) -> ConfigRuleCompliance:
        compliance = aggregate_compliance.get('Compliance', {})
        compliance_type = compliance.get('ComplianceType', 'INSUFFICIENT_DATA')
        contributor_count = 0
        contributor = compliance.get('ComplianceContributorCount', {})
        if isinstance(contributor, dict):
            contributor_count = contributor.get('CappedCount', 0) or 0

        compliant = 1 if compliance_type == 'COMPLIANT' else 0
        non_compliant = contributor_count if compliance_type == 'NON_COMPLIANT' else 0
        not_applicable = 1 if compliance_type == 'NOT_APPLICABLE' else 0
        insufficient = 1 if compliance_type == 'INSUFFICIENT_DATA' else 0

        return ConfigRuleCompliance(
            rule_name=aggregate_compliance['ConfigRuleName'],
            account_id=account_id,
            compliant_count=compliant,
            non_compliant_count=non_compliant,
            not_applicable_count=not_applicable,
            insufficient_data_count=insufficient,
        )


    def _get_aggregator_name(self) -> Optional[str]:
        try:
            response = self.client.describe_configuration_aggregators()
            aggregators = response.get('ConfigurationAggregators', [])
            if not aggregators:
                return None
            return aggregators[0]['ConfigurationAggregatorName']
        except (ClientError, BotoCoreError) as exc:
            logger.warning(f"Failed to describe Config aggregators: {exc}")
            return None

    def _discover_accounts(self) -> list[str]:
        try:
            org_client = self.session.client('organizations')
            paginator = org_client.get_paginator('list_accounts')
            accounts: list[str] = []
            for page in paginator.paginate():
                for account in page.get('Accounts', []):
                    if account.get('Status') == 'ACTIVE':
                        accounts.append(account['Id'])
            return accounts
        except Exception:
            # Fallback to current account if Organizations is unavailable
            sts_client = self.session.client('sts')
            return [sts_client.get_caller_identity()['Account']]
