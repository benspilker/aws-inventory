"""Resource Explorer adapter for inventory discovery."""

import logging
from datetime import datetime
from typing import Optional, Any

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from aws_ri.application.ports.aws_ports import ResourceExplorerPort
from aws_ri.application.ports.exceptions import InventoryError
from aws_ri.domain.inventory.resource import Resource, ResourceTag

logger = logging.getLogger(__name__)


class ResourceExplorerInventoryAdapter(ResourceExplorerPort):
    """Adapter that reads resources from AWS Resource Explorer views."""

    def __init__(self, session: Optional[boto3.Session] = None):
        self.session = session or boto3.Session()
        self.client = self.session.client('resource-explorer-2')
        self._view_cache: dict[str, str] = {}

    def fetch_resources(
        self,
        view_name: str,
        account_ids: Optional[list[str]] = None,
        regions: Optional[list[str]] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> list[Resource]:
        """List indexed resources for the given view."""
        try:
            view_arn = self._resolve_view_arn(view_name)
            resources: list[Resource] = []
            seen: set[str] = set()
            queries = self._build_queries(account_ids)
            for query in queries:
                for entry in self._search(view_arn, query):
                    resource = self._map_resource(entry)
                    if not resource or not resource.arn:
                        continue
                    if resource.arn in seen:
                        continue
                    if account_ids and resource.account_id not in account_ids:
                        continue
                    if regions and resource.region not in regions:
                        continue
                    if not self._within_window(resource, start_time, end_time):
                        continue
                    resources.append(resource)
                    seen.add(resource.arn)
            logger.info(
                "Fetched %s resources from Resource Explorer view %s",
                len(resources),
                view_arn,
            )
            return resources
        except ClientError as e:
            raise InventoryError(f"Resource Explorer API error: {e}") from e
        except BotoCoreError as e:
            raise InventoryError(f"AWS API error: {e}") from e

    def _resolve_view_arn(self, identifier: str) -> str:
        if identifier.startswith("arn:"):
            return identifier
        if identifier in self._view_cache:
            return self._view_cache[identifier]

        paginator = self.client.get_paginator('list_views')
        name_token = f"/{identifier}/"
        for page in paginator.paginate():
            for view_arn in page.get('Views', []):
                if not isinstance(view_arn, str):
                    continue
                if view_arn == identifier:
                    self._view_cache[identifier] = view_arn
                    return view_arn
                if name_token in view_arn:
                    self._view_cache[identifier] = view_arn
                    return view_arn
        raise InventoryError(f"Resource Explorer view '{identifier}' not found")

    def _map_resource(self, entry: dict[str, Any]) -> Optional[Resource]:
        arn = entry.get('Arn')
        if not arn:
            return None
        region = entry.get('Region') or self._region_from_arn(arn)
        account_id = entry.get('OwningAccountId') or self._account_from_arn(arn)
        capture_time = self._parse_time(entry.get('LastReportedAt'))
        configuration = self._map_properties(entry.get('Properties'))
        tags = self._extract_tags(entry.get('Properties'))
        return Resource(
            resource_type=entry.get('ResourceType') or entry.get('Service') or 'Unknown',
            account_id=account_id or 'unknown',
            region=region or 'unknown',
            resource_id=arn,
            resource_name=None,
            arn=arn,
            tags=tags,
            configuration=configuration,
            creation_time=None,
            capture_time=capture_time,
            status=None,
        )

    @staticmethod
    def _map_properties(raw: Any) -> Optional[dict]:
        if not raw:
            return None
        properties: dict[str, Any] = {}
        if isinstance(raw, list):
            for prop in raw:
                name = prop.get('Name') if isinstance(prop, dict) else None
                value = prop.get('Value') if isinstance(prop, dict) else None
                if name:
                    properties[name] = value
        elif isinstance(raw, dict):
            properties = dict(raw)
        return properties or None

    @staticmethod
    def _extract_tags(raw: Any) -> tuple[ResourceTag, ...]:
        if not raw or not isinstance(raw, list):
            return tuple()
        tags: list[ResourceTag] = []
        for prop in raw:
            if not isinstance(prop, dict):
                continue
            name = (prop.get("Name") or "").lower()
            if name not in {"tags", "tag"}:
                continue
            data = prop.get("Data")
            if isinstance(data, dict):
                candidates = data.get("tags") or data.get("Tags") or data.get("tagSet")
                if isinstance(candidates, list):
                    for item in candidates:
                        key = item.get("Key") or item.get("key")
                        value = item.get("Value") or item.get("value")
                        if key is not None:
                            tags.append(ResourceTag(str(key), str(value or "")))
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        key = item.get("Key") or item.get("key")
                        value = item.get("Value") or item.get("value")
                        if key is not None:
                            tags.append(ResourceTag(str(key), str(value or "")))
        return tuple(tags)

    def _build_queries(self, account_ids: Optional[list[str]]) -> list[str]:
        if account_ids:
            return [f"accountid:{account_id}" for account_id in account_ids]
        return ["*"]

    def _search(self, view_arn: str, query: str) -> list[dict[str, Any]]:
        entries: list[dict[str, Any]] = []
        next_token: Optional[str] = None
        while True:
            kwargs = {"ViewArn": view_arn, "QueryString": query, "MaxResults": 1000}
            if next_token:
                kwargs["NextToken"] = next_token
            page = self.client.search(**kwargs)
            entries.extend(page.get("Resources", []))
            next_token = page.get("NextToken")
            if not next_token:
                break
        return entries

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
    def _account_from_arn(arn: str) -> Optional[str]:
        try:
            return arn.split(':')[4]
        except IndexError:
            return None

    @staticmethod
    def _region_from_arn(arn: str) -> Optional[str]:
        try:
            return arn.split(':')[3]
        except IndexError:
            return None

    @staticmethod
    def _within_window(
        resource: Resource,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
    ) -> bool:
        if not start_time and not end_time:
            return True
        reference = resource.capture_time
        if not reference:
            return False
        if start_time and reference < start_time:
            return False
        if end_time and reference > end_time:
            return False
        return True
