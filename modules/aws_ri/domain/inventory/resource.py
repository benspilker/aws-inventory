"""Inventory domain - Resource entity and value objects."""

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from collections import OrderedDict


@dataclass(frozen=True)
class ResourceTag:
    """AWS resource tag."""
    key: str
    value: str

    def __str__(self) -> str:
        return f"{self.key}={self.value}"


@dataclass(frozen=True)
class Resource:
    """AWS Resource entity.

    Represents a discovered AWS resource from Config Aggregator.
    Domain invariant: Must have either ARN or resource_id.
    """
    resource_type: str
    account_id: str
    region: str
    resource_id: str
    resource_name: Optional[str] = None
    arn: Optional[str] = None
    tags: tuple[ResourceTag, ...] = field(default_factory=tuple)
    configuration: Optional[dict] = None
    creation_time: Optional[datetime] = None
    capture_time: Optional[datetime] = None
    status: Optional[str] = None

    def __post_init__(self):
        if not self.resource_id and not self.arn:
            raise ValueError("Resource must have either resource_id or arn")

    def has_tags(self) -> bool:
        """Check if resource has tags."""
        return len(self.tags) > 0

    def get_tag_value(self, key: str) -> Optional[str]:
        """Get tag value by key."""
        for tag in self.tags:
            if tag.key == key:
                return tag.value
        return None

    def display_name(self) -> str:
        """Get display name (prefer resource_name, fall back to id)."""
        return self.resource_name or self.resource_id

    def __str__(self) -> str:
        return f"{self.resource_type}: {self.display_name()} ({self.account_id}/{self.region})"

    def attribute_values(self, reference_time: Optional[datetime] = None) -> "OrderedDict[str, str]":
        """Return ordered resource-specific attributes."""
        # Local import to avoid circular dependency during module import.
        from aws_ri.domain.inventory import resource_attributes

        return resource_attributes.extract_resource_attributes(self, reference_time)

    def attribute_headers(self) -> list[str]:
        """Headers registered for this resource type."""
        from aws_ri.domain.inventory import resource_attributes

        return resource_attributes.attribute_headers_for_type(self.resource_type)


@dataclass
class ResourceInventory:
    """Collection of resources with aggregate metrics.

    Domain service for inventory-wide calculations.
    """
    resources: list[Resource]

    def total_count(self) -> int:
        """Total number of resources."""
        return len(self.resources)

    def count_by_type(self) -> dict[str, int]:
        """Count resources by type."""
        counts: dict[str, int] = {}
        for resource in self.resources:
            counts[resource.resource_type] = counts.get(resource.resource_type, 0) + 1
        return counts

    def count_by_account(self) -> dict[str, int]:
        """Count resources by account."""
        counts: dict[str, int] = {}
        for resource in self.resources:
            counts[resource.account_id] = counts.get(resource.account_id, 0) + 1
        return counts

    def count_by_region(self) -> dict[str, int]:
        """Count resources by region."""
        counts: dict[str, int] = {}
        for resource in self.resources:
            counts[resource.region] = counts.get(resource.region, 0) + 1
        return counts

    def tag_coverage(self) -> float:
        """Calculate percentage of resources with tags.

        Domain calculation: tag coverage is a key governance metric.
        """
        if not self.resources:
            return 0.0
        tagged = sum(1 for r in self.resources if r.has_tags())
        return (tagged / len(self.resources)) * 100.0

    def resources_by_account(self, account_id: str) -> list[Resource]:
        """Filter resources by account."""
        return [r for r in self.resources if r.account_id == account_id]

    def resources_by_region(self, region: str) -> list[Resource]:
        """Filter resources by region."""
        return [r for r in self.resources if r.region == region]

    def resources_by_type(self, resource_type: str) -> list[Resource]:
        """Filter resources by type."""
        return [r for r in self.resources if r.resource_type == resource_type]

    def attribute_distribution(
        self,
        resource_type: str,
        attribute_label: str,
        reference_time: Optional[datetime] = None,
    ) -> dict[str, int]:
        """Count attribute occurrences for a specific resource type."""
        reference_time = reference_time or datetime.utcnow()
        distribution: dict[str, int] = {}
        for resource in self.resources_by_type(resource_type):
            value = resource.attribute_values(reference_time).get(attribute_label)
            if value:
                distribution[value] = distribution.get(value, 0) + 1
        return distribution
