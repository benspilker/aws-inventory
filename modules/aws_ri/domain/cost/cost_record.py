"""Cost domain - Cost record entity and aggregations."""

from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from typing import Optional


@dataclass(frozen=True)
class CostRecord:
    """AWS Cost record from Cost Explorer.

    Represents cost for a specific dimension (account/region/service).
    Domain invariant: Amount must be non-negative.
    """
    account_id: str
    service: str
    region: str
    amount: Decimal
    start_date: date
    end_date: date
    unit: str = "USD"
    resource_id: Optional[str] = None

    def __post_init__(self):
        if self.amount < 0:
            raise ValueError(f"Cost amount cannot be negative: {self.amount}")

    def __str__(self) -> str:
        return f"{self.service} ({self.account_id}/{self.region}): ${self.amount:.2f}"


@dataclass
class CostSummary:
    """Aggregate cost summary.

    Domain service for cost calculations and rollups.
    """
    records: list[CostRecord]
    region_totals: dict[str, Decimal] = field(default_factory=dict)

    def total_cost(self) -> Decimal:
        """Calculate total cost across all records."""
        return sum((record.amount for record in self.records), Decimal("0"))

    def cost_by_account(self) -> dict[str, Decimal]:
        """Aggregate cost by account."""
        result: dict[str, Decimal] = {}
        for record in self.records:
            result[record.account_id] = result.get(record.account_id, Decimal("0")) + record.amount
        return result

    def cost_by_service(self) -> dict[str, Decimal]:
        """Aggregate cost by service."""
        result: dict[str, Decimal] = {}
        for record in self.records:
            result[record.service] = result.get(record.service, Decimal("0")) + record.amount
        return result

    def cost_by_region(self) -> dict[str, Decimal]:
        """Aggregate cost by region."""
        if self.region_totals:
            return self.region_totals

        result: dict[str, Decimal] = {}
        for record in self.records:
            result[record.region] = result.get(record.region, Decimal("0")) + record.amount
        return result

    def cost_by_month(self) -> dict[str, Decimal]:
        """Aggregate cost by calendar month based on record start_date."""
        result: dict[str, Decimal] = {}
        for record in self.records:
            label = record.start_date.strftime("%Y-%m")
            result[label] = result.get(label, Decimal("0")) + record.amount
        return result

    def top_accounts(self, limit: int = 10) -> list[tuple[str, Decimal]]:
        """Get top N accounts by cost."""
        by_account = self.cost_by_account()
        return sorted(by_account.items(), key=lambda x: x[1], reverse=True)[:limit]

    def top_services(self, limit: int = 10) -> list[tuple[str, Decimal]]:
        """Get top N services by cost."""
        by_service = self.cost_by_service()
        return sorted(by_service.items(), key=lambda x: x[1], reverse=True)[:limit]

    def top_regions(self, limit: int = 10) -> list[tuple[str, Decimal]]:
        """Get top N regions by cost."""
        by_region = self.cost_by_region()
        return sorted(by_region.items(), key=lambda x: x[1], reverse=True)[:limit]

    def cost_for_account(self, account_id: str) -> Decimal:
        """Get total cost for specific account."""
        return sum(
            (record.amount for record in self.records if record.account_id == account_id),
            Decimal("0")
        )

    def cost_for_service(self, service: str) -> Decimal:
        """Get total cost for specific service."""
        return sum(
            (record.amount for record in self.records if record.service == service),
            Decimal("0")
        )

    def records_for_account(self, account_id: str) -> list[CostRecord]:
        """Filter cost records by account."""
        return [r for r in self.records if r.account_id == account_id]


@dataclass(frozen=True)
class CostData:
    """Result from cost collection adapters."""
    records: list[CostRecord]
    region_totals: dict[str, Decimal] = field(default_factory=dict)
