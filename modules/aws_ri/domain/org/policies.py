"""AWS Organizations policy summaries."""

from dataclasses import dataclass
from typing import List, Dict


@dataclass(frozen=True)
class OrgPolicy:
    """Represents an AWS Organizations policy."""
    policy_id: str
    name: str
    description: str
    type: str
    target_count: int
    targets: List[str]


@dataclass
class OrgPolicySummary:
    """Aggregate info for organization policies grouped by type."""
    policies_by_type: Dict[str, List[OrgPolicy]]

    def total_policies(self) -> int:
        return sum(len(policies) for policies in self.policies_by_type.values())

    def types(self) -> List[str]:
        return list(self.policies_by_type.keys())
