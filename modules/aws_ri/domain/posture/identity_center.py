"""Identity Center domain summaries."""

from dataclasses import dataclass
from typing import List, Optional


@dataclass(frozen=True)
class IdentityCenterUser:
    """IAM Identity Center user information."""
    user_id: str
    username: Optional[str]
    display_name: Optional[str]
    email: Optional[str]


@dataclass(frozen=True)
class IdentityCenterGroup:
    """IAM Identity Center group information."""
    group_id: str
    display_name: Optional[str]
    description: Optional[str]


@dataclass(frozen=True)
class IdentityCenterAssignment:
    """Represents a principal assignment to a permission set."""
    instance_arn: str
    account_id: str
    permission_set_arn: str
    principal_type: str
    principal_name: str


@dataclass(frozen=True)
class IdentityCenterInstance:
    """Represents a single IAM Identity Center instance summary."""
    instance_arn: str
    identity_store_id: str
    region: str
    permission_set_count: int
    account_assignment_count: int
    permission_sets: List[str]
    user_count: int
    group_count: int
    users: List[IdentityCenterUser]
    groups: List[IdentityCenterGroup]
    assignments: List[IdentityCenterAssignment]


@dataclass
class IdentityCenterSummary:
    """Aggregate summary for IAM Identity Center."""
    instances: List[IdentityCenterInstance]

    def total_instances(self) -> int:
        return len(self.instances)

    def total_permission_sets(self) -> int:
        return sum(instance.permission_set_count for instance in self.instances)

    def total_assignments(self) -> int:
        return sum(instance.account_assignment_count for instance in self.instances)
