"""Organization domain - Account entity and value objects."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AccountStatus(Enum):
    """AWS Organization account status."""
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    PENDING_CLOSURE = "PENDING_CLOSURE"


@dataclass(frozen=True)
class AccountId:
    """AWS Account ID value object."""
    value: str

    def __post_init__(self):
        if not self.value or len(self.value) != 12 or not self.value.isdigit():
            raise ValueError(f"Invalid AWS Account ID: {self.value}")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Account:
    """AWS Organization Account entity.

    Represents an AWS account within an organization.
    Domain invariant: Account ID must be valid 12-digit number.
    """
    id: AccountId
    name: str
    email: str
    status: AccountStatus
    joined_timestamp: Optional[str] = None

    def is_active(self) -> bool:
        """Check if account is active."""
        return self.status == AccountStatus.ACTIVE

    def __str__(self) -> str:
        return f"{self.name} ({self.id})"


@dataclass(frozen=True)
class AccountScope:
    """Collection of accounts to operate on.

    Represents the boundary for inventory/cost/posture operations.
    """
    accounts: tuple[Account, ...]

    def __post_init__(self):
        if not self.accounts:
            raise ValueError("AccountScope must contain at least one account")

    def active_accounts(self) -> tuple[Account, ...]:
        """Return only active accounts."""
        return tuple(acc for acc in self.accounts if acc.is_active())

    def get_account_by_id(self, account_id: str) -> Optional[Account]:
        """Find account by ID."""
        for account in self.accounts:
            if str(account.id) == account_id:
                return account
        return None

    def __len__(self) -> int:
        return len(self.accounts)

    def __iter__(self):
        return iter(self.accounts)
