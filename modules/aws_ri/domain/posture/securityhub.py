"""Security Hub domain entities and summaries."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SecurityHubSeverity(Enum):
    """Security Hub severity labels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class SecurityHubFinding:
    """Security Hub finding entity."""
    finding_id: str
    title: str
    severity: SecurityHubSeverity
    workflow_status: str
    account_id: str
    region: Optional[str]
    resource_type: Optional[str]
    resource_id: Optional[str]

    def is_open(self) -> bool:
        """Check if finding is still open."""
        return self.workflow_status.upper() not in {"RESOLVED", "SUPPRESSED"}


@dataclass
class SecurityHubSummary:
    """Aggregated Security Hub findings summary."""
    findings: list[SecurityHubFinding]

    def total_findings(self) -> int:
        return len(self.findings)

    def open_findings(self) -> int:
        return sum(1 for finding in self.findings if finding.is_open())

    def findings_by_severity(self) -> dict[SecurityHubSeverity, int]:
        counts: dict[SecurityHubSeverity, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def accounts_with_findings(self) -> dict[str, int]:
        """Count findings per account."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.account_id] = counts.get(finding.account_id, 0) + 1
        return counts
