"""Posture domain - Compliance and security findings."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ComplianceStatus(Enum):
    """AWS Config compliance status."""
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


class AdvisorSeverity(Enum):
    """Trusted Advisor finding severity."""
    ERROR = "error"
    WARNING = "warning"
    OK = "ok"


@dataclass(frozen=True)
class ConfigRuleCompliance:
    """AWS Config rule compliance summary.

    Represents compliance state for a single Config rule.
    """
    rule_name: str
    account_id: str
    compliant_count: int
    non_compliant_count: int
    not_applicable_count: int
    insufficient_data_count: int

    def total_resources(self) -> int:
        """Total resources evaluated by this rule."""
        return (
            self.compliant_count +
            self.non_compliant_count +
            self.not_applicable_count +
            self.insufficient_data_count
        )

    def compliance_rate(self) -> float:
        """Calculate compliance percentage.

        Domain calculation: compliance rate excludes not_applicable and insufficient_data.
        """
        evaluated = self.compliant_count + self.non_compliant_count
        if evaluated == 0:
            return 100.0
        return (self.compliant_count / evaluated) * 100.0

    def has_violations(self) -> bool:
        """Check if rule has non-compliant resources."""
        return self.non_compliant_count > 0


@dataclass(frozen=True)
class AdvisorFinding:
    """Trusted Advisor finding.

    Represents a single check result from Trusted Advisor.
    """
    check_id: str
    check_name: str
    category: str
    status: AdvisorSeverity
    resources_flagged: int
    resources_ignored: int
    resources_suppressed: int
    description: Optional[str] = None

    def total_affected(self) -> int:
        """Total resources affected (flagged + ignored + suppressed)."""
        return self.resources_flagged + self.resources_ignored + self.resources_suppressed

    def has_issues(self) -> bool:
        """Check if finding has flagged resources."""
        return self.resources_flagged > 0


@dataclass
class ComplianceSummary:
    """Organization-wide compliance summary.

    Domain service for compliance calculations.
    """
    config_rules: list[ConfigRuleCompliance]

    def total_rules(self) -> int:
        """Total number of Config rules."""
        return len(self.config_rules)

    def rules_with_violations(self) -> int:
        """Count rules with violations."""
        return sum(1 for rule in self.config_rules if rule.has_violations())

    def overall_compliance_rate(self) -> float:
        """Calculate overall compliance rate across all rules.

        Domain calculation: weighted average by evaluated resources.
        """
        total_compliant = 0
        total_evaluated = 0

        for rule in self.config_rules:
            total_compliant += rule.compliant_count
            total_evaluated += rule.compliant_count + rule.non_compliant_count

        if total_evaluated == 0:
            return 100.0

        return (total_compliant / total_evaluated) * 100.0

    def total_violations(self) -> int:
        """Total non-compliant resources across all rules."""
        return sum(rule.non_compliant_count for rule in self.config_rules)

    def compliance_by_account(self) -> dict[str, float]:
        """Calculate compliance rate per account."""
        account_stats: dict[str, dict[str, int]] = {}

        for rule in self.config_rules:
            if rule.account_id not in account_stats:
                account_stats[rule.account_id] = {"compliant": 0, "evaluated": 0}

            account_stats[rule.account_id]["compliant"] += rule.compliant_count
            account_stats[rule.account_id]["evaluated"] += (
                rule.compliant_count + rule.non_compliant_count
            )

        result = {}
        for account_id, stats in account_stats.items():
            if stats["evaluated"] == 0:
                result[account_id] = 100.0
            else:
                result[account_id] = (stats["compliant"] / stats["evaluated"]) * 100.0

        return result


@dataclass
class AdvisorSummary:
    """Trusted Advisor findings summary.

    Domain service for advisor calculations.
    """
    findings: list[AdvisorFinding]

    def total_checks(self) -> int:
        """Total number of checks."""
        return len(self.findings)

    def checks_with_issues(self) -> int:
        """Count checks with flagged resources."""
        return sum(1 for finding in self.findings if finding.has_issues())

    def total_flagged_resources(self) -> int:
        """Total flagged resources across all checks."""
        return sum(finding.resources_flagged for finding in self.findings)

    def findings_by_category(self) -> dict[str, int]:
        """Count findings by category."""
        result: dict[str, int] = {}
        for finding in self.findings:
            result[finding.category] = result.get(finding.category, 0) + 1
        return result

    def findings_by_severity(self) -> dict[AdvisorSeverity, int]:
        """Count findings by severity."""
        result: dict[AdvisorSeverity, int] = {}
        for finding in self.findings:
            result[finding.status] = result.get(finding.status, 0) + 1
        return result
