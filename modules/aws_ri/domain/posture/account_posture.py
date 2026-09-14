"""Account-level posture records collected from AWS security services."""

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PostureRecord:
    category: str
    record_id: str
    status: str = ""
    severity: str = ""
    region: str = "global"
    resource: str = ""
    title: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccountPostureSummary:
    records: list[PostureRecord] = field(default_factory=list)

    def by_category(self) -> dict[str, list[PostureRecord]]:
        result: dict[str, list[PostureRecord]] = {}
        for record in self.records:
            result.setdefault(record.category, []).append(record)
        return result
