"""Organizational unit domain models."""

from dataclasses import dataclass
from typing import Optional, Dict, Iterable, Tuple


@dataclass(frozen=True)
class OrganizationalUnit:
    """Represents an AWS Organizations OU or root."""

    id: str
    name: str
    parent_id: Optional[str]
    child_ou_ids: Tuple[str, ...]
    account_ids: Tuple[str, ...]

    def account_count(self) -> int:
        return len(self.account_ids)


@dataclass
class OrgHierarchy:
    """Complete AWS Organizations hierarchy summary."""

    roots: Tuple[str, ...]
    units: Dict[str, OrganizationalUnit]

    def total_units(self) -> int:
        return len(self.units)

    def iter_units_depth_first(self) -> Iterable[tuple[OrganizationalUnit, int]]:
        """Yield units depth-first with depth values."""

        def walk(ou_id: str, depth: int):
            unit = self.units.get(ou_id)
            if not unit:
                return
            yield unit, depth
            for child_id in unit.child_ou_ids:
                yield from walk(child_id, depth + 1)

        for root_id in self.roots:
            yield from walk(root_id, 0)

    def parent_name(self, ou_id: str) -> Optional[str]:
        unit = self.units.get(ou_id)
        if not unit or not unit.parent_id:
            return None
        parent = self.units.get(unit.parent_id)
        return parent.name if parent else None

    def account_ids_for(self, ou_id: str) -> Tuple[str, ...]:
        unit = self.units.get(ou_id)
        return unit.account_ids if unit else tuple()
