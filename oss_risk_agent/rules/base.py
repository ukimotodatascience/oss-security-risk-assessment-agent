"""Base rule interface."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oss_risk_agent.models.risk import RiskRecord


@dataclass(slots=True)
class Rule:
    rule_id: str
    category: str
    title: str
    enabled: bool = True

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        """Evaluate rule against target.

        TODO: implement per-rule logic.
        """
        _ = (target, mode)
        return []
