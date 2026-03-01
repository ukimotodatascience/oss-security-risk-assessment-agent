"""Rule engine skeleton."""

from __future__ import annotations

from pathlib import Path

from oss_risk_agent.models.risk import RiskRecord
from oss_risk_agent.rules.registry import RuleRegistry


class RuleEngine:
    def __init__(self) -> None:
        self.registry = RuleRegistry.default()

    def evaluate(self, target: Path, mode: str) -> list[RiskRecord]:
        """Evaluate registered rules.

        TODO: implement file discovery, diff-only filtering and evidence aggregation.
        """
        findings: list[RiskRecord] = []
        for rule in self.registry.rules:
            _ = (target, mode, rule)
            # TODO: run rule and append findings
        return findings
