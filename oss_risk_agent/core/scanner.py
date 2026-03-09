"""Top-level scanner orchestration.

This module intentionally contains framework-level structure only.
Detailed scanning logic will be implemented in subsequent iterations.
"""

from __future__ import annotations

from pathlib import Path

from oss_risk_agent.models.result import ScanResult

from .rule_engine import RuleEngine


class Scanner:
    """Facade for scan execution across multiple modes."""

    def __init__(self) -> None:
        self.rule_engine = RuleEngine()

    def scan(self, target: Path, mode: str = "pr") -> ScanResult:
        """Run a scan and return normalized result object.

        TODO:
        - Resolve config/context from files and CLI flags
        - Execute mode-specific pipelines (PR/Nightly/Audit/SBOM)
        - Collect warnings from each subsystem
        """

        result = ScanResult(scan_mode=mode)
        result.risks = self.rule_engine.evaluate(target=target, mode=mode)
        result.summary.total_risks = len(result.risks)

        for risk in result.risks:
            if risk.severity.value == "Critical":
                result.summary.critical_count += 1
            elif risk.severity.value == "High":
                result.summary.high_count += 1
            elif risk.severity.value == "Medium":
                result.summary.medium_count += 1
            elif risk.severity.value == "Low":
                result.summary.low_count += 1
            else:
                result.summary.info_count += 1

        return result
