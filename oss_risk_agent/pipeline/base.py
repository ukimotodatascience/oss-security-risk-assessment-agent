"""Pipeline interface for scan modes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oss_risk_agent.models.result import ScanResult


@dataclass(slots=True)
class Pipeline:
    mode: str

    def run(self, target: Path) -> ScanResult:
        """Run mode-specific pipeline.

        TODO: implement concrete behavior per mode.
        """
        _ = target
        return ScanResult(scan_mode=self.mode)
