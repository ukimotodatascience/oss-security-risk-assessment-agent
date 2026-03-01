"""Scan result models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from .context import ScanContext
from .risk import RiskRecord


@dataclass(slots=True)
class ScanWarning:
    code: str
    message: str
    detail: str | None = None


@dataclass(slots=True)
class Summary:
    total_risks: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_score: float = 0.0
    maturity_score: float = 100.0


@dataclass(slots=True)
class ScanResult:
    scan_mode: str
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    context: ScanContext = field(default_factory=ScanContext)
    risks: list[RiskRecord] = field(default_factory=list)
    warnings: list[ScanWarning] = field(default_factory=list)
    summary: Summary = field(default_factory=Summary)
    assumptions: list[str] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_mode": self.scan_mode,
            "scan_timestamp": self.scan_timestamp,
            "context": asdict(self.context),
            "risks": [r.to_dict() for r in self.risks],
            "warnings": [asdict(w) for w in self.warnings],
            "summary": asdict(self.summary),
            "assumptions": self.assumptions,
            "coverage": self.coverage,
        }

    def to_text(self) -> str:
        return (
            "OSS Risk Agent (skeleton)\n"
            f"mode={self.scan_mode} risks={len(self.risks)} warnings={len(self.warnings)}"
        )
