"""Risk-related data models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(slots=True)
class Evidence:
    file: str | None = None
    line: int | None = None
    snippet: str | None = None
    source: str | None = None


@dataclass(slots=True)
class RiskRecord:
    category: str
    rule_id: str
    severity: Severity
    risk_score: float | None = None
    confidence: float | None = None
    evidence: list[Evidence] = field(default_factory=list)
    remediation: str = "TODO: add remediation guidance"
    cvss: float | None = None
    epss: float | None = None
    kev_flag: bool = False
    exploit_available: bool = False
    context: dict[str, Any] = field(default_factory=dict)
    status: str = "OPEN"
    source: str = "rule-engine"
    scan_mode: str = "pr"
    scan_timestamp: str | None = None
    coverage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data
