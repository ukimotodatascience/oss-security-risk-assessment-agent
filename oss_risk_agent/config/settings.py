"""Typed runtime settings skeleton."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class RiskPolicy:
    critical: int = 1
    high: int = 3
    total_score: int = 15


@dataclass(slots=True)
class SuppressRule:
    rule_id: str
    justification: str
    expiry_date: str
    approver: str
    ticket: str
    path: str | None = None
    hash: str | None = None


@dataclass(slots=True)
class RuntimeConfig:
    w_cvss: float = 0.5
    w_epss: float = 0.3
    kev_bonus: float = 0.2
    exploit_bonus: float = 0.1
    max_context_multiplier: float = 2.0
    min_context_multiplier: float = 0.5
    policy: RiskPolicy = field(default_factory=RiskPolicy)
    suppress_rules: list[SuppressRule] = field(default_factory=list)
