"""Risk scoring skeleton based on spec v4."""

from __future__ import annotations

from oss_risk_agent.config.settings import RuntimeConfig
from oss_risk_agent.models.context import ScanContext


class RiskScorer:
    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def compute_risk_score(
        self,
        cvss: float | None,
        epss_percentile: float | None,
        kev_flag: bool,
        exploit_available: bool,
        context: ScanContext,
    ) -> float:
        """Compute risk score in [0, 1+] before severity mapping.

        TODO: implement exact normalization, missing-value behavior, and clamp rules.
        """
        _ = (cvss, epss_percentile, kev_flag, exploit_available, context)
        return 0.0

    def map_severity(self, risk_score: float) -> str:
        """Map risk score to severity label."""
        if risk_score >= 0.85:
            return "Critical"
        if risk_score >= 0.65:
            return "High"
        if risk_score >= 0.40:
            return "Medium"
        if risk_score >= 0.20:
            return "Low"
        return "Info"
