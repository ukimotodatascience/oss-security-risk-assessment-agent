from __future__ import annotations

from collections import Counter, defaultdict
from typing import Dict, List

from pydantic import BaseModel, Field

from .models import RiskRecord, Severity


SEVERITY_SCORES: Dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 3,
    Severity.HIGH: 6,
    Severity.CRITICAL: 10,
}

# Category weights (enterprise extended categories)
CATEGORY_WEIGHTS: Dict[str, float] = {
    "A": 0.30,
    "B": 0.20,
    "C": 0.20,
    "D": 0.15,
    "E": 0.10,
    "F": 0.05,
    "G": 0.00,
}


class ScoreSummary(BaseModel):
    risk_score: float = Field(description="0=low risk, 100=high risk")
    maturity_score: float = Field(description="0=immature, 100=mature")
    category_scores: Dict[str, float]
    counts_by_severity: Dict[str, int]
    counts_by_category: Dict[str, int]
    total_risks: int
    critical_count: int
    unscored_categories: List[str] = Field(default_factory=list)
    health_score: float = Field(default=100.0)


def _category_group(category: str) -> str:
    if not category:
        return "UNKNOWN"
    return category.split("-", 1)[0].upper()


def calculate_score_summary(risks: List[RiskRecord]) -> ScoreSummary:
    """
    Calculate Risk/Maturity scores from detected risks.

    - Risk score: 0 (best) to 100 (worst)
    - Maturity score: 100 - risk score
    """
    if not risks:
        return ScoreSummary(
            risk_score=0.0,
            maturity_score=100.0,
            category_scores={k: 0.0 for k in sorted(CATEGORY_WEIGHTS.keys())},
            counts_by_severity={s.value: 0 for s in Severity},
            counts_by_category={},
            total_risks=0,
            critical_count=0,
            unscored_categories=[],
            health_score=100.0,
        )

    counts_by_severity_counter = Counter(r.severity.value for r in risks)
    counts_by_category_counter = Counter(r.category for r in risks)

    counts_by_severity = {
        s.value: counts_by_severity_counter.get(s.value, 0) for s in Severity
    }
    counts_by_category = dict(
        sorted(counts_by_category_counter.items(), key=lambda x: x[0])
    )

    category_sum_score = defaultdict(float)
    category_count = defaultdict(int)
    health_scores: List[float] = []

    for risk in risks:
        group = _category_group(risk.category)
        category_sum_score[group] += SEVERITY_SCORES.get(risk.severity, 0)
        category_count[group] += 1
        if risk.category == "D-3" and isinstance(risk.score_metadata, dict):
            hs = risk.score_metadata.get("health_score")
            if isinstance(hs, (int, float)):
                health_scores.append(float(hs))

    # Enterprise extended: category score uses accumulated severity contribution.
    #   category_score = min(sum(severity_weight) * 10, 100)
    category_scores: Dict[str, float] = {}
    for group in CATEGORY_WEIGHTS.keys():
        normalized = min(category_sum_score.get(group, 0.0) * 10.0, 100.0)
        category_scores[group] = round(normalized, 2)

    # Total Risk Score = Σ(category_weight × severity_weight × rule_count)
    # Scaled to 0-100 by multiplying by 10, then capped.
    weighted_raw = 0.0
    for group, weight in CATEGORY_WEIGHTS.items():
        weighted_raw += weight * category_sum_score.get(group, 0.0)

    risk_score = round(min(max(weighted_raw * 10.0, 0.0), 100.0), 2)
    maturity_score = round(100.0 - risk_score, 2)
    health_score = round(min(health_scores), 2) if health_scores else 100.0

    unscored_categories = sorted(
        {g for g in category_count.keys() if g not in CATEGORY_WEIGHTS}
    )

    return ScoreSummary(
        risk_score=risk_score,
        maturity_score=maturity_score,
        category_scores=category_scores,
        counts_by_severity=counts_by_severity,
        counts_by_category=counts_by_category,
        total_risks=len(risks),
        critical_count=counts_by_severity.get(Severity.CRITICAL.value, 0),
        unscored_categories=unscored_categories,
        health_score=health_score,
    )
