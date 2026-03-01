from oss_risk_agent.core.models import RiskRecord, Severity
from oss_risk_agent.core.scoring import calculate_score_summary


def test_score_summary_empty_risks():
    summary = calculate_score_summary([])

    assert summary.risk_score == 0.0
    assert summary.maturity_score == 100.0
    assert summary.total_risks == 0
    assert summary.critical_count == 0
    assert summary.category_scores["A"] == 0.0
    assert summary.category_scores["F"] == 0.0


def test_score_summary_weighted_categories():
    risks = [
        RiskRecord(
            category="A-1",
            name="vuln",
            severity=Severity.CRITICAL,
            description="",
            target_file="a.txt",
            evidence="e",
        ),
        RiskRecord(
            category="B-1",
            name="supply",
            severity=Severity.HIGH,
            description="",
            target_file="b.txt",
            evidence="e",
        ),
        RiskRecord(
            category="C-1",
            name="config",
            severity=Severity.MEDIUM,
            description="",
            target_file="c.txt",
            evidence="e",
        ),
    ]

    summary = calculate_score_summary(risks)

    # A=100, B=60, C=30 with weights A(0.30),B(0.20),C(0.20)
    expected = round(100 * 0.30 + 60 * 0.20 + 30 * 0.20, 2)

    assert summary.risk_score == expected
    assert summary.maturity_score == round(100 - expected, 2)
    assert summary.counts_by_severity["CRITICAL"] == 1
    assert summary.counts_by_severity["HIGH"] == 1
    assert summary.counts_by_severity["MEDIUM"] == 1
    assert summary.total_risks == 3


def test_score_summary_unknown_category_is_unscored():
    risks = [
        RiskRecord(
            category="G-1",
            name="opa",
            severity=Severity.HIGH,
            description="",
            target_file="g.txt",
            evidence="e",
        )
    ]

    summary = calculate_score_summary(risks)

    assert summary.risk_score == 0.0
    assert summary.unscored_categories == []
