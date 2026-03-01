import pytest
from pathlib import Path
from oss_risk_agent.rules.category_a_dependency import (
    A1VulnerableDependencyRule,
    A2UnpinnedDependencyRule,
    A3SbomGenerationRule,
    A4EffectiveVulnerabilityPriorityRule,
)
from oss_risk_agent.core.models import Severity


def test_a1_vulnerable_dependency_rule_reqs(dummy_repo: Path, mock_external_apis):
    rule = A1VulnerableDependencyRule()

    req_file = dummy_repo / "requirements.txt"
    req_file.write_text(
        "requests==2.25.1\nDjango==3.1.0\nnumpy>=1.19.0", encoding="utf-8"
    )

    risks = rule.analyze(dummy_repo)

    # We only checked exactly pinned dependencies in the current logic.
    # requests==2.25.1 and Django==3.1.0 will trigger API calls.
    # The mock returns a vuln for ALL queries, so we expect 2 risks.
    assert len(risks) == 2
    for risk in risks:
        assert risk.category == "A-1"
        assert risk.severity in [Severity.HIGH, Severity.CRITICAL]
        assert risk.target_file == "requirements.txt"


def test_a2_unpinned_dependency_rule(dummy_repo: Path):
    rule = A2UnpinnedDependencyRule()

    req_file = dummy_repo / "requirements.txt"
    req_file.write_text("requests>=2.25.1\nDjango==4.0.0", encoding="utf-8")

    risks = rule.analyze(dummy_repo)

    # Should flag requests>=2.25.1
    assert len(risks) == 1
    assert risks[0].category == "A-2"
    assert (
        "requests >=2.25.1" in risks[0].evidence
        or "requests >=2.25.1" in risks[0].description
    )
    assert risks[0].severity == Severity.MEDIUM


def test_a3_sbom_generation_rule(dummy_repo: Path):
    rule = A3SbomGenerationRule()
    (dummy_repo / "requirements.txt").write_text("requests>=2.0\n", encoding="utf-8")

    risks = rule.analyze(dummy_repo)
    categories = [r.category for r in risks]
    assert "A-3" in categories
    assert any(r.severity == Severity.MEDIUM for r in risks)
    assert any(r.severity == Severity.HIGH for r in risks)


def test_a4_effective_vulnerability_priority_rule(dummy_repo: Path, monkeypatch):
    rule = A4EffectiveVulnerabilityPriorityRule()
    (dummy_repo / "requirements.txt").write_text("requests==2.25.1\n", encoding="utf-8")

    monkeypatch.setattr(
        "oss_risk_agent.rules.category_a_dependency.check_vulnerability",
        lambda name, version, ecosystem="PyPI": {
            "vulns": [
                {
                    "id": "CVE-2024-0001",
                    "severity": [{"type": "CVSS_V3", "score": "7.5"}],
                }
            ]
        },
    )
    monkeypatch.setattr(
        "oss_risk_agent.rules.category_a_dependency.get_epss_score",
        lambda cve: 0.3,
    )
    monkeypatch.setattr(
        "oss_risk_agent.rules.category_a_dependency.is_known_exploited",
        lambda cve: False,
    )

    risks = rule.analyze(dummy_repo)
    assert len(risks) >= 1
    r = risks[0]
    assert r.category == "A-4"
    assert r.score_metadata is not None
    assert "effective_score" in r.score_metadata
