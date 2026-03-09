from __future__ import annotations

from pathlib import Path

from oss_risk_agent.core.scanner import Scanner
from oss_risk_agent.rules.builtin import A0_SbomFullAnalysisRule


def test_a0_returns_medium_when_only_direct_dependencies(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")

    rule = A0_SbomFullAnalysisRule()
    findings = rule.evaluate(target=tmp_path, mode="pr")

    assert len(findings) == 1
    assert findings[0].rule_id == "A-0"
    assert findings[0].severity.value == "Medium"
    assert findings[0].context["direct_dependencies"] >= 1
    assert findings[0].context["transitive_dependencies"] == 0


def test_a0_returns_info_when_transitive_dependencies_available(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"dependencies": {"express": "^4.19.0"}}',
        encoding="utf-8",
    )
    (tmp_path / "package-lock.json").write_text(
        """
        {
          "name": "sample",
          "lockfileVersion": 3,
          "packages": {
            "": {"name": "sample"},
            "node_modules/express": {"version": "4.19.2"},
            "node_modules/body-parser": {"version": "1.20.2"}
          }
        }
        """,
        encoding="utf-8",
    )

    rule = A0_SbomFullAnalysisRule()
    findings = rule.evaluate(target=tmp_path, mode="sbom")

    assert len(findings) == 1
    assert findings[0].rule_id == "A-0"
    assert findings[0].severity.value == "Info"
    assert findings[0].context["direct_dependencies"] >= 1
    assert findings[0].context["transitive_dependencies"] >= 1
    assert findings[0].status == "MITIGATED"


def test_scanner_includes_a0_result_in_output(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n", encoding="utf-8")

    scanner = Scanner()
    result = scanner.scan(target=tmp_path, mode="pr")

    a0_results = [r for r in result.risks if r.rule_id == "A-0"]
    assert len(a0_results) == 1
    assert result.summary.total_risks == len(result.risks)
