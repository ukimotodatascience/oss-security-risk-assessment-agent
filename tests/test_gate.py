import json
from pathlib import Path

from oss_risk_agent.core.gate import (
    apply_baseline,
    apply_ignore_rules,
    calculate_total_score,
    create_baseline_payload,
    evaluate_gate,
    load_fail_conditions,
)
from oss_risk_agent.core.models import RiskRecord, Severity


def _risk(
    category: str,
    severity: Severity,
    target_file: str,
    line_number: int | None = None,
) -> RiskRecord:
    return RiskRecord(
        category=category,
        name="test risk",
        severity=severity,
        description="desc",
        target_file=target_file,
        line_number=line_number,
        evidence="evidence",
    )


def test_load_fail_conditions_default(tmp_path: Path):
    cond = load_fail_conditions(tmp_path, ".oss-risk-policy.yml")
    assert cond == {"critical": 1, "high": 3, "total_score": 15}


def test_load_fail_conditions_custom(tmp_path: Path):
    (tmp_path / ".oss-risk-policy.yml").write_text(
        """
fail_conditions:
  critical: 2
  high: 5
  total_score: 20
""",
        encoding="utf-8",
    )
    cond = load_fail_conditions(tmp_path, ".oss-risk-policy.yml")
    assert cond == {"critical": 2, "high": 5, "total_score": 20}


def test_calculate_total_score():
    risks = [
        _risk("A-1", Severity.CRITICAL, "a.txt"),
        _risk("B-1", Severity.HIGH, "b.txt"),
        _risk("C-1", Severity.MEDIUM, "c.txt"),
        _risk("D-1", Severity.LOW, "d.txt"),
    ]
    assert calculate_total_score(risks) == 18


def test_evaluate_gate_default_fail_conditions():
    risks = [_risk("A-1", Severity.HIGH, "a.txt") for _ in range(3)]
    result = evaluate_gate(risks, {"critical": 1, "high": 3, "total_score": 15})
    assert result.fail is True
    assert result.high_count == 3


def test_apply_ignore_rules_rule_path_match(tmp_path: Path):
    ignore = tmp_path / ".oss-risk-ignore.yml"
    ignore.write_text(
        """
ignore_rules:
  - rule_id: B-2
    path: docker/Dockerfile
    reason: Internal trusted image registry
""",
        encoding="utf-8",
    )
    risks = [
        _risk("B-2", Severity.HIGH, "docker/Dockerfile"),
        _risk("C-3", Severity.MEDIUM, "app/server.py"),
    ]
    remained, applied = apply_ignore_rules(risks, tmp_path, ".oss-risk-ignore.yml")
    assert len(remained) == 1
    assert remained[0].category == "C-3"
    assert len(applied) == 1
    assert applied[0]["rule_id"] == "B-2"


def test_apply_baseline_marks_existing_as_informational(tmp_path: Path):
    base_risk = _risk("A-1", Severity.HIGH, "requirements.txt", line_number=1)
    new_risk = _risk("B-2", Severity.CRITICAL, "Dockerfile", line_number=3)

    payload = create_baseline_payload([base_risk])
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    output_risks, gate_risks, existing_count = apply_baseline(
        [base_risk, new_risk], str(baseline_path), tmp_path
    )

    assert existing_count == 1
    assert len(output_risks) == 2
    assert output_risks[0].severity == Severity.INFORMATIONAL
    assert len(gate_risks) == 1
    assert gate_risks[0].category == "B-2"
