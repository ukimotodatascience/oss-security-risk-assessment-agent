import pytest
from pathlib import Path
from oss_risk_agent.rules.category_c_configuration import (
    C1ContainerRootRule,
    C2SensitiveFileRule,
    C3ExposedBindRule,
)
from oss_risk_agent.core.models import Severity


def test_c1_root_execution_rule(dummy_repo: Path):
    rule = C1ContainerRootRule()

    # 1. Non-compliant Dockerfile (no USER instruction)
    bad_df = dummy_repo / "Dockerfile.bad"
    bad_df.write_text("FROM ubuntu:latest\nRUN apt-get update", encoding="utf-8")

    # 2. Compliant Dockerfile (has USER instruction)
    good_df = dummy_repo / "Dockerfile.good"
    good_df.write_text(
        'FROM ubuntu:latest\nRUN useradd myuser\nUSER myuser\nCMD ["bash"]',
        encoding="utf-8",
    )

    risks = rule.analyze(dummy_repo)

    assert len(risks) == 1
    assert risks[0].category == "C-1"
    assert risks[0].severity == Severity.HIGH
    assert "USER命令" in risks[0].description
    assert risks[0].target_file == "Dockerfile.bad"


def test_c2_secret_file_rule(dummy_repo: Path):
    rule = C2SensitiveFileRule()

    # Create mock secret files
    (dummy_repo / ".env").write_text("API_KEY=foo")
    (dummy_repo / "id_rsa.pem").write_text("-----BEGIN RSA PRIVATE KEY-----")
    (dummy_repo / "config.json").write_text("{}")

    risks = rule.analyze(dummy_repo)

    # Should detect .env and .pem, but not config.json
    assert len(risks) == 2
    for risk in risks:
        assert risk.category == "C-2"
        assert risk.severity == Severity.CRITICAL
        assert risk.target_file in [".env", "id_rsa.pem"]


def test_c3_network_bind_rule(dummy_repo: Path):
    rule = C3ExposedBindRule()

    # Python file binding to 0.0.0.0
    (dummy_repo / "app.py").write_text(
        "app.run(host='0.0.0.0', port=8080)", encoding="utf-8"
    )

    # Go file binding to 0.0.0.0
    (dummy_repo / "main.go").write_text(
        'http.ListenAndServe("0.0.0.0:8080", nil)', encoding="utf-8"
    )

    # Safe binding
    (dummy_repo / "safe.py").write_text(
        "app.run(host='127.0.0.1', port=8080)", encoding="utf-8"
    )

    risks = rule.analyze(dummy_repo)

    assert len(risks) == 2
    for risk in risks:
        assert risk.category == "C-3"
        assert risk.severity == Severity.MEDIUM
        assert risk.target_file in ["app.py", "main.go"]
        assert "0.0.0.0" in risk.evidence
