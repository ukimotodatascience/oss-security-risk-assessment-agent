import pytest
from pathlib import Path
from oss_risk_agent.rules.category_f_cicd import (
    F1SecretsLogOutputRule,
    F2StructuredTokenDetectionRule,
)
from oss_risk_agent.core.models import Severity


def test_f1_secrets_log_rule(dummy_repo: Path):
    rule = F1SecretsLogOutputRule()
    workflow_dir = dummy_repo / ".github" / "workflows"

    # Bad workflow (echoing secrets)
    bad_yml = workflow_dir / "bad_secrets.yml"
    bad_yml.write_text(
        """
jobs:
  build:
    steps:
      - name: show token
        run: echo "Token is ${{ secrets.GITHUB_TOKEN }}"
""",
        encoding="utf-8",
    )

    # Good workflow
    good_yml = workflow_dir / "good_secrets.yml"
    good_yml.write_text(
        """
jobs:
  build:
    steps:
      - name: deploy
        env:
          MY_TOKEN: ${{ secrets.DEPLOY_TOKEN }}
        run: ./deploy.sh
""",
        encoding="utf-8",
    )

    risks = rule.analyze(dummy_repo)

    assert len(risks) == 1
    assert risks[0].category == "F-1"
    assert "機密情報" in risks[0].description
    assert risks[0].severity == Severity.CRITICAL


def test_f2_structured_token_detection_rule(dummy_repo: Path):
    rule = F2StructuredTokenDetectionRule()

    (dummy_repo / "app.py").write_text(
        'token = "ghp_abcdefghijklmnopqrstuvwxyz123456"\n',
        encoding="utf-8",
    )
    (dummy_repo / "creds.env").write_text(
        "AWS_KEY=AKIA1234567890ABCDEF\n", encoding="utf-8"
    )

    risks = rule.analyze(dummy_repo)
    assert len(risks) >= 1
    assert any(r.category == "F-2" for r in risks)
    assert all(r.severity == Severity.CRITICAL for r in risks)
