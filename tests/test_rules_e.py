import pytest
from pathlib import Path
from oss_risk_agent.rules.category_e_license import (
    E1GplLicenseRule,
    E2MissingLicenseRule,
)
from oss_risk_agent.core.models import Severity


def test_e1_copyleft_license_rule(dummy_repo: Path):
    rule = E1GplLicenseRule()

    # 1. Provide an AGPL license
    lic_file = dummy_repo / "LICENSE"
    lic_file.write_text("GNU AFFERO GENERAL PUBLIC LICENSE ...", encoding="utf-8")

    risks = rule.analyze(dummy_repo)

    assert len(risks) == 1
    assert risks[0].category == "E-1"
    assert risks[0].severity == Severity.MEDIUM
    assert "強いコピーレフトライセンス" in risks[0].description

    # 2. Provide an MIT license
    lic_file.write_text("MIT License ...", encoding="utf-8")
    risks_mit = rule.analyze(dummy_repo)
    assert len(risks_mit) == 0


def test_e2_missing_license_rule(dummy_repo: Path):
    rule = E2MissingLicenseRule()

    # Initially no license
    risks = rule.analyze(dummy_repo)
    assert len(risks) == 1
    assert risks[0].category == "E-2"
    assert risks[0].severity == Severity.HIGH

    # Add license
    (dummy_repo / "LICENSE.md").write_text("MIT")
    risks_after = rule.analyze(dummy_repo)
    assert len(risks_after) == 0
