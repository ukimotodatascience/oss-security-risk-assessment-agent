import json
import subprocess
from pathlib import Path

from oss_risk_agent.core.models import Severity
from oss_risk_agent.core.opa_integration import OPAIntegrationEngine


def test_evaluate_returns_empty_when_opa_not_installed(tmp_path: Path, monkeypatch):
    engine = OPAIntegrationEngine(tmp_path)

    monkeypatch.setattr("shutil.which", lambda _: None)

    risks = engine.evaluate({"name": "demo"}, "oss_risk.package_json")
    assert risks == []


def test_evaluate_parses_opa_result_to_risk_records(tmp_path: Path, monkeypatch):
    engine = OPAIntegrationEngine(tmp_path)

    monkeypatch.setattr("shutil.which", lambda _: "opa")

    opa_payload = {
        "result": [
            {
                "expressions": [
                    {
                        "value": {
                            "deny": [
                                {
                                    "msg": "危険な依存バージョンです",
                                    "severity": "CRITICAL",
                                    "file": "package.json",
                                    "line": 12,
                                    "evidence": "left-pad@*",
                                }
                            ],
                            "warn": [
                                {
                                    "msg": "推奨設定が不足しています",
                                    "file": "package.json",
                                }
                            ],
                        }
                    }
                ]
            }
        ]
    }

    def fake_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=json.dumps(opa_payload, ensure_ascii=False),
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    risks = engine.evaluate({"name": "demo"}, "oss_risk.package_json")

    assert len(risks) == 2

    deny_risk = risks[0]
    assert deny_risk.category == "G-1"
    assert deny_risk.severity == Severity.CRITICAL
    assert deny_risk.target_file == "package.json"
    assert deny_risk.line_number == 12

    warn_risk = risks[1]
    assert warn_risk.category == "G-1"
    assert warn_risk.severity == Severity.MEDIUM
    assert "推奨設定" in warn_risk.description
