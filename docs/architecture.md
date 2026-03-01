# Architecture Skeleton

## Main Flow

1. CLI (`oss_risk_agent/cli.py`)
2. Scanner (`oss_risk_agent/core/scanner.py`)
3. RuleEngine (`oss_risk_agent/core/rule_engine.py`)
4. Scoring (`oss_risk_agent/scoring/scorer.py`)
5. Outputs (`oss_risk_agent/outputs/*`)

## Modules

- `models/`: Result, risk, context dataclasses
- `config/`: Runtime policy and suppression loading
- `rules/`: Rule interface and registry
- `integrations/`: External APIs (KEV/GHSA/OSV/NVD/GitHub)
- `pipeline/`: PR/Nightly/Audit/SBOM execution skeleton

## Notes

- This repository currently contains **structure-first** implementation.
- Detection logic, API calls, and file parsing are intentionally TODO.
