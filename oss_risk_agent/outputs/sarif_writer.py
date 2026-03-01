"""SARIF output renderer skeleton."""

from __future__ import annotations

import json

from oss_risk_agent.models.result import ScanResult


def render_sarif(result: ScanResult) -> str:
    """Render SARIF 2.1.0 structure.

    TODO: map risks to SARIF rules/results with precise locations.
    """
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "oss-risk-agent",
                        "informationUri": "https://github.com/ukimotodatascience/oss-security-risk-assessment-agent",
                        "rules": [],
                    }
                },
                "results": [],
                "invocations": [{"executionSuccessful": True}],
                "properties": {"scan_mode": result.scan_mode},
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
