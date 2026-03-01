"""JSON output renderer."""

from __future__ import annotations

import json

from oss_risk_agent.models.result import ScanResult


def render_json(result: ScanResult) -> str:
    """Render normalized JSON output.

    TODO: align fields with final audit schema v4.
    """
    return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
