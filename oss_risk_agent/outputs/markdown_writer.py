"""Markdown report renderer."""

from __future__ import annotations

from oss_risk_agent.models.result import ScanResult


def render_markdown(result: ScanResult) -> str:
    """Render markdown report skeleton.

    TODO: populate detailed sections and SLA/KEV tables.
    """
    lines = [
        "# OSS Risk Report",
        "",
        "## Executive Summary",
        f"- Scan mode: {result.scan_mode}",
        f"- Total risks: {len(result.risks)}",
        f"- Warnings: {len(result.warnings)}",
        "",
        "## Critical一覧",
        "- TODO",
        "",
        "## 新規リスク",
        "- TODO",
        "",
        "## SLA超過",
        "- TODO",
        "",
        "## KEV一覧",
        "- TODO",
        "",
        "## 修正優先度",
        "- TODO",
        "",
        "## Assumption",
        "- TODO",
    ]
    return "\n".join(lines)
