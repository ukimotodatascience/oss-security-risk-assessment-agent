"""Smoke test skeleton for CLI."""

from __future__ import annotations

from oss_risk_agent.cli import build_parser


def test_parser_has_scan_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["scan", "."])
    assert args.command == "scan"
