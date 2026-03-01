"""CLI entrypoint for OSS Risk Agent."""

from __future__ import annotations

import argparse
from pathlib import Path

from oss_risk_agent.core.scanner import Scanner
from oss_risk_agent.models.result import ScanResult
from oss_risk_agent.outputs.json_writer import render_json
from oss_risk_agent.outputs.markdown_writer import render_markdown
from oss_risk_agent.outputs.sarif_writer import render_sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oss-risk-agent")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run security risk scan")
    scan.add_argument("target", nargs="?", default=".")
    scan.add_argument(
        "--format", choices=["text", "json", "markdown", "sarif"], default="text"
    )
    scan.add_argument("--output", "--output-file", dest="output_file")
    scan.add_argument(
        "--mode", choices=["pr", "nightly", "audit", "sbom"], default="pr"
    )
    scan.add_argument("--baseline")
    scan.add_argument("--create-baseline")
    scan.add_argument("--fail-on-critical", action="store_true")
    scan.add_argument("--max-risk-score", type=float)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        scanner = Scanner()
        result = scanner.scan(Path(args.target), mode=args.mode)
        return _handle_output_and_exit(result, args.format, args.output_file)

    parser.print_help()
    return 1


def _handle_output_and_exit(
    result: ScanResult, output_format: str, output_file: str | None
) -> int:
    if output_format == "json":
        payload = render_json(result)
    elif output_format == "markdown":
        payload = render_markdown(result)
    elif output_format == "sarif":
        payload = render_sarif(result)
    else:
        payload = result.to_text()

    if output_file:
        Path(output_file).write_text(payload, encoding="utf-8")
    else:
        print(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
