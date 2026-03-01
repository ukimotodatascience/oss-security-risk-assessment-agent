import json
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from oss_risk_agent.core.gate import (
    apply_baseline,
    apply_ignore_rules,
    build_audit_log,
    create_baseline_payload,
    evaluate_gate,
    load_fail_conditions,
    load_fail_conditions_with_profile,
)
from oss_risk_agent.core.models import Severity
from oss_risk_agent.core.scanner import Scanner
from oss_risk_agent.core.sarif import convert_to_sarif
from oss_risk_agent.core.scoring import calculate_score_summary
from oss_risk_agent.utils.sbom import generate_cyclonedx_sbom

app = typer.Typer(
    name="oss-risk-agent",
    help="OSS Security Risk Assessment Agent",
    add_completion=False,
)
console = Console()


@app.command()
def scan(
    path: str = typer.Argument(..., help="Path to the repository to scan"),
    o_format: str = typer.Option(
        "text", "--format", "-f", help="Output format: text, json, sarif"
    ),
    output_file: str = typer.Option(
        None,
        "--output",
        "--output-file",
        "-o",
        help="File to write output to (applicable for json, sarif)",
    ),
    create_baseline: str = typer.Option(
        None,
        "--create-baseline",
        help="Create baseline JSON from current scan results and save to file",
    ),
    baseline: str = typer.Option(
        None,
        "--baseline",
        help="Use baseline JSON and evaluate only newly introduced risks",
    ),
    generate_sbom: bool = typer.Option(
        False,
        "--generate-sbom",
        help="Generate CycloneDX SBOM (sbom.cdx.json) before scanning",
    ),
    profile: str = typer.Option(
        None,
        "--profile",
        help="Policy profile name (e.g. production/development)",
    ),
    policy_file: str = typer.Option(
        "policy.yml",
        "--policy-file",
        help="Policy file path (relative to scan root)",
    ),
    ignore_file: str = typer.Option(
        ".oss-riskignore",
        "--ignore-file",
        help="Ignore file path (relative to scan root)",
    ),
    ignore_expired_check: bool = typer.Option(
        False,
        "--ignore-expired-check",
        help="Apply ignore rules even when expiry has passed",
    ),
    max_risk_score: float = typer.Option(
        None,
        "--max-risk-score",
        help="Fail with exit code 1 if calculated risk score is greater than this threshold (0-100)",
    ),
    fail_on_critical: bool = typer.Option(
        False,
        "--fail-on-critical",
        help="Fail with exit code 1 when at least one CRITICAL risk is detected",
    ),
):
    """
    Scan a repository for OSS security risks.
    """
    if o_format not in ["text", "json", "sarif"]:
        console.print(
            "[bold red]Invalid format. Choose from: text, json, sarif[/bold red]"
        )
        raise typer.Exit(code=1)

    repo_path = Path(path)

    if generate_sbom:
        sbom_path = repo_path / "sbom.cdx.json"
        generate_cyclonedx_sbom(repo_path, sbom_path)
        if o_format == "text":
            console.print(f"[green]SBOM generated:[/green] {sbom_path}")

    if max_risk_score is not None and not (0 <= max_risk_score <= 100):
        console.print(
            "[bold red]Invalid --max-risk-score. Must be between 0 and 100.[/bold red]"
        )
        raise typer.Exit(code=1)

    if o_format == "text":
        console.print(Panel.fit(f"[bold blue]Starting scan for:[/bold blue] {path}"))

    scanner = Scanner(path)
    raw_risks = scanner.scan()
    warnings = scanner.warnings

    filtered_risks, ignore_applied = apply_ignore_rules(
        raw_risks,
        repo_path,
        ignore_file,
        ignore_expired_check=ignore_expired_check,
    )
    output_risks, gate_target_risks, baseline_existing_count = apply_baseline(
        filtered_risks, baseline, repo_path
    )

    if create_baseline:
        baseline_payload = create_baseline_payload(filtered_risks)
        with open(create_baseline, "w", encoding="utf-8") as f:
            f.write(json.dumps(baseline_payload, indent=2, ensure_ascii=False))
        console.print(
            f"[bold green]Successfully created baseline file:[/bold green] {create_baseline}"
        )
        return

    summary = calculate_score_summary(output_risks)

    fail_conditions = load_fail_conditions_with_profile(repo_path, policy_file, profile)
    gate_result = evaluate_gate(gate_target_risks, fail_conditions)
    audit_log = build_audit_log(repo_path, fail_conditions, ignore_applied, policy_file)

    dump = getattr(summary, "model_dump", summary.dict)
    summary_dict = dump()

    if o_format in ["json", "sarif"]:
        output_data = ""
        if o_format == "json":
            result_obj = {
                "risks": [r.dict() for r in output_risks],
                "warnings": [w.dict() for w in warnings],
                "summary": summary_dict,
                "gate": gate_result.model_dump(),
                "baseline": {
                    "enabled": bool(baseline),
                    "existing_risks_count": baseline_existing_count,
                    "new_risks_count": len(gate_target_risks),
                },
                "audit_log": audit_log,
            }
            output_data = json.dumps(result_obj, indent=2, ensure_ascii=False)
        elif o_format == "sarif":
            output_data = convert_to_sarif(output_risks)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output_data)
            console.print(
                f"[bold green]Successfully wrote {o_format} output to {output_file}[/bold green]"
            )
        else:
            print(output_data)
    else:
        if warnings:
            console.print(
                Panel.fit(
                    f"[bold yellow]Scan warnings:[/bold yellow] {len(warnings)} (一部ルールでエラーが発生しました)"
                )
            )

        score_panel = (
            f"[bold]Risk Score[/bold]: {summary.risk_score:.2f} / 100 (高いほど危険)\n"
            f"[bold]Maturity Score[/bold]: {summary.maturity_score:.2f} / 100 (高いほど成熟)\n"
            f"[bold]Critical Count[/bold]: {summary.critical_count}\n"
            f"[bold]Gate Total Score[/bold]: {gate_result.total_score}"
        )
        console.print(Panel.fit(score_panel, title="Risk Summary"))

        gate_panel = (
            f"[bold]Critical[/bold]: {gate_result.critical_count} / threshold {gate_result.fail_conditions['critical']}\n"
            f"[bold]High[/bold]: {gate_result.high_count} / threshold {gate_result.fail_conditions['high']}\n"
            f"[bold]Total Score[/bold]: {gate_result.total_score} / threshold {gate_result.fail_conditions['total_score']}\n"
            f"[bold]Evaluated Risks[/bold]: {gate_result.evaluated_risk_count}"
        )
        console.print(Panel.fit(gate_panel, title="Approval Gate"))

        if baseline:
            console.print(
                Panel.fit(
                    f"[bold]Baseline mode enabled[/bold]\nexisting risks: {baseline_existing_count}\nnew risks: {len(gate_target_risks)}",
                    title="Baseline Diff Gate",
                )
            )

        if ignore_applied:
            console.print(
                Panel.fit(
                    f"[bold]Ignore rules applied[/bold]: {len(ignore_applied)}",
                    title="Ignore / Allowlist",
                )
            )

        cat_table = Table(title="Category Scores")
        cat_table.add_column("Category", style="cyan", no_wrap=True)
        cat_table.add_column("Score (0-100)", justify="right")
        for cat, score in summary.category_scores.items():
            cat_table.add_row(cat, f"{score:.2f}")
        console.print(cat_table)

        # Rich table output
        if not output_risks:
            console.print("[bold green]No risks detected! 🎉[/bold green]")
        else:
            table = Table(title="Detected Security Risks")
            table.add_column("Category", style="cyan", no_wrap=True)
            table.add_column("Severity", justify="center")
            table.add_column("Name", style="magenta")
            table.add_column("Target (Line)")
            table.add_column("Description")

            # Sort risks by severity roughly (CRITICAL -> HIGH -> MEDIUM -> LOW)
            severity_order = {
                Severity.CRITICAL.value: 0,
                Severity.HIGH.value: 1,
                Severity.MEDIUM.value: 2,
                Severity.LOW.value: 3,
                Severity.INFORMATIONAL.value: 4,
            }
            output_risks.sort(
                key=lambda x: (severity_order.get(x.severity.value, 4), x.category)
            )

            for idx, risk in enumerate(output_risks):
                sev_color = (
                    "red" if risk.severity.value in ("HIGH", "CRITICAL") else "yellow"
                )
                if risk.severity.value == "INFORMATIONAL":
                    sev_color = "cyan"
                target_disp = risk.target_file
                if risk.line_number:
                    target_disp += f" (L{risk.line_number})"

                table.add_row(
                    risk.category,
                    f"[{sev_color} bold]{risk.severity.value}[/{sev_color} bold]",
                    risk.name,
                    target_disp,
                    risk.description,
                )
                # 視認性向上のために行間に空行を入れる（最後以外）
                if idx < len(output_risks) - 1:
                    table.add_row("", "", "", "", "")

            console.print(table)
            console.print(
                f"\n[bold red]Total risks found:[/bold red] {len(output_risks)}"
            )

    should_fail = False

    if gate_result.fail:
        should_fail = True
        console.print("[bold red]Policy violation:[/bold red] approval gate failed.")

    if fail_on_critical and summary.critical_count > 0:
        should_fail = True
        console.print(
            f"[bold red]Policy violation:[/bold red] critical risks detected ({summary.critical_count})."
        )

    if max_risk_score is not None and summary.risk_score > max_risk_score:
        should_fail = True
        console.print(
            f"[bold red]Policy violation:[/bold red] risk score {summary.risk_score:.2f} exceeds threshold {max_risk_score:.2f}."
        )

    if should_fail:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
