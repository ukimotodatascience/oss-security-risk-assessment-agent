import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from oss_risk_agent.core.scanner import Scanner
from oss_risk_agent.core.sarif import convert_to_sarif
from oss_risk_agent.core.scoring import calculate_score_summary

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
        "--output-file",
        "-o",
        help="File to write output to (applicable for json, sarif)",
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

    if max_risk_score is not None and not (0 <= max_risk_score <= 100):
        console.print(
            "[bold red]Invalid --max-risk-score. Must be between 0 and 100.[/bold red]"
        )
        raise typer.Exit(code=1)

    if o_format == "text":
        console.print(Panel.fit(f"[bold blue]Starting scan for:[/bold blue] {path}"))

    scanner = Scanner(path)
    risks = scanner.scan()
    warnings = scanner.warnings
    summary = calculate_score_summary(risks)

    dump = getattr(summary, "model_dump", summary.dict)
    summary_dict = dump()

    if o_format in ["json", "sarif"]:
        output_data = ""
        if o_format == "json":
            result_obj = {
                "risks": [r.dict() for r in risks],
                "warnings": [w.dict() for w in warnings],
                "summary": summary_dict,
            }
            output_data = json.dumps(result_obj, indent=2, ensure_ascii=False)
        elif o_format == "sarif":
            output_data = convert_to_sarif(risks)

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
            f"[bold]Critical Count[/bold]: {summary.critical_count}"
        )
        console.print(Panel.fit(score_panel, title="Risk Summary"))

        cat_table = Table(title="Category Scores")
        cat_table.add_column("Category", style="cyan", no_wrap=True)
        cat_table.add_column("Score (0-100)", justify="right")
        for cat, score in summary.category_scores.items():
            cat_table.add_row(cat, f"{score:.2f}")
        console.print(cat_table)

        # Rich table output
        if not risks:
            console.print("[bold green]No risks detected! 🎉[/bold green]")
        else:
            table = Table(title="Detected Security Risks")
            table.add_column("Category", style="cyan", no_wrap=True)
            table.add_column("Severity", justify="center")
            table.add_column("Name", style="magenta")
            table.add_column("Target (Line)")
            table.add_column("Description")

            # Sort risks by severity roughly (CRITICAL -> HIGH -> MEDIUM -> LOW)
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
            risks.sort(
                key=lambda x: (severity_order.get(x.severity.value, 4), x.category)
            )

            for idx, risk in enumerate(risks):
                sev_color = (
                    "red" if risk.severity.value in ("HIGH", "CRITICAL") else "yellow"
                )
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
                if idx < len(risks) - 1:
                    table.add_row("", "", "", "", "")

            console.print(table)
            console.print(f"\n[bold red]Total risks found:[/bold red] {len(risks)}")

    should_fail = False
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
