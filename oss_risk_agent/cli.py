import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from oss_risk_agent.core.scanner import Scanner
from oss_risk_agent.core.sarif import convert_to_sarif

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
):
    """
    Scan a repository for OSS security risks.
    """
    if o_format not in ["text", "json", "sarif"]:
        console.print(
            "[bold red]Invalid format. Choose from: text, json, sarif[/bold red]"
        )
        raise typer.Exit(code=1)

    if o_format == "text":
        console.print(Panel.fit(f"[bold blue]Starting scan for:[/bold blue] {path}"))

    scanner = Scanner(path)
    risks = scanner.scan()
    warnings = scanner.warnings

    if o_format in ["json", "sarif"]:
        output_data = ""
        if o_format == "json":
            result_obj = {
                "risks": [r.dict() for r in risks],
                "warnings": [w.dict() for w in warnings],
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

        # Rich table output
        if not risks:
            console.print("[bold green]No risks detected! 🎉[/bold green]")
            return

        table = Table(title="Detected Security Risks")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Severity", justify="center")
        table.add_column("Name", style="magenta")
        table.add_column("Target (Line)")
        table.add_column("Description")

        # Sort risks by severity roughly (CRITICAL -> HIGH -> MEDIUM -> LOW)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        risks.sort(key=lambda x: (severity_order.get(x.severity.value, 4), x.category))

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


if __name__ == "__main__":
    app()
