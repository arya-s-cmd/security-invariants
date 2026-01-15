from __future__ import annotations

import asyncio
import json

import typer
from rich.console import Console
from rich.table import Table

from invariants.runner import run_all

console = Console()


def main(
    config: str = typer.Option("invariants.yml", "--config", "-c", help="Path to invariants.yml"),
    json_out: bool = typer.Option(False, "--json", help="Emit findings as JSON"),
    base_url: str = typer.Option("", "--base-url", help="Run against a live server URL (e.g. http://127.0.0.1:8000)"),
):
    """Run security invariants and exit non-zero on failures."""
    try:
        findings = asyncio.run(run_all(config, base_url=base_url.strip() or None))
    except Exception as e:
        console.print(f"[bold red] Runner crashed[/bold red]: {e}")
        raise typer.Exit(code=2)

    if not findings:
        console.print("[bold green] All invariants passed[/bold green]")
        raise typer.Exit(code=0)

    if json_out:
        payload = [
            {"severity": f.severity, "check": f.check, "message": f.message, "evidence": f.evidence}
            for f in findings
        ]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        raise typer.Exit(code=1)

    table = Table(title="Invariant Failures")
    table.add_column("Severity", style="bold")
    table.add_column("Check")
    table.add_column("Message")
    table.add_column("Evidence")

    for f in findings:
        table.add_row(
            f.severity,
            f.check,
            f.message,
            json.dumps(f.evidence, ensure_ascii=False) if f.evidence else "",
        )

    console.print(table)
    raise typer.Exit(code=1)


if __name__ == "__main__":
    typer.run(main)