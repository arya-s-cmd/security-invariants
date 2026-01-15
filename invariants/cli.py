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
):
    """Run all security invariants and exit non-zero on failures."""
    findings = asyncio.run(run_all(config))

    if not findings:
        console.print("[bold green]✅ All invariants passed[/bold green]")
        raise typer.Exit(code=0)

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
