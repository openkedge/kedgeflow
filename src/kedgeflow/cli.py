"""KedgeFlow command-line interface."""

from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="kedgeflow",
    help="KedgeFlow: Agents propose. KedgeFlow controls. Execution proves.",
    add_completion=False,
)
console = Console()

__version__ = "0.1.0-alpha.1"


def version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]kedgeflow[/bold cyan] version [green]{__version__}[/green]")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show the KedgeFlow version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """KedgeFlow: Programmable Agentic Control Plane."""
    pass


@app.command()
def status() -> None:
    """Display the KedgeFlow control plane status and architecture overview."""
    console.print("[bold cyan]KedgeFlow Control Plane[/bold cyan]")
    console.print("  [bold]Status:[/bold] Reference implementation active (in-process mode)")
    console.print(f"  [bold]Version:[/bold] {__version__}")
    console.print("  [bold]Architecture:[/bold] OpenKedge Agentic Control Plane (ACP)")
    console.print("  [bold]Components:[/bold]")
    console.print("    - Protocol Engine: v0.1 (Proposal, Grant, Guard, Receipt)")
    console.print("    - Controller: KedgeFlowController with HMAC-SHA256 Signer")
    console.print("    - Enforcer: LocalEnforcer with live Guard evaluator")
    console.print("    - State: GlobalState (thread-safe in-memory store)")


@app.command()
def demo(
    scenario: str = typer.Argument(
        "hello",
        help="Demo scenario to run: 'hello' (default) or 'conflict'",
    ),
) -> None:
    """Run an end-to-end KedgeFlow scenario demonstrating control plane enforcement."""
    scenario_clean = scenario.strip().lower()

    if scenario_clean in ("hello", "default"):
        from kedgeflow.demos.hello import run_demo

        console.print("[bold yellow]==> Running Hello KedgeFlow Scenario...[/bold yellow]\n")
        run_demo()
    elif scenario_clean == "conflict":
        from kedgeflow.demos.conflict import run_conflict_demo

        console.print("[bold yellow]==> Running Conflicting Agents Scenario...[/bold yellow]\n")
        run_conflict_demo()
    else:
        console.print(
            f"[bold red]Unknown scenario:[/bold red] '{scenario}'. Choose 'hello' or 'conflict'."
        )
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
