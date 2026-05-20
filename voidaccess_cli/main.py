"""
cli/main.py — typer entry point exposed as the `voidaccess` script.

Defined as the [project.scripts] target in pyproject.toml:
    voidaccess = "voidaccess_cli.main:app"
"""

from __future__ import annotations

import json
import os
import sys

# Force UTF-8 on Windows consoles so rich glyphs render reliably
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

import typer
from rich.console import Console
from rich.table import Table

from voidaccess_cli import __version__
from voidaccess_cli import config as cli_config
from voidaccess_cli.commands import configure, enrich, export, investigate, show

console = Console()
BANNER = """\
[color(183)]     ░░[color(141)]████████[color(183)]░░[/]
[color(183)]   ░░[color(141)]████████████[color(183)]░░[/]
[color(183)]  ░░[color(141)]██████████████[color(183)]░░[/]
[color(183)]  ░░[color(141)]████[/]  [bright_white]void[/]  [color(141)]████[color(183)]░░[/]
[color(183)]  ░░[color(141)]██████████████[color(183)]░░[/]
[color(183)]   ░░[color(141)]████████████[color(183)]░░[/]
[color(183)]     ░░[color(141)]████████[color(183)]░░[/]
[dim white]   dark web osint intelligence[/dim white]"""

app = typer.Typer(
    name="voidaccess",
    help="Dark web OSINT — query to intelligence report.",
    no_args_is_help=True,
    add_completion=False,
)

# Sub-commands
app.add_typer(configure.app, name="configure", help="Configure the CLI (LLM, keys, Tor).")
app.command("investigate", help="Run a new investigation.")(investigate.run)
app.command("show", help="Open the entity browser TUI.")(show.run)
app.command("export", help="Export an investigation to STIX/MISP/Sigma/CSV/MD/JSON.")(export.run)
app.command("enrich", help="Re-enrich a stored investigation against current feeds.")(enrich.run)


def _ensure_first_run() -> None:
    """Auto-launch wizard on first invocation when no config exists."""
    if cli_config.CONFIG_PATH.exists():
        return
    console.print(
        "[bold magenta]Welcome to voidaccess.[/bold magenta] "
        "Let's get you configured first."
    )
    # Invoke wizard via Typer
    try:
        configure.configure_default(ctx=typer.Context(configure.app))
    except Exception:
        pass


@app.command("status")
def status() -> None:
    """Show current config, Tor status, and detected API keys."""
    from voidaccess_cli.tor_detect import detect_tor
    cli_config.apply_env()
    cfg = cli_config.load_config()

    table = Table(title="voidaccess status", show_lines=False)
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    table.add_row("Version", __version__)
    table.add_row("Config path", str(cli_config.CONFIG_PATH))
    table.add_row("DB path", str(cli_config.DB_PATH))
    table.add_row("Output dir", str(cli_config.get_output_dir(cfg)))

    llm = cfg.get("llm", {})
    table.add_row("LLM provider", llm.get("provider") or "—")
    table.add_row("LLM model", llm.get("model") or "—")
    table.add_row("LLM key", "[green]set[/green]" if llm.get("api_key") else "[red]missing[/red]")

    table.add_row("Tor host", cfg.get("tor", {}).get("host", "—"))
    table.add_row("Tor port", str(cfg.get("tor", {}).get("port", "—")))

    tor_status = detect_tor()
    if tor_status.proxy_url:
        table.add_row("Tor reachable", f"[green]{tor_status.source}[/green] at {tor_status.proxy_url}")
    else:
        table.add_row("Tor reachable", "[red]no proxy responded[/red]")

    try:
        import spacy

        spacy.load("en_core_web_sm")
        spacy_status = "ready"
    except Exception:
        spacy_status = "not installed"
    table.add_row("spaCy NER", spacy_status)

    keys = cfg.get("enrichment_keys", {})
    set_count = sum(1 for v in keys.values() if v)
    table.add_row("Enrichment keys", f"{set_count}/{len(keys)} set")

    console.print(table)


@app.command("list")
def list_investigations(
    limit: int = typer.Option(20, "--limit", "-n", help="Number of rows"),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """List saved investigations."""
    cli_config.apply_env()
    from voidaccess_cli.adapters import sqlite as sqlite_adapter
    sqlite_adapter.init_db()
    rows = sqlite_adapter.list_investigations(limit=limit)
    if as_json:
        console.print_json(json.dumps(rows, default=str))
        return
    if not rows:
        console.print("[grey50]No saved investigations.[/grey50]")
        return
    table = Table(title="Saved investigations")
    table.add_column("Id", style="cyan")
    table.add_column("Query")
    table.add_column("Status")
    table.add_column("Entities", justify="right")
    table.add_column("Created")
    for r in rows:
        table.add_row(
            r["id"][:8],
            (r["query"] or "")[:60],
            r["status"] or "",
            str(r["entity_count"]),
            (r["created_at"] or "")[:19],
        )
    console.print(table)


@app.command("version")
def version() -> None:
    """Print the installed version."""
    console.print(f"voidaccess {__version__}")


def show_banner(console: Console) -> None:
    if not sys.stdout.isatty():
        return
    console.print()
    console.print(BANNER, justify="center")
    console.print()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    no_banner: bool = typer.Option(
        False, "--no-banner",
        help="Skip banner"
    ),
) -> None:
    """Set env vars and render banner before command execution."""
    cli_config.apply_env()
    if not no_banner and not ctx.invoked_subcommand:
        show_banner(console)


if __name__ == "__main__":
    app()
