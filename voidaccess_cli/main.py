"""
cli/main.py — typer entry point exposed as the `voidaccess` script.

Defined as the [project.scripts] target in pyproject.toml:
    voidaccess = "voidaccess_cli.main:app"
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Force UTF-8 on Windows consoles so rich glyphs render reliably
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

import typer
from rich.align import Align
from rich.console import Console
from rich.table import Table

from voidaccess_cli import __version__
from voidaccess_cli import config as cli_config
from voidaccess_cli.commands import actors, configure, enrich, export, investigate, show

console = Console()
BANNER = """\
[color(183)]     ░░░░░[color(141)]█[color(183)]░░░░░[/]
[color(183)]  ░░[color(141)]█████████████[color(183)]░░[/]
[color(183)] ░[color(141)]█████████████████[color(183)]░[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(141)]██████[/]  [bright_white]void[/]  [color(141)]███████[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(183)]░[color(141)]███████████████████[color(183)]░[/]
[color(183)] ░[color(141)]█████████████████[color(183)]░[/]
[color(183)]  ░░[color(141)]█████████████[color(183)]░░[/]
[color(183)]     ░░░░░[color(141)]█[color(183)]░░░░░[/]
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
app.command("export", help="Export an investigation to STIX/MISP/Sigma/package/CSV/MD/JSON.")(export.run)
app.command("enrich", help="Re-enrich a stored investigation against current feeds.")(enrich.run)
app.command("actors", help="List persistent actor profiles.")(actors.run)
app.command("actor", help="Show or annotate a single actor profile.")(actors.run)


@app.command("package")
def package(
    target: str = typer.Argument(..., help="Investigation id or .json file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output ZIP path"),
    tlp: str = typer.Option(
        "white",
        "--tlp",
        help="TLP marker: white|green|amber|red",
    ),
    redact_credentials: bool = typer.Option(
        True,
        "--redact-credentials/--no-redact-credentials",
        help="Partially redact credential values",
    ),
    include_raw: bool = typer.Option(
        False,
        "--include-raw/--no-include-raw",
        help="Include raw scraped page content",
    ),
) -> None:
    """Shortcut: build an IOC package ZIP for an investigation.

    Equivalent to `voidaccess export <target> --format package`.
    """
    export.run(
        target=target,
        fmt="package",
        output=output,
        tlp=tlp,
        redact_credentials=redact_credentials,
        include_raw=include_raw,
    )


@app.command("timeline")
def timeline(
    handle: str = typer.Argument(..., help="Actor handle or UUID"),
    limit: int = typer.Option(
        50, "--limit", "-n",
        help="Maximum number of timeline events to show",
    ),
    event_types: Optional[str] = typer.Option(
        None, "--event-types",
        help=(
            "Comma-separated event types to include "
            "(FIRST_SEEN, INVESTIGATION, NEW_ALIAS, "
            "NEW_INFRASTRUCTURE, NOTE_ADDED)"
        ),
    ),
    as_json: bool = typer.Option(False, "--json", help="JSON output"),
) -> None:
    """Shortcut: show the chronological activity timeline for an actor.

    Equivalent to ``voidaccess actor <handle> --timeline
    [--event-types …] [--limit N] [--json]``.
    """
    actors.run(
        handle=handle,
        timeline=True,
        limit=limit,
        event_types=event_types,
        as_json=as_json,
    )


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
def status(
    engines: bool = typer.Option(False, "--engines", help="Show search engine performance stats"),
    cache: bool = typer.Option(False, "--cache", help="Show enrichment cache stats"),
    seeds: bool = typer.Option(False, "--seeds", help="Show seed pool breakdown (permanent + discovered)"),
) -> None:
    """Show current config, Tor status, and detected API keys."""
    from voidaccess_cli.tor_detect import detect_tor
    cli_config.apply_env()
    if engines:
        _show_engine_status()
        return

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

    # Inline enrichment-cache summary (always shown when --cache is set,
    # otherwise the row is omitted). Never raises — cache is best-effort.
    if cache:
        cache_stats = _get_enrichment_cache_stats_sync()
        backend = cache_stats.get("backend", "n/a")
        hits = cache_stats.get("hits", 0)
        misses = cache_stats.get("misses", 0)
        hit_rate = cache_stats.get("hit_rate_pct", 0.0)
        size = cache_stats.get("size", 0)
        table.add_row(
            "Enrichment cache",
            f"backend=[cyan]{backend}[/cyan] "
            f"hits={hits} misses={misses} "
            f"rate=[green]{hit_rate}%[/green] "
            f"entries={size}",
        )

    console.print(table)

    if cache:
        _show_cache_detail_table()

    if seeds:
        _show_seed_pool_table()


def _show_seed_pool_table() -> None:
    """Render the seed-pool breakdown table used by `voidaccess status --seeds`."""
    try:
        from sources.seed_manager import get_seed_manager

        sm = get_seed_manager()
        breakdown = sm.count_by_type()
        last_validated = sm.summary().get("last_validated")

        seed_table = Table(title="Seed pool", show_lines=False)
        seed_table.add_column("Bucket", style="bold")
        seed_table.add_column("Count", justify="right")
        seed_table.add_row(
            "Permanent",
            f"[cyan]{breakdown.get('permanent', 0)}[/cyan]",
        )
        seed_table.add_row(
            "Discovered (total)",
            f"[cyan]{breakdown.get('discovered_total', 0)}[/cyan]",
        )
        seed_table.add_row(
            "  pending validation",
            f"[yellow]{breakdown.get('discovered_pending', 0)}[/yellow]",
        )
        seed_table.add_row(
            "  validated",
            f"[green]{breakdown.get('discovered_validated', 0)}[/green]",
        )
        seed_table.add_row(
            "Last validation",
            str(last_validated) if last_validated else "never",
        )
        console.print(seed_table)
    except Exception as exc:
        console.print(f"[red]Seed pool unavailable: {exc}[/red]")


def _get_enrichment_cache_stats_sync() -> dict:
    """Synchronously fetch enrichment cache stats (cache errors → empty dict)."""
    try:
        from utils.async_utils import run_async
        from utils.enrichment_cache import get_enrichment_cache

        async def _fetch() -> dict:
            cache = await get_enrichment_cache()
            return await cache.stats()

        return run_async(_fetch()) or {}
    except Exception as exc:
        logger_msg = exc  # noqa: F841 — logged in caller if needed
        return {"backend": "unavailable", "hits": 0, "misses": 0,
                "hit_rate_pct": 0.0, "size": 0, "error": str(exc)[:120]}


def _show_cache_detail_table() -> None:
    """Print a per-source TTL table under the main status table."""
    from utils.enrichment_cache import DEFAULT_TTL

    ttl_table = Table(title="Enrichment cache TTL defaults", show_lines=False)
    ttl_table.add_column("Source", style="bold")
    ttl_table.add_column("TTL (seconds)", justify="right")
    ttl_table.add_column("TTL (human)")

    def _human(seconds: int) -> str:
        if seconds < 3600:
            return f"{seconds // 60}m"
        if seconds < 86400:
            return f"{seconds // 3600}h"
        return f"{seconds // 86400}d"

    for source, ttl in sorted(DEFAULT_TTL.items()):
        ttl_table.add_row(source, str(ttl), _human(ttl))
    console.print(ttl_table)


def _show_engine_status() -> None:
    import asyncio
    from voidaccess_cli.adapters import sqlite as sqlite_adapter

    sqlite_adapter.init_db()
    rows = asyncio.run(sqlite_adapter.get_all_engine_stats())
    if not rows:
        console.print("[grey50]No search engine stats recorded yet.[/grey50]")
        return

    table = Table(title="Search engine status", show_lines=False)
    table.add_column("Engine Name", style="bold")
    table.add_column("Score", justify="right")
    table.add_column("Success Rate", justify="right")
    table.add_column("Avg Time", justify="right")
    table.add_column("Circuit")
    table.add_column("Last Success")

    for row in sorted(rows, key=lambda r: r.get("score", 0), reverse=True):
        attempts = int(row.get("total_attempts") or 0)
        successes = int(row.get("total_successes") or 0)
        success_rate = int(round((successes / attempts) * 100)) if attempts else 0
        avg_ms = float(row.get("avg_response_time_ms") or 0)
        avg_time = f"{avg_ms / 1000:.1f}s" if avg_ms else "-"
        circuit = "[red]OPEN[/red]" if row.get("is_circuit_open") else "[green]CLOSED[/green]"
        last_success = _relative_time(row.get("last_success_at"), datetime.now(timezone.utc))
        table.add_row(
            str(row.get("engine_name") or ""),
            f"{float(row.get('score') or 0):.2f}",
            f"{success_rate}%",
            avg_time,
            circuit,
            last_success,
        )

    console.print(table)


def _relative_time(value, now) -> str:
    if not value:
        return "never"
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value)
        except Exception:
            return "unknown"
    else:
        dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = now - dt
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


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
    import shutil
    if os.environ.get("TERM") == "dumb":
        return
    if not sys.stdout.isatty() and "PS1" not in os.environ and os.name != "nt":
        return
    console.print()
    raw_line = "     oooooXooooo     "  # widest line, 21 chars
    pad = max(0, (console.width - len(raw_line)) // 2)
    for line in BANNER.split("\n"):
        console.print(" " * pad + line)
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
    if not no_banner and ctx.invoked_subcommand:
        show_banner(console)


if __name__ == "__main__":
    app()
