"""
cli/commands/configure.py — first-run wizard and config sub-commands.

    voidaccess configure         — full wizard
    voidaccess configure llm     — just the LLM provider/key
    voidaccess configure keys    — just enrichment API keys
"""

from __future__ import annotations

from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Prompt, Confirm
from rich.table import Table

from voidaccess_cli import config as cli_config

app = typer.Typer(help="Configure the voidaccess CLI.", no_args_is_help=False, invoke_without_command=True)
console = Console()


PROVIDERS = [
    ("openrouter", "OpenRouter (free models available)"),
    ("groq",       "Groq (completely free)"),
    ("google",     "Google Gemini (free tier)"),
    ("openai",     "OpenAI (paid)"),
    ("anthropic",  "Anthropic (paid)"),
    ("ollama",     "Ollama (local, free)"),
]

DEFAULT_MODELS = {
    "openrouter": "openrouter/deepseek/deepseek-chat",
    "groq":       "groq/llama-3.3-70b-versatile",
    "google":     "gemini-1.5-flash",
    "openai":     "gpt-4o-mini",
    "anthropic":  "claude-haiku-4-5-20251001",
    "ollama":     "ollama/llama3.2",
}


def _print_provider_table() -> None:
    table = Table(title="LLM provider")
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Provider", style="bold")
    table.add_column("Notes")
    for idx, (key, desc) in enumerate(PROVIDERS, start=1):
        suffix = " ← default" if key == "openrouter" else ""
        table.add_row(str(idx), key, desc + suffix)
    console.print(table)


def _test_llm_key(provider: str, api_key: str, model: str) -> bool:
    """Light credential validation — instantiate the LangChain class only."""
    if provider == "ollama":
        return True
    try:
        from voidaccess.llm import get_llm
        get_llm(model, api_keys={cli_config.PROVIDER_ENV.get(provider, ""): api_key})
        return True
    except Exception as exc:
        console.print(f"[yellow]Could not validate key:[/yellow] {exc}")
        return False


def _prompt_llm(cfg: dict) -> None:
    _print_provider_table()
    while True:
        choice = Prompt.ask(
            "Pick provider [1-6]",
            default="1",
            choices=[str(i) for i in range(1, len(PROVIDERS) + 1)],
            show_choices=False,
        )
        provider, _ = PROVIDERS[int(choice) - 1]
        break

    model = Prompt.ask(
        "Model identifier",
        default=DEFAULT_MODELS.get(provider, ""),
    )

    api_key = ""
    if provider != "ollama":
        api_key = Prompt.ask(
            f"API key for {provider}",
            default=cfg["llm"].get("api_key", "") if cfg["llm"].get("provider") == provider else "",
            password=True,
        )

    cfg["llm"]["provider"] = provider
    cfg["llm"]["model"] = model
    cfg["llm"]["api_key"] = api_key

    if api_key and provider != "ollama":
        console.print("Testing key…", style="grey50")
        if _test_llm_key(provider, api_key, model):
            console.print("[green]Key looks valid.[/green]")
        else:
            console.print("[yellow]Saved anyway — verify later with `voidaccess status`.[/yellow]")


def _prompt_enrichment(cfg: dict) -> None:
    console.print("\n[bold]Enrichment API keys[/bold] (press Enter to skip any)")
    for key_name in cli_config.ENRICHMENT_KEYS:
        existing = cfg["enrichment_keys"].get(key_name, "")
        display_default = "(saved)" if existing else "(skip)"
        val = Prompt.ask(f"  {key_name}", default=existing or "", show_default=False)
        cfg["enrichment_keys"][key_name] = val.strip()


def _prompt_output_dir(cfg: dict) -> None:
    current = cfg.get("output_dir") or str(cli_config.DEFAULT_OUTPUT_DIR)
    new_dir = Prompt.ask("Output directory", default=current)
    cfg["output_dir"] = new_dir


def _ensure_spacy_model() -> None:
    console.print("\n  → Downloading spaCy NER model...")
    try:
        import subprocess
        import sys

        result = subprocess.run(
            [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            console.print("  ✓ spaCy model ready")
        else:
            console.print(
                "  ⚠ spaCy download failed — run manually: "
                "python -m spacy download en_core_web_sm"
            )
    except Exception as e:
        console.print(f"  ⚠ spaCy: {e}")


@app.callback()
def configure_default(ctx: typer.Context) -> None:
    """Run the full wizard when no sub-command is given."""
    if ctx.invoked_subcommand is not None:
        return
    cfg = cli_config.load_config()
    console.print("[bold magenta]voidaccess — initial setup[/bold magenta]\n")
    _prompt_llm(cfg)
    if Confirm.ask("\nAdd enrichment API keys now?", default=False):
        _prompt_enrichment(cfg)
    _prompt_output_dir(cfg)
    cli_config.save_config(cfg)
    console.print(f"\n[green]Saved to[/green] {cli_config.CONFIG_PATH}")
    _ensure_spacy_model()


@app.command("llm")
def configure_llm() -> None:
    """Configure just the LLM provider, model, and API key."""
    cfg = cli_config.load_config()
    _prompt_llm(cfg)
    cli_config.save_config(cfg)
    console.print(f"[green]Saved to[/green] {cli_config.CONFIG_PATH}")


@app.command("keys")
def configure_keys() -> None:
    """Configure enrichment API keys."""
    cfg = cli_config.load_config()
    _prompt_enrichment(cfg)
    cli_config.save_config(cfg)
    console.print(f"[green]Saved to[/green] {cli_config.CONFIG_PATH}")


@app.command("tor")
def configure_tor(
    host: str = typer.Option("127.0.0.1", help="Tor SOCKS5 host"),
    port: int = typer.Option(9050, help="Tor SOCKS5 port"),
) -> None:
    """Override Tor proxy host/port."""
    cfg = cli_config.load_config()
    cfg["tor"]["host"] = host
    cfg["tor"]["port"] = port
    cli_config.save_config(cfg)
    console.print(f"Tor set to {host}:{port}")
