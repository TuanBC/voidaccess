"""
cli/commands/configure.py — first-run wizard and config sub-commands.

    voidaccess configure         — full wizard
    voidaccess configure llm     — just the LLM provider/key
    voidaccess configure keys    — just enrichment API keys
    voidaccess configure tor     — override Tor proxy host/port
    voidaccess configure proxy   — ScrapingAnt key + enable/disable toggle
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


# Keys in ENRICHMENT_KEYS that get their own dedicated wizard step
# (with custom explanation) rather than the generic one-line prompt.
# Adding a key here means the generic iteration in _prompt_enrichment
# will skip it.  Phase 1.6: ScrapingAnt — the API key (the only real
# credential per https://docs.scrapingant.com/proxy-mode) gets a
# dedicated step with honest explanation; the proxy type also lives
# here so the entire proxy config lives in one uninterrupted block.
KEYS_WITH_DEDICATED_STEP = {
    "SCRAPINGANT_API_KEY",
    "SCRAPINGANT_PROXY_TYPE",
}


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
    except ImportError as exc:
        missing = str(exc).split("'")[-2] if "'" in str(exc) else str(exc)
        console.print(
            f"[yellow]Skipped validation:[/yellow] missing dependency [bold]{missing}[/bold]. "
            f"Install with: [bold]pip install {missing.replace('_', '-')}[/bold]"
        )
        return False
    try:
        get_llm(model, api_keys={cli_config.PROVIDER_ENV.get(provider, ""): api_key})
        return True
    except ImportError as exc:
        missing = str(exc).split("'")[-2] if "'" in str(exc) else str(exc)
        console.print(
            f"[yellow]Skipped validation:[/yellow] missing dependency [bold]{missing}[/bold]. "
            f"Install with: [bold]pip install {missing.replace('_', '-')}[/bold]"
        )
        return False
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
        # Phase 1.6 — keys with their own dedicated wizard step
        # (custom explanation + associated toggle) are handled by their
        # own _prompt_* function, not the generic one-liner.
        if key_name in KEYS_WITH_DEDICATED_STEP:
            continue
        existing = cfg["enrichment_keys"].get(key_name, "")
        display_default = "(saved)" if existing else "(skip)"
        val = Prompt.ask(f"  {key_name}", default=existing or "", show_default=False)
        cfg["enrichment_keys"][key_name] = val.strip()


def _prompt_scrapingant(cfg: dict) -> None:
    """Phase 1.6 — dedicated wizard step for the optional clearnet proxy.

    Honest, specific wording: this is opt-in, it affects paste sites and
    RSS feeds ONLY, and it never touches Tor/.onion traffic.

    Per https://docs.scrapingant.com/proxy-mode §Integration details,
    the ONLY real credential is SCRAPINGANT_API_KEY. The username
    string for Proxy Mode is built at connection time as
    "scrapingant&browser=false&proxy_type=residential|datacenter" —
    "scrapingant" is a literal constant, not a per-customer value.
    SCRAPINGANT_PROXY_TYPE selects residential vs datacenter as a
    username parameter, NOT as a different hostname.

    The two transport toggles (API / Proxy) are mutually exclusive
    alternates per the docs (Proxy Mode is "a light front-end for the
    scraping API"); we ask about each separately but they cannot be
    combined.
    """
    console.print("\n[bold]Clearnet proxy (ScrapingAnt)[/bold] — optional")
    console.print(
        "  Routes [cyan]clearnet scraping only[/cyan] — paste sites (Pastebin, "
        "dpaste, Rentry) and RSS feeds (Krebs, BleepingComputer, Talos, etc.) "
        "through ScrapingAnt's Web Scraping API or Proxy Mode to improve reliability."
    )
    console.print(
        "  [yellow]Never touches Tor traffic.[/yellow] Dark web and .onion fetches "
        "are unaffected regardless of this setting."
    )
    console.print(
        "  Sign up at [link=https://scrapingant.com/?ref=mzliyzh]"
        "[cyan]https://scrapingant.com/?ref=mzliyzh[/cyan][/link]"
        " (referral bonus applied on first paid plan — also unlocks"
        " a free tier for low-volume use)."
    )
    console.print("  Press Enter to skip any field.\n")

    # --- SCRAPINGANT_API_KEY (the only credential for both transports) ---
    existing_key = cfg["enrichment_keys"].get("SCRAPINGANT_API_KEY", "")
    prompt_default = existing_key or ""
    new_key = Prompt.ask(
        "  SCRAPINGANT_API_KEY",
        default=prompt_default,
        show_default=False,
        password=True,
    )
    cfg["enrichment_keys"]["SCRAPINGANT_API_KEY"] = new_key.strip()

    # --- SCRAPINGANT_PROXY_TYPE (residential default; datacenter for higher bandwidth) ---
    # Per docs, this is passed as `proxy_type=` in the Proxy Mode
    # username string.  Only meaningful when the Proxy Mode transport
    # is selected; ignored otherwise.
    existing_type = (
        cfg["enrichment_keys"].get("SCRAPINGANT_PROXY_TYPE", "") or "residential"
    ).strip().lower()
    if existing_type not in ("residential", "datacenter"):
        existing_type = "residential"
    console.print(
        "  [dim]Proxy pool type:[/dim] [cyan]residential[/cyan] (default — "
        "harder to detect, slightly higher latency) or [cyan]datacenter[/cyan] "
        "(faster, cheaper, easier to fingerprint).  Press Enter for residential."
    )
    type_choices = ["residential", "datacenter"]
    new_type = Prompt.ask(
        "  SCRAPINGANT_PROXY_TYPE",
        choices=type_choices,
        default=existing_type,
    )
    cfg["enrichment_keys"]["SCRAPINGANT_PROXY_TYPE"] = new_type.strip()

    # Transport selection — mutually exclusive alternates per docs.
    # We ask about each separately but they are NOT combinable: enabling
    # both means the chokepoint picks proxy (logged at runtime with a
    # one-shot info message).
    if new_key.strip():
        current_api = bool(cfg.get("features", {}).get("use_proxies", False))
        if Confirm.ask(
            "  Enable REST API transport (ScrapingAnt Web Scraping API) for clearnet scrapes?",
            default=current_api,
        ):
            cfg.setdefault("features", {})["use_proxies"] = True
        else:
            cfg.setdefault("features", {})["use_proxies"] = False

        current_proxy = bool(cfg.get("features", {}).get("use_proxy", False))
        if Confirm.ask(
            f"  Enable Proxy Mode transport (HTTP CONNECT through proxy.scrapingant.com:8080, "
            f"{new_type} pool) for clearnet scrapes?",
            default=current_proxy,
        ):
            cfg.setdefault("features", {})["use_proxy"] = True
        else:
            cfg.setdefault("features", {})["use_proxy"] = False


def _prompt_output_dir(cfg: dict) -> None:
    current = cfg.get("output_dir") or str(cli_config.DEFAULT_OUTPUT_DIR)
    new_dir = Prompt.ask("Output directory", default=current)
    cfg["output_dir"] = new_dir


def _ensure_spacy_model() -> None:
    cli_config.ensure_spacy_model()


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
        # Phase 1.6 — dedicated step for keys that have associated
        # on/off behavior (currently just ScrapingAnt).  This sits
        # inside the "Add enrichment API keys now?" branch because
        # ScrapingAnt is functionally an optional key, but it gets
        # its own honest explanation rather than the generic one-liner.
        _prompt_scrapingant(cfg)
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
    # Phase 1.6 — ScrapingAnt also has its own dedicated prompt here
    # so users running `voidaccess configure keys` get the same honest
    # explanation they would in the full wizard.
    _prompt_scrapingant(cfg)
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


@app.command("proxy")
def configure_proxy(
    enable: Optional[bool] = typer.Option(
        None,
        "--enable/--disable",
        help="Enable or disable the REST API transport (legacy v1.5.0 toggle).",
    ),
    enable_proxy: Optional[bool] = typer.Option(
        None,
        "--enable-proxy/--disable-proxy",
        help="Enable or disable the Proxy Mode transport (HTTP CONNECT through proxy.scrapingant.com:8080).",
    ),
    show: bool = typer.Option(
        False,
        "--show",
        help="Print current proxy config (key masked, pool type, both transport states) and exit.",
    ),
) -> None:
    """Configure the optional clearnet proxy (ScrapingAnt).

    With no flags, runs the interactive prompt.  With --enable / --disable,
    sets the REST API transport toggle non-interactively (legacy v1.5.0
    flag).  With --enable-proxy / --disable-proxy, sets the Proxy Mode
    transport toggle (new in v1.6.0 — requires SCRAPINGANT_API_KEY to
    actually activate).

    The two transports are MUTUALLY EXCLUSIVE alternates per
    https://docs.scrapingant.com/proxy-mode §Introduction ("Proxy Mode
    is a light front-end for the scraping API"). Setting one does not
    enable the other; if both are set, the chokepoint picks Proxy Mode
    and emits a one-shot info log.

    Clearnet scraping only — Tor and .onion traffic are never affected.
    """
    cfg = cli_config.load_config()

    # --show: display current state with the key masked, and exit.
    if show and enable is None and enable_proxy is None:
        key = cfg.get("enrichment_keys", {}).get("SCRAPINGANT_API_KEY", "")
        proxy_type = (
            cfg.get("enrichment_keys", {}).get("SCRAPINGANT_PROXY_TYPE", "") or "—"
        )
        api_transport = bool(cfg.get("features", {}).get("use_proxies", False))
        proxy_transport = bool(cfg.get("features", {}).get("use_proxy", False))

        masked_key = (
            f"{key[:4]}…{key[-4:]}" if len(key) > 8 else ("set" if key else "—")
        )

        console.print("  [bold]ScrapingAnt proxy[/bold]")
        console.print(f"  Key             : {masked_key}")
        console.print(f"  Pool type       : {proxy_type}")
        api_label = "[green]enabled[/green]" if api_transport else "[red]disabled[/red]"
        proxy_label = "[green]enabled[/green]" if proxy_transport else "[red]disabled[/red]"
        console.print(f"  API transport   : {api_label}")
        console.print(f"  Proxy transport : {proxy_label}")
        console.print("  Scope           : paste + RSS only, never Tor")
        if (api_transport or proxy_transport) and not key:
            console.print(
                "  [yellow]Note:[/yellow] a transport is enabled but no SCRAPINGANT_API_KEY "
                "is set — both transports will stay inactive until a key is provided."
            )
        if api_transport and proxy_transport:
            console.print(
                "  [yellow]Note:[/yellow] both transports are enabled. They are mutually "
                "exclusive alternates; the chokepoint picks Proxy Mode at runtime."
            )
        return

    if enable is not None:
        cfg.setdefault("features", {})["use_proxies"] = bool(enable)
        cli_config.save_config(cfg)
        state = "enabled" if enable else "disabled"
        console.print(f"ScrapingAnt REST API transport [green]{state}[/green]")
        if enable and not cfg.get("enrichment_keys", {}).get("SCRAPINGANT_API_KEY"):
            console.print(
                "[yellow]Note:[/yellow] no SCRAPINGANT_API_KEY configured yet — "
                "set one with `voidaccess configure proxy` (interactive) or "
                "`voidaccess configure keys`."
            )
        return

    if enable_proxy is not None:
        cfg.setdefault("features", {})["use_proxy"] = bool(enable_proxy)
        cli_config.save_config(cfg)
        state = "enabled" if enable_proxy else "disabled"
        console.print(f"ScrapingAnt Proxy Mode transport [green]{state}[/green]")
        if enable_proxy and not cfg.get("enrichment_keys", {}).get("SCRAPINGANT_API_KEY"):
            console.print(
                "[yellow]Note:[/yellow] no SCRAPINGANT_API_KEY configured yet — "
                "set one with `voidaccess configure proxy` (interactive) or "
                "`voidaccess configure keys`."
            )
        return

    # No flags — run the interactive prompt
    _prompt_scrapingant(cfg)
    cli_config.save_config(cfg)
    console.print(f"[green]Saved to[/green] {cli_config.CONFIG_PATH}")
