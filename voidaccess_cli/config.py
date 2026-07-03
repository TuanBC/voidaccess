"""
cli/config.py — Persistent config for the voidaccess CLI.

Stores LLM provider/model, API keys, Tor proxy settings, and output dir
in ~/.voidaccess/config.json. Exposes helpers and an apply_env() function
that pushes the saved config into os.environ before any voidaccess module
is imported (the existing modules read API keys from env at import time).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Optional

CLI_HOME = Path(os.path.expanduser("~/.voidaccess"))
CONFIG_PATH = CLI_HOME / "config.json"
DB_PATH = CLI_HOME / "investigations.db"
DEFAULT_OUTPUT_DIR = CLI_HOME / "results"

ENRICHMENT_KEYS = [
    "OTX_API_KEY",
    "VT_API_KEY",
    "ABUSEIPDB_API_KEY",
    "GREYNOISE_API_KEY",
    "URLSCAN_API_KEY",
    "SECURITYTRAILS_API_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "HYBRID_ANALYSIS_API_KEY",
    "HIBP_API_KEY",
    "EMAILREP_API_KEY",
    "SHODAN_API_KEY",
    "BLOCKCYPHER_TOKEN",
    "ETHERSCAN_API_KEY",
    "DEEPL_API_KEY",
    "DARKSEARCH_API_KEY",
    # Phase 1.6 — optional clearnet proxy. The ONLY credential needed
    # for either the REST API transport or proxy transport per
    # https://docs.scrapingant.com/proxy-mode. Never touches Tor or
    # .onion traffic. Stored in the same enrichment_keys section as
    # every other optional key.
    "SCRAPINGANT_API_KEY",
    "SCRAPINGANT_PROXY_USERNAME",
    "SCRAPINGANT_PROXY_PASSWORD",
    # Phase 1.6 — proxy pool type.  Accepts "residential" (default) or
    # "datacenter".  Empty when the feature is unused; the chokepoint
    # defaults to "residential" if this is unset.  Per docs, this is
    # passed as a `proxy_type=` parameter in the proxy transport username
    # string, NOT as a separate hostname.
    "SCRAPINGANT_PROXY_TYPE",
]

PROVIDER_ENV = {
    "openrouter": "OPENROUTER_API_KEY",
    "groq":       "GROQ_API_KEY",
    "google":     "GOOGLE_API_KEY",
    "openai":     "OPENAI_API_KEY",
    "anthropic":  "ANTHROPIC_API_KEY",
    "ollama":     None,
}

DEFAULT_CONFIG: dict[str, Any] = {
    "llm": {
        "provider": "openrouter",
        "model": "openrouter/deepseek/deepseek-chat",
        "api_key": "",
    },
    "enrichment_keys": {k: "" for k in ENRICHMENT_KEYS},
    # Phase 1.6 — boolean feature toggles persisted across CLI invocations.
    # Currently used for the optional clearnet proxy (ScrapingAnt).  Read by
    # apply_env() and pushed to os.environ so the runtime chokepoint
    # (sources/proxy_client.py) sees the same value the user set in
    # `voidaccess configure`.
    "features": {
        # Phase 1.6 — boolean feature toggles persisted across CLI
        # invocations.  Currently used for the optional clearnet proxy
        # (ScrapingAnt).  Read by apply_env() and pushed to os.environ
        # so the runtime chokepoint (sources/proxy_client.py) sees the
        # same value the user set in `voidaccess configure`.
        #
        # use_proxies           → VOIDACCESS_USE_PROXIES=true
        #                         Selects the REST API transport.
        #                         (legacy v1.5.0 alias; Phase 1 verified
        #                         correct, must not be touched.)
        #
        # use_proxy             → VOIDACCESS_USE_PROXY=true
        #                         Selects the proxy transport.
        #                         Per docs (https://docs.scrapingant.com/
        #                         proxy-mode §Introduction) proxy transport is
        #                         "a light front-end for the scraping API
        #                         and has all the same functionality and
        #                         performance as sending requests to the
        #                         API endpoint" — so the two transports
        #                         are mutually exclusive alternates,
        #                         NEVER combinable.  When both flags are
        #                         set, the chokepoint picks proxy and
        #                         emits a one-shot info log.
        "use_proxies": False,
        "use_proxy": False,
    },
    "tor": {
        "host": "127.0.0.1",
        "port": 9050,
    },
    "output_dir": str(DEFAULT_OUTPUT_DIR),
}


def _ensure_home() -> None:
    CLI_HOME.mkdir(parents=True, exist_ok=True)


def load_config() -> dict[str, Any]:
    """Return saved config or DEFAULT_CONFIG if none exists."""
    _ensure_home()
    if not CONFIG_PATH.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        cfg = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return json.loads(json.dumps(DEFAULT_CONFIG))
    # Merge with defaults so missing keys don't crash
    merged = json.loads(json.dumps(DEFAULT_CONFIG))
    merged["llm"].update(cfg.get("llm", {}))
    merged["tor"].update(cfg.get("tor", {}))
    merged["enrichment_keys"].update(cfg.get("enrichment_keys", {}))
    merged["features"].update(cfg.get("features", {}))
    if cfg.get("output_dir"):
        merged["output_dir"] = cfg["output_dir"]
    return merged


def save_config(config: dict[str, Any]) -> None:
    _ensure_home()
    CONFIG_PATH.write_text(
        json.dumps(config, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def is_configured() -> bool:
    if not CONFIG_PATH.exists():
        return False
    cfg = load_config()
    provider = cfg.get("llm", {}).get("provider", "")
    api_key = cfg.get("llm", {}).get("api_key", "")
    if provider == "ollama":
        return True
    return bool(provider and api_key)


def get_llm_key(config: Optional[dict[str, Any]] = None) -> str:
    cfg = config or load_config()
    return cfg.get("llm", {}).get("api_key", "") or ""


def get_llm_model(config: Optional[dict[str, Any]] = None) -> str:
    cfg = config or load_config()
    return cfg.get("llm", {}).get("model", "") or ""


def get_llm_provider(config: Optional[dict[str, Any]] = None) -> str:
    cfg = config or load_config()
    return cfg.get("llm", {}).get("provider", "") or ""


def get_tor_proxy(config: Optional[dict[str, Any]] = None) -> str:
    cfg = config or load_config()
    host = cfg.get("tor", {}).get("host", "127.0.0.1")
    port = cfg.get("tor", {}).get("port", 9050)
    return f"socks5://{host}:{port}"


def get_output_dir(config: Optional[dict[str, Any]] = None) -> Path:
    cfg = config or load_config()
    p = Path(os.path.expanduser(cfg.get("output_dir") or str(DEFAULT_OUTPUT_DIR)))
    p.mkdir(parents=True, exist_ok=True)
    return p


def db_url() -> str:
    """SQLite URL used by db.session via DATABASE_URL env var."""
    _ensure_home()
    return f"sqlite:///{DB_PATH.as_posix()}"


def ensure_spacy_model(model_name: str = "en_core_web_sm") -> bool:
    """
    Ensure spaCy NER model is installed. Returns True if model is loadable
    after this call. Handles PEP 668 (externally-managed-environment) on
    Debian/Ubuntu/Kali by setting PIP_BREAK_SYSTEM_PACKAGES=1, and uses
    PIP_USER=1 outside virtualenvs.

    Prints progress via rich. Safe to call repeatedly.
    """
    import sys
    import subprocess

    try:
        import spacy
        spacy.load(model_name)
        return True
    except Exception:
        pass

    from rich.console import Console
    con = Console()
    con.print(f"  [dim]→[/dim] Installing spaCy NER model [bold]{model_name}[/bold] (one-time)...")

    env = dict(os.environ)
    env["PIP_BREAK_SYSTEM_PACKAGES"] = "1"
    in_venv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if not in_venv:
        env["PIP_USER"] = "1"

    result = subprocess.run(
        [sys.executable, "-m", "spacy", "download", model_name],
        capture_output=True,
        text=True,
        env=env,
    )

    if result.returncode == 0:
        try:
            import importlib
            import spacy as _spacy  # noqa: F401
            importlib.invalidate_caches()
            import spacy as _spacy2
            _spacy2.load(model_name)
            con.print(f"  [green]✓[/green] spaCy model ready")
            return True
        except Exception:
            pass

    err_tail = (result.stderr or result.stdout or "").strip().splitlines()[-3:]
    con.print(f"  [yellow]⚠[/yellow] spaCy install failed (exit {result.returncode}) — NER will be skipped.")
    for line in err_tail:
        con.print(f"    [dim]{line}[/dim]")
    con.print(
        f"  Run manually: [bold]PIP_BREAK_SYSTEM_PACKAGES=1 "
        f"{os.path.basename(sys.executable)} -m spacy download {model_name}[/bold]"
    )
    return False


def apply_env(config: Optional[dict[str, Any]] = None) -> None:
    """
    Push saved config into os.environ so that the existing voidaccess
    modules (config.py, llm.py, sources/*) pick up the values at import.

    Must be called BEFORE any voidaccess module is imported.
    """
    cfg = config or load_config()

    os.environ.setdefault("DATABASE_URL", db_url())
    os.environ.setdefault("JWT_SECRET", "voidaccess-cli-local-no-auth")
    os.environ.setdefault("DISABLE_RATE_LIMIT", "true")
    os.environ.setdefault("PLAYWRIGHT_ENABLED", "false")

    def _set_env_if_present(key: str, value: Any, *, clear_if_empty: bool = False) -> None:
        text = str(value) if value is not None else ""
        if not text or not text.strip():
            if clear_if_empty:
                os.environ.pop(key, None)
            return
        os.environ[key] = text.strip()

    # Tor proxy
    _set_env_if_present("TOR_PROXY_HOST", cfg.get("tor", {}).get("host", "127.0.0.1"))
    _set_env_if_present("TOR_PROXY_PORT", cfg.get("tor", {}).get("port", 9050))

    # LLM provider key (push under its canonical env var name)
    provider = cfg.get("llm", {}).get("provider", "")
    api_key = cfg.get("llm", {}).get("api_key", "")
    env_name = PROVIDER_ENV.get(provider)
    if env_name:
        _set_env_if_present(env_name, api_key, clear_if_empty=True)

    # Default model
    default_model = cfg.get("llm", {}).get("model", "")
    _set_env_if_present("DEFAULT_MODEL", default_model)

    # Enrichment keys
    for k, v in (cfg.get("enrichment_keys") or {}).items():
        _set_env_if_present(k, v, clear_if_empty=True)

    # Phase 1.6 — clearnet proxy toggles.  Per architect review these
    # are MUTUALLY EXCLUSIVE alternates, not independently combinable
    # gates (see sources/proxy_client.py §Architectural grounding for
    # the full quote from https://docs.scrapingant.com/proxy-mode).
    #
    # - features.use_proxies (legacy v1.5.0) → VOIDACCESS_USE_PROXIES=true
    #   Selects the REST API transport.
    # - features.use_proxy (new in v1.6.2)  → VOIDACCESS_USE_PROXY=true
    #   Selects the proxy transport.
    #
    # Each is set ONLY when the user has explicitly enabled it.  The
    # chokepoint reads these env vars AND SCRAPINGANT_API_KEY, so missing
    # key gracefully leaves both transports inactive — no error, no
    # fallback surprise.  This is the same logic already proven in
    # Phase 1's tests.
    features = cfg.get("features") or {}
    if features.get("use_proxies"):
        os.environ["VOIDACCESS_USE_PROXIES"] = "true"
    else:
        os.environ.pop("VOIDACCESS_USE_PROXIES", None)
    if features.get("use_proxy"):
        os.environ["VOIDACCESS_USE_PROXY"] = "true"
    else:
        os.environ.pop("VOIDACCESS_USE_PROXY", None)

    # Keyless APIs (ThreatFox/URLhaus/MalwareBazaar/abuse.ch) must never
    # receive an empty auth header — clear any empty env remnant.
    for key in ("ABUSECH_API_KEY", "VT_API_KEY", "OTX_API_KEY"):
        if not (os.environ.get(key) or "").strip():
            os.environ.pop(key, None)



