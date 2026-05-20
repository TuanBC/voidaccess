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
        text = str(value).strip() if value is not None else ""
        if text:
            os.environ[key] = text
        elif clear_if_empty:
            os.environ.pop(key, None)

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
