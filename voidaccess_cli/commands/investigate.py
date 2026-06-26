"""
cli/commands/investigate.py — voidaccess investigate "<query>"

Orchestrates the existing pipeline modules (search, sources, scraper,
extractor, llm) from a fresh async entry point. Re-implements the
sequencing that api.routes.investigations._run_investigation_task did
under FastAPI — minus auth, SSE, rate limiting, Postgres.

Outputs
    ~/.voidaccess/results/<slug>-<YYYYMMDD-HHMMSS>.json
    ~/.voidaccess/results/<slug>-<YYYYMMDD-HHMMSS>.md
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console

# Import reputation enrichment sources (used in Step 6.2–6.4)
from sources.domain_reputation import enrich_domain_entities
from sources.email_reputation import enrich_email_entities
from sources.hash_reputation import enrich_hash_entities

console = Console()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Typer entry point
# ---------------------------------------------------------------------------


def run(
    query: str = typer.Argument(..., help="Investigation query (e.g. 'LockBit ransomware')"),
    output: Optional[Path] = typer.Option(None, "--output", help="Override output directory"),
    model: Optional[str] = typer.Option(None, "--model", help="Override LLM model"),
    no_tor: bool = typer.Option(False, "--no-tor", help="Clearnet-only mode (skip Tor)"),
    no_llm: bool = typer.Option(False, "--no-llm", help="Skip LLM (query refinement, filtering, summary)"),
    depth: str = typer.Option("normal", "--depth", help="shallow | normal | deep"),
    fmt: str = typer.Option("both", "--format", help="json | md | both"),
    quiet: bool = typer.Option(False, "--quiet", help="No live display; print final summary only"),
) -> None:
    """Run an investigation: query → search → scrape → extract → enrich → report."""
    from voidaccess_cli import config as cli_config

    cli_config.apply_env()

    try:
        import spacy
        spacy.load("en_core_web_sm")
    except Exception:
        import subprocess, sys
        from rich.console import Console
        Console().print(
            "  [dim]→[/dim] Installing spaCy NER model (one-time)..."
        )
        subprocess.run(
            [sys.executable, "-m", "spacy",
             "download", "en_core_web_sm"],
            capture_output=True
        )

    if quiet:
        logging.getLogger().setLevel(logging.ERROR)

    from utils.content_safety import is_blocked_query
    blocked, reason = is_blocked_query(query)
    if blocked:
        console.print(f"[red]Query blocked:[/red] {reason}")
        raise typer.Exit(code=1)

    if not cli_config.is_configured() and not no_llm:
        console.print("[yellow]No LLM configured.[/yellow] Run [bold]voidaccess configure[/bold] first, or pass --no-llm.")
        raise typer.Exit(code=2)

    if depth not in ("shallow", "normal", "deep"):
        console.print(f"[red]Invalid depth:[/red] {depth}")
        raise typer.Exit(code=2)
    if fmt not in ("json", "md", "both"):
        console.print(f"[red]Invalid format:[/red] {fmt}")
        raise typer.Exit(code=2)

    out_dir = Path(output).expanduser() if output else cli_config.get_output_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        asyncio.run(
            _run_investigation(
                query=query,
                out_dir=out_dir,
                model=model,
                no_tor=no_tor,
                no_llm=no_llm,
                depth=depth,
                fmt=fmt,
                quiet=quiet,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user.[/yellow]")
        raise typer.Exit(code=130)


# ---------------------------------------------------------------------------
# Pipeline orchestrator
# ---------------------------------------------------------------------------


DEPTH_PRESETS = {
    "shallow": {"top_n": 10, "max_workers": 3, "extract_concurrency": 3},
    "normal":  {"top_n": 20, "max_workers": 5, "extract_concurrency": 5},
    "deep":    {"top_n": 40, "max_workers": 8, "extract_concurrency": 6},
}

# Pages kept after LLM relevance filter (must match voidaccess.llm.filter_results cap).
LLM_FILTER_TOP_N = 15

INVESTIGATION_STEPS = [
    "Refining query",
    "Searching dark web",
    "Filtering results",
    "Scraping pages",
    "Discovering seeds",
    "Extracting entities",
    "Enriching intelligence",
    "Enriching domains",
    "Enriching hashes",
    "Enriching emails",
    "Building graph",
    "Generating summary",
    "Finalizing results",
]

# ---------------------------------------------------------------------------
# Phase 6.2 — per-phase timeouts (CLI mirror of API PHASE_TIMEOUTS)
# ---------------------------------------------------------------------------
# Defaults mirror the API.  All values are env-var-overridable so ops can
# loosen the cap on a slow host without code changes.
_CLI_PHASE_TIMEOUT_DEFAULTS = {
    "enrichment": 120,
    "graph_build": 60,
    "summary": 90,
    "finalize": 30,
}

_CLI_PHASE_TIMEOUT_ENV_VARS = {
    "enrichment": "VOIDACCESS_ENRICHMENT_TIMEOUT",
    "graph_build": "VOIDACCESS_GRAPH_TIMEOUT",
    "summary": "VOIDACCESS_SUMMARY_TIMEOUT",
    "finalize": "VOIDACCESS_FINALIZE_TIMEOUT",
}


def _cli_phase_timeout(name: str) -> int:
    """Resolve a single CLI phase timeout from env vars (read at call time)."""
    default = _CLI_PHASE_TIMEOUT_DEFAULTS.get(name, 60)
    env_var = _CLI_PHASE_TIMEOUT_ENV_VARS.get(name)
    if env_var:
        raw = os.getenv(env_var)
        if raw:
            try:
                return int(raw)
            except ValueError:
                logger.warning(
                    "[cli-phase-timeout] Invalid %s=%r — using default %ds",
                    env_var, raw, default,
                )
    return default


CLI_PHASE_TIMEOUTS: dict[str, int] = {
    name: _cli_phase_timeout(name) for name in _CLI_PHASE_TIMEOUT_DEFAULTS
}


async def _cli_run_with_timeout(coro, timeout_seconds: int, phase_name: str, investigation_id: str):
    """Phase 6.2 timeout wrapper for the CLI.

    On timeout: logs a warning and returns ``None``.  Never raises
    ``TimeoutError`` to the caller — the pipeline must always be able to
    continue with partial results.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout_seconds)
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] CLI phase '%s' timed out after %ds — continuing with partial results",
            investigation_id, phase_name, timeout_seconds,
        )
        return None


async def _run_investigation(
    query: str,
    out_dir: Path,
    model: Optional[str],
    no_tor: bool,
    no_llm: bool,
    depth: str,
    fmt: str,
    quiet: bool,
) -> None:
    from voidaccess_cli import config as cli_config
    from voidaccess_cli.adapters import sqlite as sqlite_adapter
    from voidaccess_cli.display import InvestigationDisplay
    from voidaccess_cli.tor_detect import detect_tor, tor_unavailable_message

    cfg = cli_config.load_config()
    preset = DEPTH_PRESETS[depth]
    display = InvestigationDisplay(quiet=quiet)
    display.start(query, steps=INVESTIGATION_STEPS)

    # Background tasks scheduled during the pipeline that must be awaited
    # before asyncio.run() exits, otherwise they get cancelled mid-write.
    # Populated by ``asyncio.create_task(...)`` calls that want to remain
    # non-blocking from the perspective of the main pipeline, but still
    # need a deterministic drain before the process exits.
    _background_tasks: list[asyncio.Task] = []

    # --- DB init ----------------------------------------------------------
    sqlite_adapter.init_db()
    _patch_llm_extraction_cache(sqlite_adapter)

    # Phase 6.3 — clean up CLI investigations that were interrupted by a
    # prior Ctrl-C / kill -9 / power loss.  asyncio.run() can't leave rows
    # mid-flight the way FastAPI BackgroundTasks can, but Ctrl-C during a
    # long pipeline can — this is the safety net.
    try:
        cleaned = await sqlite_adapter.cleanup_stuck_investigations(cutoff_minutes=None)
        if cleaned and not quiet:
            console.print(
                f"[yellow]Marked {cleaned} interrupted investigation(s) as failed.[/yellow]"
            )
    except Exception as exc:
        logger.debug("CLI stuck-investigation cleanup failed (non-fatal): %s", exc)

    # --- Tor preflight ----------------------------------------------------
    tor_proxy: Optional[str] = None
    if not no_tor:
        status = detect_tor()
        if status.proxy_url:
            tor_proxy = status.proxy_url
            os.environ["TOR_PROXY_HOST"] = status.host or "127.0.0.1"
            os.environ["TOR_PROXY_PORT"] = str(status.port or 9050)
        else:
            display.error(tor_unavailable_message())
            return

    # --- LLM instance -----------------------------------------------------
    llm = None
    chosen_model = model or cli_config.get_llm_model(cfg)
    if not no_llm:
        try:
            from voidaccess.llm import get_llm
            llm = get_llm(chosen_model)
        except Exception as exc:
            display.update_step("Refining query", "fail", f"LLM init failed: {exc}")
            llm = None

    # --- Create investigation row -----------------------------------------
    investigation_id = sqlite_adapter.save_investigation(
        query=query,
        model_used=chosen_model if llm is not None else None,
        status="running",
    )
    inv_uuid = uuid.UUID(investigation_id)

    sources_used: dict[str, dict[str, Any]] = {}
    page_count_by_url: dict[str, dict[str, Any]] = {}

    # --- Step 1 — refine query -------------------------------------------
    display.update_step("Refining query", "active")
    refined = query
    if llm is not None:
        try:
            from voidaccess.llm import refine_query
            refined = await asyncio.to_thread(refine_query, llm, query) or query
        except Exception as exc:
            display.update_step("Refining query", "fail", str(exc))
            refined = query
        else:
            display.update_step("Refining query", "ok", f"→ {refined!r}")
    else:
        display.update_step("Refining query", "skip", "--no-llm")
    sqlite_adapter.update_investigation(investigation_id, {"refined_query": refined})

    # --- Step 2 — search fan-out -----------------------------------------
    display.update_step("Searching dark web", "active")
    search_links: list[dict] = []
    paste_pages: list[dict] = []
    github_pages: list[dict] = []
    gitlab_pages: list[dict] = []
    rss_pages: list[dict] = []
    search_summary: dict[str, int] = {}

    if not no_tor:
        try:
            from search import get_last_search_summary, get_search_results_async
            display.update_substep("Searching dark web", "Tor engines", "active")
            search_links = await asyncio.to_thread(get_search_results_async, refined, preset["max_workers"], llm)
            display.update_substep("Searching dark web", "Tor engines", "ok")
            search_summary = get_last_search_summary()
            sources_used["tor_search"] = {"status": "ok", "count": len(search_links)}
        except Exception as exc:
            display.update_substep("Searching dark web", "Tor engines", "fail")
            search_summary = {}
            sources_used["tor_search"] = {"status": "fail", "error": str(exc)}
    else:
        display.update_substep("Searching dark web", "Tor engines", "skip")
        sources_used["tor_search"] = {"status": "skipped"}

    # Parallel clearnet sources
    async def _safe(coro_factory, label, key):
        display.update_substep("Searching dark web", label, "active")
        try:
            res = await coro_factory()
            display.update_substep("Searching dark web", label, "ok")
            sources_used[key] = {"status": "ok", "count": len(res) if res else 0}
            return res or []
        except Exception as exc:
            display.update_substep("Searching dark web", label, "fail")
            sources_used[key] = {"status": "fail", "error": str(exc)}
            return []

    side_tasks = await asyncio.gather(
        _safe(lambda: _scrape_pastes(refined), "Paste sites", "paste_sites"),
        _safe(lambda: _scrape_github(refined), "GitHub", "github"),
        _safe(lambda: _scrape_gitlab(refined), "GitLab", "gitlab"),
        _safe(lambda: _scrape_rss(refined), "RSS feeds", "rss"),
    )
    paste_pages, github_pages, gitlab_pages, rss_pages = side_tasks

    if not no_tor and search_summary:
        display.update_step(
            "Searching dark web",
            "ok",
            (
                f"{search_summary.get('active', 0)}/{search_summary.get('total', 0)} engines active, "
                f"{search_summary.get('circuits_open', 0)} circuits open, {len(search_links)} results"
            ),
        )
    else:
        display.update_step("Searching dark web", "ok", f"{len(search_links)} links + side sources")

    # --- Step 3 — filter results ------------------------------------------
    display.update_step("Filtering results", "active")
    filter_top_n = LLM_FILTER_TOP_N
    filtered_links = search_links[: filter_top_n * 2] if search_links else []
    if llm is not None and search_links:
        try:
            from voidaccess.llm import filter_results
            filtered_links = await asyncio.to_thread(filter_results, llm, refined, search_links, filter_top_n) or search_links
            filtered_links = filtered_links[:filter_top_n]
            display.update_step("Filtering results", "ok", f"top {len(filtered_links)}")
        except Exception as exc:
            display.update_step("Filtering results", "fail", str(exc))
            filtered_links = search_links[:filter_top_n]
    elif no_llm and search_links:
        # No LLM: pick pages via the heuristic ranker instead of just
        # taking the first N (which are usually search-engine index
        # pages and low-value landing pages).
        try:
            from voidaccess.llm import _heuristic_filter
            picked = _heuristic_filter(search_links, refined or query, filter_top_n)
            filtered_links = [search_links[i - 1] for i in picked]
            display.update_step(
                "Filtering results",
                "ok",
                f"heuristic top {len(filtered_links)}",
            )
        except Exception as exc:
            logger.warning("Heuristic filter failed (%s); falling back to first-N", exc)
            filtered_links = (search_links or [])[:filter_top_n]
            display.update_step("Filtering results", "skip", f"{len(filtered_links)} kept")
    else:
        filtered_links = (search_links or [])[:filter_top_n]
        display.update_step("Filtering results", "skip" if no_llm else "ok", f"{len(filtered_links)} kept")

    # --- Step 4 — scrape pages -------------------------------------------
    display.update_step("Scraping pages", "active")
    scraped_pages: list[dict] = []
    if filtered_links:
        try:
            from scraper.scrape import scrape_multiple

            async def _scrape_with_progress():
                # scrape_multiple does its own batching; we surface current URL
                # by intercepting via a side ticker since the underlying API
                # doesn't expose per-URL callbacks. Best effort: just show the
                # first URL while the gather runs.
                display.update_current_url(
                    (filtered_links[0].get("link") if filtered_links else "") or ""
                )
                return await scrape_multiple(
                    filtered_links,
                    max_workers=preset["max_workers"],
                    investigation_id=investigation_id,
                )

            results = await _scrape_with_progress()
            display.update_current_url("")
            for url, text in results.items():
                if text:
                    scraped_pages.append({"url": url, "text": text, "source": "tor_search"})
            display.update_step("Scraping pages", "ok", f"{len(scraped_pages)} pages")
        except Exception as exc:
            display.update_step("Scraping pages", "fail", str(exc))
    else:
        display.update_step("Scraping pages", "skip", "no links")

    # --- Step 4.1 — discover seeds from scraped pages --------------------
    # scrape_multiple already submits discovered seeds fire-and-forget, but
    # the CLI also wants an explicit count to show in the progress display
    # and to surface in the final report payload.
    seeds_discovered = 0
    try:
        from scraper.scrape import _discover_seeds_from_one_page  # noqa: WPS437

        seeds_discovered = await _discover_seeds_from_pages(
            scraped_pages,
            investigation_id=investigation_id,
        )
        if seeds_discovered > 0:
            display.update_step(
                "Discovering seeds",
                "ok",
                f"{seeds_discovered} new .onion addresses",
            )
    except Exception as exc:
        logger.debug("Seed discovery from CLI pages failed (non-fatal): %s", exc)
        display.update_step("Discovering seeds", "skip", "no new seeds")

    # Merge in clearnet pages (paste/github/gitlab/rss)
    for extra in (paste_pages, github_pages, gitlab_pages, rss_pages):
        for page in extra:
            url = page.get("url") or page.get("link")
            text = page.get("text") or page.get("content") or page.get("cleaned_text") or page.get("text_content") or ""
            if not url or not text:
                continue
            scraped_pages.append({"url": url, "text": text, "source": page.get("source", "clearnet")})

    # Resolve page_ids from DB (scrape_multiple persisted .onion pages)
    page_ids = await asyncio.to_thread(_lookup_page_ids, [p["url"] for p in scraped_pages])
    for page in scraped_pages:
        pid = page_ids.get(page["url"])
        if pid is not None:
            page["page_id"] = pid

    page_count_by_url = {p["url"]: p for p in scraped_pages}

    # --- Step 5 — extract entities ---------------------------------------
    display.update_step("Extracting entities", "active")
    extraction_results = []
    try:
        from extractor.pipeline import extract_entities_from_pages
        extraction_results = await extract_entities_from_pages(
            pages=scraped_pages,
            investigation_id=inv_uuid,
            llm=llm,
            run_llm_extraction=llm is not None,
            max_concurrent=preset["extract_concurrency"],
        )
        total_entities = sum(len(r.entity_ids) for r in extraction_results)
        display.update_step("Extracting entities", "ok", f"{total_entities} entities")
    except Exception as exc:
        display.update_step("Extracting entities", "fail", str(exc))

    # --- Step 6 — enrich intelligence (OTX + IP) ---------------------------
    display.update_step("Enriching intelligence", "active")
    enrichment_pages: list[dict] = []
    try:
        from sources.enrichment import enrich_investigation as _enrich_inv
        otx_key = os.getenv("OTX_API_KEY", "") or ""
        entity_dicts = sqlite_adapter.get_entities(investigation_id)
        enrichment_pages = await _enrich_inv(refined, otx_api_key=otx_key, entities=entity_dicts)
        sources_used["enrichment"] = {"status": "ok", "count": len(enrichment_pages)}
        display.update_step("Enriching intelligence", "ok", f"{len(enrichment_pages)} pages added")
    except Exception as exc:
        sources_used["enrichment"] = {"status": "fail", "error": str(exc)}
        display.update_step("Enriching intelligence", "fail", str(exc))

    try:
        from sources.ip_reputation import enrich_ip_entities
        await enrich_ip_entities(extraction_results, investigation_id=inv_uuid)
    except Exception as ip_exc:
        logger.debug("ip_reputation skipped: %s", ip_exc)

    # --- Step 6.2–6.4 — domain / hash / email (before graph) -------------
    # Phase 6.2 — per-step timeouts so a hung reputation source doesn't
    # wedge the whole CLI run.  The outer enrichment cap (CLI_PHASE_TIMEOUTS
    # ["enrichment"]) is a defence-in-depth safety net applied around the
    # whole cluster further down.
    display.update_step("Enriching domains", "active")
    try:
        extraction_results = await asyncio.wait_for(
            enrich_domain_entities(extraction_results, inv_uuid),
            timeout=60,
        )
        domain_count = sum(
            1
            for e in sqlite_adapter.get_entities(investigation_id)
            if (e.get("entity_type") or "").upper() == "DOMAIN"
        )
        detail = f"{domain_count} domains enriched" if domain_count else ""
        display.update_step("Enriching domains", "ok", detail)
    except asyncio.TimeoutError:
        logger.warning("[%s] Domain enrichment timed out after 60s", inv_uuid)
        display.update_step("Enriching domains", "fail", "timeout")
    except Exception as exc:
        logger.debug("Domain enrichment: %s", exc)
        display.update_step("Enriching domains", "fail", str(exc))

    display.update_step("Enriching hashes", "active")
    try:
        extraction_results = await asyncio.wait_for(
            enrich_hash_entities(extraction_results, inv_uuid),
            timeout=45,
        )
        display.update_step("Enriching hashes", "ok")
    except asyncio.TimeoutError:
        logger.warning("[%s] Hash enrichment timed out after 45s", inv_uuid)
        display.update_step("Enriching hashes", "fail", "timeout")
    except Exception as exc:
        logger.debug("Hash enrichment: %s", exc)
        display.update_step("Enriching hashes", "fail", str(exc))

    display.update_step("Enriching emails", "active")
    try:
        extraction_results = await asyncio.wait_for(
            enrich_email_entities(extraction_results, inv_uuid),
            timeout=30,
        )
        display.update_step("Enriching emails", "ok")
    except asyncio.TimeoutError:
        logger.warning("[%s] Email enrichment timed out after 30s", inv_uuid)
        display.update_step("Enriching emails", "fail", "timeout")
    except Exception as exc:
        logger.debug("Email enrichment: %s", exc)
        display.update_step("Enriching emails", "fail", str(exc))

    if enrichment_pages:
        try:
            from extractor.pipeline import extract_entities_from_pages as _extr2
            await _extr2(
                pages=enrichment_pages,
                investigation_id=inv_uuid,
                llm=None,
                run_llm_extraction=False,
                max_concurrent=preset["extract_concurrency"],
            )
        except Exception as exc:
            console.print(f"[grey50]Enrichment extraction failed: {exc}[/grey50]")

    # --- Step 6.9 — Update persistent actor profiles (non-blocking) -------
    # Aggregate THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP entities from the
    # extraction results into the cross-investigation actor profile tables.
    # Fire-and-forget so a slow DB write never stalls the pipeline.
    try:
        actor_entities: list = []
        for _r in extraction_results:
            actor_entities.extend(getattr(_r, "entities", []) or [])
        if actor_entities:
            _ap_task = asyncio.create_task(
                _update_cli_actor_profiles(actor_entities, inv_uuid),
                name=f"actor-profiles-{inv_uuid}",
            )
            _background_tasks.append(_ap_task)
            def _log_actor_task_result(t: "asyncio.Task") -> None:
                try:
                    t.result()
                except asyncio.CancelledError:
                    pass
                except Exception as exc:
                    logger.debug(
                        "Actor profile CLI task raised (non-fatal): %s", exc
                    )
            _ap_task.add_done_callback(_log_actor_task_result)
            logger.debug(
                "Actor profile update scheduled (%d entities, non-blocking)",
                len(actor_entities),
            )
    except Exception as _ap_exc:
        logger.debug("Actor profile schedule failed (non-fatal): %s", _ap_exc)

    # --- Step 7 — build graph (co-occurrence) ----------------------------
    # Phase 6.2 — capped by CLI_PHASE_TIMEOUTS["graph_build"] so a large
    # entity table doesn't pin the CLI thread indefinitely.
    display.update_step("Building graph", "active")
    try:
        edges_written = await asyncio.wait_for(
            asyncio.to_thread(_build_cooccurrence_edges, investigation_id),
            timeout=CLI_PHASE_TIMEOUTS["graph_build"],
        )
        display.update_step("Building graph", "ok", f"{edges_written} edges")
    except asyncio.TimeoutError:
        logger.warning(
            "[%s] Graph build timed out after %ds",
            inv_uuid, CLI_PHASE_TIMEOUTS["graph_build"],
        )
        display.update_step("Building graph", "fail", "timeout")
    except Exception as exc:
        display.update_step("Building graph", "fail", str(exc))

    # --- Step 7.5 — community detection (server-side Louvain alt) ---------
    # Runs against the same entity/relationship set the graph was built from,
    # using greedy modularity from networkx.  Same algorithm as the API uses
    # in ``graph.builder.detect_communities`` so the CLI JSON and the web UI
    # colour the same communities identically.
    communities: dict[str, int] = {}
    try:
        communities = await asyncio.to_thread(
            _detect_communities_for_investigation, investigation_id
        )
    except Exception as exc:
        logger.debug("Community detection skipped: %s", exc)

    # --- Step 8 — summary -------------------------------------------------
    # Phase 6.2 — capped by CLI_PHASE_TIMEOUTS["summary"] so a slow LLM
    # call never holds the CLI process open past its budget.
    display.update_step("Generating summary", "active")
    summary_text = ""
    if llm is not None:
        try:
            from voidaccess.llm import generate_summary
            pages_to_summarize = scraped_pages[:10]
            if pages_to_summarize:
                summary_text = await asyncio.wait_for(
                    asyncio.to_thread(
                        generate_summary, llm, refined, pages_to_summarize, "threat_intel"
                    ),
                    timeout=CLI_PHASE_TIMEOUTS["summary"],
                )
            display.update_step("Generating summary", "ok")
        except asyncio.TimeoutError:
            logger.warning(
                "[%s] Summary generation timed out after %ds",
                inv_uuid, CLI_PHASE_TIMEOUTS["summary"],
            )
            display.update_step("Generating summary", "fail", "timeout")
        except Exception as exc:
            display.update_step("Generating summary", "fail", str(exc))
    else:
        display.update_step("Generating summary", "skip", "--no-llm")

    # --- Step 9 — finalize & write outputs --------------------------------
    display.update_step("Finalizing results", "active")
    final_entities = sqlite_adapter.get_entities(investigation_id)
    final_relationships = sqlite_adapter.get_relationships(investigation_id)
    sqlite_adapter.update_investigation(
        investigation_id,
        {
            "status": "completed",
            "summary": summary_text or None,
            "entity_count": len(final_entities),
            "page_count": len(scraped_pages),
            "current_step": 9,
            "current_step_label": "Completed",
        },
    )

    # Persist seeds_discovered count in the summary metadata so admin/
    # show commands can surface it without re-querying the seed manager.
    try:
        from sources.seed_manager import get_seed_manager as _gsm

        _sm = _gsm()
        _discovered_count = sum(
            1
            for s in _sm.list_seeds()
            if s.get("category") == "discovered"
            and s.get("investigation_id") == investigation_id
        )
    except Exception:
        _discovered_count = seeds_discovered

    slug = _slugify(query)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    json_path = out_dir / f"{slug}-{ts}.json"
    md_path = out_dir / f"{slug}-{ts}.md"

    payload = {
        "id": investigation_id,
        "query": query,
        "refined_query": refined,
        "model_used": chosen_model if llm is not None else None,
        "status": "completed" if final_entities or scraped_pages else "completed_no_results",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary_text,
        "sources_used": sources_used,
        "entities": final_entities,
        "relationships": final_relationships,
        "pages_scraped": [{"url": p["url"], "source": p.get("source", "")} for p in scraped_pages],
        "communities": communities,
        "community_count": len(set(communities.values())) if communities else 0,
        "seeds_discovered": _discovered_count,
    }

    if fmt in ("json", "both"):
        json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    if fmt in ("md", "both"):
        md_path.write_text(_render_markdown(payload), encoding="utf-8")

    display.update_step("Finalizing results", "ok")

    # Drain any background tasks scheduled during the pipeline (e.g. the
    # actor-profile aggregator).  This keeps the "fire-and-forget"
    # semantics for the main pipeline while still guaranteeing the task
    # completes before asyncio.run() exits and cancels pending work.
    if _background_tasks:
        try:
            await asyncio.wait_for(
                asyncio.gather(*_background_tasks, return_exceptions=True),
                timeout=30,
            )
        except asyncio.TimeoutError:
            logger.debug(
                "Background tasks did not finish in 30s — letting them cancel"
            )

    c2_count = sum(
        1 for e in final_entities
        if e["entity_type"] == "IP_ADDRESS"
        and (e.get("corroborating_sources") or "").lower().find("c2") >= 0
    )

    display.complete(
        {
            "entity_count": len(final_entities),
            "page_count": len(scraped_pages),
            "c2_ips": c2_count,
            "seeds_discovered": _discovered_count,
            "sources_used": sum(1 for v in sources_used.values() if v.get("status") == "ok"),
            "report_path": str(md_path) if fmt in ("md", "both") else None,
            "data_path": str(json_path) if fmt in ("json", "both") else None,
        }
    )

    # Close any cached aiohttp sessions so the event loop exits cleanly
    # (otherwise aiohttp prints "Unclosed client session" warnings).
    await _close_cached_sessions()


def _patch_llm_extraction_cache(sqlite_adapter: Any) -> None:
    """Use sqlite adapter for cache reads (naive ISO strings from SQLite)."""
    try:
        import extractor.llm_extract as llm_extract
    except Exception:
        return
    llm_extract._load_from_cache = sqlite_adapter.get_page_extraction_cache


# Cap per-investigation seed discovery (mirrors the scraper's constant).
_SEED_DISCOVERY_MAX_PER_INVESTIGATION = 100


async def _discover_seeds_from_pages(
    pages: list[dict],
    investigation_id: str,
) -> int:
    """
    Extract .onion URLs from a batch of scraped pages and submit them
    to the seed manager.  Reuses scraper.scrape._discover_seeds_from_one_page
    so the per-page/per-investigation cap and fire-and-forget semantics
    stay identical to the API pipeline.

    Only onion pages are mined (matches the scraper's gate).

    Returns the number of new seeds successfully submitted.
    """
    if not pages:
        return 0

    try:
        from scraper.scrape import _discover_seeds_from_one_page  # noqa: WPS437
    except Exception:
        return 0

    counter: dict = {"count": 0}

    async def _run(page: dict) -> int:
        page_url = page.get("url") or ""
        page_text = page.get("text") or page.get("content") or ""
        if not page_url or not page_text:
            return 0
        if ".onion" not in page_url.lower():
            return 0
        if counter["count"] >= _SEED_DISCOVERY_MAX_PER_INVESTIGATION:
            return 0
        return await _discover_seeds_from_one_page(
            page_url=page_url,
            content=page_text,
            investigation_id=investigation_id,
            investigation_counter=counter,
        )

    results = await asyncio.gather(
        *[_run(p) for p in pages],
        return_exceptions=True,
    )
    total = 0
    for r in results:
        if isinstance(r, int):
            total += r
    return total


async def _close_cached_sessions() -> None:
    try:
        from scraper.scrape import close_cached_sessions as _close_scrape
        await _close_scrape()
    except Exception:
        pass
    try:
        from search import close_search_session as _close_search
        await _close_search()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Side-source helpers (each gracefully degrades if module missing/disabled)
# ---------------------------------------------------------------------------


async def _scrape_pastes(query: str) -> list[dict]:
    try:
        from sources.paste_scraper import scrape_paste_sites
    except Exception:
        return []
    if os.getenv("PASTE_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_paste_sites(query) or []
    except Exception:
        return []


async def _scrape_github(query: str) -> list[dict]:
    try:
        from sources.github_scraper import scrape_github
    except Exception:
        return []
    if os.getenv("GITHUB_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_github(query) or []
    except Exception:
        return []


async def _scrape_gitlab(query: str) -> list[dict]:
    try:
        from sources.gitlab_scraper import scrape_gitlab
    except Exception:
        return []
    if os.getenv("GITLAB_SCRAPING_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_gitlab(query) or []
    except Exception:
        return []


async def _scrape_rss(query: str) -> list[dict]:
    try:
        from sources.rss_scraper import scrape_rss_feeds
    except Exception:
        return []
    if os.getenv("RSS_FEEDS_ENABLED", "true").lower() != "true":
        return []
    try:
        return await scrape_rss_feeds(query) or []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


def _lookup_page_ids(urls: list[str]) -> dict[str, uuid.UUID]:
    if not urls:
        return {}
    try:
        from db.models import Page
        from db.session import get_session
    except Exception:
        return {}
    out: dict[str, uuid.UUID] = {}
    with get_session() as session:
        rows = session.query(Page).filter(Page.url.in_(urls)).all()
        for r in rows:
            out[r.url] = r.id
    return out


def _build_cooccurrence_edges(investigation_id: str) -> int:
    """Generate CO_APPEARED_ON edges for entities sharing a page."""
    try:
        from db.models import Entity
        from db.session import get_session
    except Exception:
        return 0
    from voidaccess_cli.adapters.sqlite import save_relationships

    edges: list[dict] = []
    inv_uuid = uuid.UUID(investigation_id)

    with get_session() as session:
        rows = (
            session.query(Entity.id, Entity.page_id)
            .filter(Entity.investigation_id == inv_uuid)
            .all()
        )
    by_page: dict[uuid.UUID, list[uuid.UUID]] = {}
    for ent_id, page_id in rows:
        if page_id is None:
            continue
        by_page.setdefault(page_id, []).append(ent_id)

    for ents in by_page.values():
        if len(ents) < 2:
            continue
        for i in range(len(ents)):
            for j in range(i + 1, len(ents)):
                edges.append(
                    {
                        "entity_a_id": str(ents[i]),
                        "entity_b_id": str(ents[j]),
                        "relationship_type": "CO_APPEARED_ON",
                        "confidence": 0.8,
                    }
                )
    return save_relationships(investigation_id, edges)


def _detect_communities_for_investigation(investigation_id: str) -> dict[str, int]:
    """
    Run greedy-modularity community detection over the same entity/edge set
    that the CLI just persisted.  Returns ``{entity_id_str: community_id}``.

    Implementation reuses ``graph.builder.detect_communities`` so the CLI and
    the FastAPI graph endpoint produce identical partitions for the same
    investigation.  NetworkX is built into the project already — no new dep.
    """
    try:
        import networkx as nx

        from graph.builder import detect_communities
        from voidaccess_cli.adapters import sqlite as sqlite_adapter
    except Exception:
        return {}

    entities = sqlite_adapter.get_entities(investigation_id)
    relationships = sqlite_adapter.get_relationships(investigation_id)
    if not entities or not relationships:
        return {}

    G = nx.Graph()
    for ent in entities:
        eid = ent.get("id")
        if not eid:
            continue
        G.add_node(
            str(eid),
            entity_type=ent.get("entity_type") or "",
            confidence=float(ent.get("confidence") or 0.0),
        )
    for rel in relationships:
        a = rel.get("entity_a_id")
        b = rel.get("entity_b_id")
        if not a or not b or a == b:
            continue
        G.add_edge(
            str(a),
            str(b),
            relationship_type=rel.get("relationship_type") or "",
            confidence=float(rel.get("confidence") or 0.0),
        )

    partition = detect_communities(G)
    # Cast keys to str so the JSON payload is uniform (sqlite_adapter returns
    # plain dicts already, but be defensive).
    return {str(k): int(v) for k, v in partition.items()}


async def _update_cli_actor_profiles(
    entities: list,
    investigation_id: "uuid.UUID",
) -> None:
    """Persist THREAT_ACTOR_HANDLE / RANSOMWARE_GROUP entities to long-lived
    actor profile tables.  Mirrors the API-side
    ``api/routes/investigations._update_actor_profiles``.

    Wrapped in try/except so any failure is logged at DEBUG and never
    raised — this is fire-and-forget.
    """
    try:
        from sources.actor_profiles import ActorProfileManager

        manager = ActorProfileManager()
        return await manager.update_from_extraction(
            entities=entities or [],
            investigation_id=investigation_id,
        )
    except Exception as exc:
        logger.debug(
            "CLI actor profile update failed (non-fatal): %s", exc
        )
        return None


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def _slugify(s: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", s).strip("-").lower()
    return s[:50] or "investigation"


def _render_markdown(payload: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Investigation: {payload['query']}")
    lines.append(
        f"**Date:** {payload['created_at']}  |  **Model:** {payload.get('model_used') or '—'}"
    )
    if payload.get("refined_query") and payload["refined_query"] != payload["query"]:
        lines.append(f"**Refined:** {payload['refined_query']}")
    lines.append("")
    lines.append("## Summary")
    lines.append(payload.get("summary") or "_(no summary — LLM disabled or unavailable)_")
    lines.append("")

    entities = payload.get("entities", [])
    by_type: dict[str, list[dict]] = {}
    for e in entities:
        by_type.setdefault(e["entity_type"], []).append(e)

    c2_ips = [
        e for e in entities
        if e["entity_type"] == "IP_ADDRESS"
        and (e.get("corroborating_sources") or "").lower().find("c2") >= 0
    ]
    lines.append("## Key findings")
    lines.append(f"- {len(c2_ips)} confirmed C2 IP addresses")
    lines.append(
        f"- {len(by_type.get('RANSOMWARE_GROUP', []))} ransomware group(s) identified"
    )
    lines.append(f"- {len(by_type.get('ONION_URL', []))} .onion URLs mapped")
    lines.append(f"- {len(entities)} entities total")
    lines.append(f"- {payload.get('seeds_discovered', 0)} new .onion seeds discovered")
    lines.append("")

    lines.append(f"## Entities ({len(entities)} total)")
    for etype in sorted(by_type.keys()):
        rows = by_type[etype]
        lines.append(f"\n### {etype} ({len(rows)})")
        lines.append("| Value | Confidence | Method | Tags |")
        lines.append("|---|---|---|---|")
        for r in rows[:50]:
            tags = (r.get("corroborating_sources") or "").replace("|", "/")
            val = (r.get("canonical_value") or r.get("value") or "").replace("|", "/")
            conf = r.get("confidence")
            lines.append(
                f"| {val} | {conf:.2f} | {r.get('extraction_method') or ''} | {tags} |"
            )
        if len(rows) > 50:
            lines.append(f"\n_…and {len(rows) - 50} more (see JSON)_")
    lines.append("")

    lines.append("## Sources used")
    for name, info in payload.get("sources_used", {}).items():
        glyph = "✓" if info.get("status") == "ok" else ("↷" if info.get("status") == "skipped" else "✗")
        detail = f" ({info.get('count', 0)} results)" if "count" in info else ""
        lines.append(f"- {glyph} {name}{detail}")

    return "\n".join(lines) + "\n"
