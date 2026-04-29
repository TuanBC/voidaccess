"""
api/routes/investigations.py — Investigation management endpoints.

POST /investigations          — trigger an investigation (background task)
GET  /investigations          — list recent investigations
GET  /investigations/{id}     — get single investigation
GET  /investigations/{id}/entities — list entities for investigation
GET  /investigations/{id}/graph    — graph JSON for investigation
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import csv
import io
import logging
import os
import uuid
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select as sa_select
from crawler import crawl
from sources.seeds import get_seeds
from api.auth import get_current_user
import json

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
router = APIRouter()

# ---------------------------------------------------------------------------
# Rate limiting (shared key_func with api/main.py; enforcement via app.state.limiter)
# ---------------------------------------------------------------------------

_DISABLE_RATE_LIMIT = os.getenv("DISABLE_RATE_LIMIT", "false").lower() == "true"

if not _DISABLE_RATE_LIMIT:
    try:
        from slowapi import Limiter
        from slowapi.util import get_remote_address
        _limiter: "Limiter | None" = Limiter(key_func=get_remote_address)
    except ImportError:
        _limiter = None
else:
    _limiter = None


def _rate_limit(limit_string: str):
    """Return a slowapi rate-limit decorator, or a pass-through when disabled."""
    if _limiter is None:
        return lambda f: f
    return _limiter.limit(limit_string)


STEP_LABELS = {
    1: "Refining query",
    2: "Searching dark web",
    3: "Filtering results",
    4: "Scraping pages",
    5: "Extracting entities",
    6: "Enriching intelligence",
    7: "Building graph",
    8: "Generating summary",
    9: "Finalizing results",
}


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class InvestigationRequest(BaseModel):
    query: str
    model: Optional[str] = None
    run_crawler: bool = False


# ---------------------------------------------------------------------------
# Helper: load investigation from DB
# ---------------------------------------------------------------------------


def _get_db_investigation(investigation_id: str) -> Any:
    """Return investigation dict or raise HTTPException 404."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session  # noqa: PLC0415
        from db.queries import (  # noqa: PLC0415
            count_distinct_pages_for_investigation,
            get_investigation_by_id_or_run,
        )

        from sqlalchemy import func  # noqa: PLC0415
        from db.models import Entity, EntityRelationship, InvestigationEntityLink  # noqa: PLC0415

        inv_uuid = uuid.UUID(investigation_id)
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            pages_crawled = count_distinct_pages_for_investigation(session, inv.id)

            # Entity IDs for this investigation = own entities + junction-table links
            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            entity_subq = (
                session.query(Entity.id)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_subq)
                )
                .subquery()
            )
            entity_count = int(
                session.query(func.count()).select_from(entity_subq).scalar() or 0
            )
            relationship_count = int(
                session.query(func.count(EntityRelationship.id))
                .filter(
                    (EntityRelationship.entity_a_id.in_(entity_subq))
                    | (EntityRelationship.entity_b_id.in_(entity_subq))
                )
                .scalar()
                or 0
            )
            return {
                "id": str(inv.id),
                "run_id": str(inv.run_id),
                "query": inv.query,
                "refined_query": inv.refined_query,
                "model_used": inv.model_used,
                "preset": inv.preset,
                "summary": inv.summary,
                "status": inv.status,
                "graph_status": getattr(inv, "graph_status", "pending"),
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "current_step": inv.current_step or 0,
                "current_step_label": inv.current_step_label or "",
                "entity_count": entity_count,
                "relationship_count": relationship_count,
                "page_count": pages_crawled,
                "pages_crawled": pages_crawled,  # keep for compat
            }
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    except Exception as exc:
        logger.exception("_get_db_investigation failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {exc!s}"[:500],
        )


async def _update_investigation_status(
    investigation_id: uuid.UUID,
    status: str,
    model_used: Optional[str] = None,
    summary: Optional[str] = None,
) -> None:
    """Update investigation status in a short-lived session."""
    from db.session import get_session
    from db.models import Investigation

    with get_session() as session:
        updates: dict[str, Any] = {"status": status}
        if model_used is not None:
            updates["model_used"] = model_used
        if summary is not None:
            updates["summary"] = summary
        session.query(Investigation).filter_by(id=investigation_id).update(updates)
        session.commit()


async def _update_progress(
    investigation_id: uuid.UUID,
    step: Optional[int] = None,
    extracted_entities: Optional[list] = None,
    scraped_pages: Optional[dict] = None,
    label: Optional[str] = None,
) -> None:
    """Fire-and-forget progress field update. Failures are non-critical."""
    try:
        from db.session import get_session
        from db.models import Investigation

        with get_session() as session:
            inv = session.query(Investigation).filter_by(id=investigation_id).first()
            if inv is None:
                return
            if step is not None:
                inv.current_step = step
                inv.current_step_label = label if label is not None else STEP_LABELS.get(step, "Processing")
            elif label is not None:
                inv.current_step_label = label
            if extracted_entities is not None:
                inv.entity_count = len(extracted_entities)
            if scraped_pages is not None:
                inv.page_count = len(scraped_pages)
            session.commit()
    except Exception as e:
        logger.warning("[%s] _update_progress failed (non-critical): %s", investigation_id, e)


async def _get_investigation_model_choice(model: Optional[str]) -> tuple[str, Any]:
    """Get model choices and selected model in a short-lived session."""
    from db.session import get_session
    from llm_utils import get_model_choices
    import config as config_module

    with get_session() as session:
        model_choices = get_model_choices()
        if not model_choices:
            raise RuntimeError("No LLM models available")
        selected_model = (
            model
            or config_module.DEFAULT_MODEL
            or "openrouter/deepseek/deepseek-chat"
        )
        return selected_model, model_choices


# ---------------------------------------------------------------------------
# Background task: run investigation pipeline
# ---------------------------------------------------------------------------


def _parse_rate_limit_reset(exc: Exception) -> float:
    """Extract reset timestamp from a 429 error and return seconds to wait."""
    import time, re
    exc_str = str(exc)
    # OpenRouter returns X-RateLimit-Reset as epoch milliseconds in metadata
    match = re.search(r"'X-RateLimit-Reset':\s*'?(\d{13})'?", exc_str)
    if match:
        reset_ms = int(match.group(1))
        wait = (reset_ms / 1000.0) - time.time() + 1.0  # +1s buffer
        return max(wait, 5.0)
    # Fallback: 65s to outlast a 60s/1-min rate-limit window
    return 65.0


async def _llm_with_backoff(fn, *args, max_retries: int = 4, investigation_id: "uuid.UUID | None" = None, **kwargs):
    """Run a synchronous LLM function in a thread, retrying on 429 rate-limit errors."""
    for attempt in range(max_retries):
        try:
            return await asyncio.to_thread(fn, *args, **kwargs)
        except Exception as exc:
            if "429" in str(exc) and attempt < max_retries - 1:
                wait_secs = _parse_rate_limit_reset(exc)
                logger.info(
                    "[LLM] Rate limit hit — waiting %.0fs before retry (attempt %d/%d)",
                    wait_secs, attempt + 1, max_retries,
                )
                if investigation_id is not None:
                    await _update_progress(investigation_id, label=f"Rate limited — retrying in {wait_secs:.0f}s...")
                await asyncio.sleep(wait_secs)
            else:
                raise
    raise RuntimeError("LLM max retries exceeded")


async def _run_investigation_task(
    investigation_id: str, run_id: str, query: str, model: str, run_crawler: bool
) -> None:
    """
    Background task that runs the investigation pipeline.

    The investigation DB record already exists (created by the HTTP handler) with
    status "pending".  This task updates status → processing → completed/failed.

    CRITICAL: Each DB operation uses its own short-lived session that commits
    and closes immediately. No session is held open across asyncio.to_thread()
    calls, which prevents SQLAlchemy session state corruption and connection
    pool exhaustion.

    Errors are logged — never propagated to the caller.
    """
    try:
        if not os.getenv("DATABASE_URL"):
            logger.warning("Background investigation: DATABASE_URL not set, skipping persist")
            return

        from db.models import Investigation
        from db.session import get_session, get_async_session
        from db.queries import update_investigation_summary
        from llm import filter_results, generate_summary, get_llm, refine_query
        from llm_utils import get_model_choices
        from search import _search_async as _search_engines_async, _dedupe_links as _search_dedupe, ENGINE_WEIGHTS as _engine_weights
        from scrape import scrape_multiple, validate_urls_for_scraping
        from extractor import extract_entities_from_pages

        inv_uuid = uuid.UUID(investigation_id)

        async with get_async_session() as session:
            result = await session.execute(
                sa_select(Investigation).where(Investigation.id == inv_uuid)
            )
            inv_record = result.scalar_one_or_none()
            inv_user_id = inv_record.user_id if inv_record else None

        resolved_keys = {}
        if inv_user_id is not None:
            async with get_async_session() as session:
                from utils.user_keys import resolve_api_key
                for key_name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY",
                                "OPENROUTER_API_KEY", "GROQ_API_KEY", "OTX_API_KEY", "VT_API_KEY"):
                    resolved_keys[key_name] = await resolve_api_key(inv_user_id, key_name, session)

        # ===== STEP 0: Get model choice and mark as processing =====
        selected_model, _ = await _get_investigation_model_choice(model)
        logger.info(
            "Investigation %s: using model '%s'",
            inv_uuid,
            selected_model,
        )
        await _update_investigation_status(inv_uuid, "processing", model_used=selected_model)
        await _update_progress(inv_uuid, 0)
        logger.info("[%s] Starting investigation: %s", inv_uuid, query)

        # ===== STEP 1: Query refinement (no session held) =====
        logger.info("[%s] STEP 1: Refining query...", inv_uuid)
        llm_client = None
        refined_query = query
        try:
            llm_client = get_llm(selected_model, api_keys=resolved_keys)
            refined_query = await _llm_with_backoff(refine_query, llm_client, query, investigation_id=inv_uuid)
            logger.info("[%s] Refined query: %s", inv_uuid, refined_query)
        except Exception as exc:
            logger.exception("[%s] Query refinement failed, using original query: %s", inv_uuid, exc)
            refined_query = query

        def _persist_refined_query():
            with get_session() as session:
                inv = session.query(Investigation).filter_by(id=inv_uuid).first()
                if inv:
                    inv.refined_query = refined_query
                    session.commit()

        await asyncio.to_thread(_persist_refined_query)
        await _update_progress(inv_uuid, 1)

        # ===== STEP 1.5: Multilingual Query Expansion (no session held) =====
        logger.info("[%s] STEP 1.5: Expanding query to multiple languages...", inv_uuid)
        expanded_queries: dict[str, str] = {"en": refined_query}
        try:
            from i18n.query_expand import expand_query

            expansion = expand_query(refined_query)

            if expansion and isinstance(expansion, dict) and len(expansion) > 1:
                expanded_queries = expansion
                lang_count = len(expanded_queries)
                logger.info(
                    "[%s] Query expanded to %d languages: %s",
                    inv_uuid,
                    lang_count,
                    list(expanded_queries.keys()),
                )
            else:
                logger.info("[%s] Query expansion returned no results, using English only", inv_uuid)

        except ImportError:
            logger.info("[%s] i18n module not available, using English only", inv_uuid)
        except Exception as e:
            logger.info("[%s] Query expansion failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 2, 3.5, 4: Parallel Pipeline =====
        logger.info("[%s] STEP 2/3.5/4: Launching Search, Enrichment, and Crawler concurrently...", inv_uuid)

        async def run_search_and_filter() -> list:
            logger.info("[%s] STEP 2: Searching dark web...", inv_uuid)
            
            async def search_single_language(lang_code: str, q: str) -> list[dict]:
                search_query = q.replace(" ", "+")
                logger.info("[%s] Searching [%s]: %s...", inv_uuid, lang_code, search_query[:60])
                try:
                    engine_results = await _search_engines_async(search_query)
                    all_links: list[dict] = []
                    for er in engine_results:
                        weight = 0.5
                        for known in _engine_weights:
                            if known in er.name.lower():
                                weight = _engine_weights[known]
                                break
                        for link in er.links:
                            link["source_engine"] = er.name
                            link["source_weight"] = weight
                            all_links.append(link)
                    lang_results = _search_dedupe(all_links)
                    lang_results.sort(key=lambda r: r.get("source_weight", 0.5), reverse=True)
                    for result in lang_results:
                        result["search_language"] = lang_code
                    return lang_results
                except Exception as e:
                    logger.info("[%s] [%s] search failed: %s", inv_uuid, lang_code, e)
                    return []

            search_tasks = [
                search_single_language(lang, q)
                for lang, q in expanded_queries.items()
            ]
            try:
                results_by_language = await asyncio.wait_for(
                    asyncio.gather(*search_tasks, return_exceptions=True),
                    timeout=180,
                )
            except asyncio.TimeoutError:
                logger.warning("[%s] Multilingual search timed out after 180s, using partial results", inv_uuid)
                results_by_language = []

            all_search_results = []
            seen_urls = set()
            for lang_results in results_by_language:
                if isinstance(lang_results, Exception):
                    continue
                for result in lang_results:
                    url = result.get("link", "")
                    normalized = url.lower().rstrip("/").replace("https://", "http://")
                    if normalized and normalized not in seen_urls:
                        seen_urls.add(normalized)
                        all_search_results.append(result)

            search_results = all_search_results
            logger.info("[%s] Total search results: %d (from %d languages)", inv_uuid, len(search_results), len(expanded_queries))

            if not search_results:
                logger.info("[%s] WARNING: No search results from any language", inv_uuid)

            logger.info("[%s] STEP 3: Filtering results...", inv_uuid)
            if llm_client is None:
                filtered_results = list(search_results[:100])
                logger.info("[%s] LLM unavailable; fallback to top %s search results", inv_uuid, len(filtered_results))
            else:
                try:
                    filtered_results = await _llm_with_backoff(filter_results, llm_client, refined_query, search_results, investigation_id=inv_uuid)
                except Exception as exc:
                    logger.exception("[%s] Filter step failed, falling back: %s", inv_uuid, exc)
                    filtered_results = list(search_results[:100])
            logger.info("[%s] Filtered to %s results", inv_uuid, len(filtered_results))
            
            _urls_to_scrape = list(filtered_results)
            if len(_urls_to_scrape) < 100:
                current_links = {res.get("link") for res in _urls_to_scrape if res.get("link")}
                for res in search_results:
                    if res.get("link") not in current_links:
                        _urls_to_scrape.append(res)
                        current_links.add(res.get("link"))
                    if len(_urls_to_scrape) >= 150:
                        break
            return _urls_to_scrape

        async def run_enrichment() -> list:
            logger.info("[%s] STEP 3.5: Running threat intel enrichment...", inv_uuid)
            try:
                from sources.enrichment import enrich_investigation
                from config import OTX_API_KEY

                # Always try original query; add refined only if different
                queries_to_enrich = [query]
                if refined_query and refined_query.strip().lower() != query.strip().lower():
                    queries_to_enrich.append(refined_query)

                all_pages: list = []
                seen_urls: set = set()
                for eq in queries_to_enrich:
                    try:
                        batch = await enrich_investigation(
                            query=eq,
                            otx_api_key=resolved_keys.get("OTX_API_KEY") or "",
                        )
                        for p in batch:
                            u = p.get("url") or p.get("link") or ""
                            if u not in seen_urls:
                                seen_urls.add(u)
                                all_pages.append(p)
                    except Exception as exc:
                        logger.info("[%s] Enrichment batch failed for '%s': %s", inv_uuid, eq, exc)

                logger.info("[%s] Enrichment: %s pages (tried %s queries)", inv_uuid, len(all_pages), len(queries_to_enrich))
                return all_pages
            except Exception as exc:
                logger.info("[%s] Enrichment failed (non-fatal): %s", inv_uuid, exc)
                return []

        async def run_crawler_task() -> list:
            if not run_crawler:
                logger.info("[%s] STEP 4: Crawler disabled", inv_uuid)
                return []
            try:
                logger.info("[%s] STEP 4: Running recursive crawler...", inv_uuid)
                seeds = await asyncio.to_thread(get_seeds, category="index", query=refined_query)
                seed_urls = [seed["url"] for seed in seeds if seed.get("url")]
                crawler_result = await crawl(seed_urls=seed_urls, query=refined_query, max_depth=2, max_pages=50)
                logger.info("[%s] Crawler: %s pages, %s failed", inv_uuid, crawler_result.pages_crawled, crawler_result.pages_failed)
                return [{"link": item.get("url", ""), "title": "Crawler discovery"} 
                        for item in crawler_result.results if isinstance(item, dict) and item.get("url")]
            except Exception as exc:
                logger.exception("[%s] Crawler failed: %s", inv_uuid, str(exc))
                return []

        search_urls, enrichment_pages, crawler_urls = await asyncio.gather(
            run_search_and_filter(),
            run_enrichment(),
            run_crawler_task()
        )
        await _update_progress(inv_uuid, 2)

        if len(search_urls) < 2:
            logger.warning(
                "[%s] Filtered results too small (%s INTELLIGENCE pages). "
                "Query may have returned only directory/index pages. "
                "Try a more specific query.",
                inv_uuid,
                len(search_urls),
            )
            no_result_summary = (
                f"Investigation for '{refined_query}' completed but found insufficient "
                f"intelligence content. Only {len(search_urls)} qualifying page(s) remained "
                f"after filtering out directory/index pages. This suggests the query "
                f"returned primarily link aggregators or marketplace indexes rather than "
                f"actual threat intelligence content. Try a more specific, targeted query "
                f"(e.g., specific malware names, actor handles, or infrastructure indicators) "
                f"instead of broad topic searches."
            )
            with get_session() as session:
                session.query(Investigation).filter_by(id=inv_uuid).update(
                    {"status": "completed_no_results", "summary": no_result_summary, "graph_status": "no_data"}
                )
                session.commit()
            logger.info("[%s] Investigation COMPLETED_NO_RESULTS (run_id=%s)", inv_uuid, run_id)
            return

        # Seed .onion leak-site URLs discovered by enrichment (e.g. ransomware.live)
        # into the scrape queue so they get visited even if search engines didn't find them
        enrichment_onion_seeds = [
            {"link": p.get("link") or p.get("url"), "title": p.get("title", "Enrichment seed")}
            for p in enrichment_pages
            if p.get("_scrape_seed") and ".onion" in (p.get("link") or p.get("url") or "")
        ]
        if enrichment_onion_seeds:
            logger.info(
                "[%s] Adding %d .onion seeds from enrichment to scrape queue",
                inv_uuid, len(enrichment_onion_seeds),
            )

        all_urls_to_scrape = search_urls + crawler_urls + enrichment_onion_seeds
        logger.info("[%s] Total URLs after crawler+enrichment seeds: %s", inv_uuid, len(all_urls_to_scrape))

        if enrichment_pages:
            try:
                from vector.store import store_page
                for ep in enrichment_pages:
                    u = ep.get("url") or ep.get("link") or ""
                    t = ep.get("text") or ep.get("content") or ""
                    if u and t:
                        store_page(url=u, content=t, metadata={"source": ep.get("source", "enrichment")})
            except Exception:
                pass

        # ===== STEP 4.5: Vector Cache Lookup (no session held) =====
        logger.info(
            "[%s] STEP 4.5: Checking vector cache for %d URLs...",
            inv_uuid,
            len(all_urls_to_scrape),
        )
        cached_dict: dict = {}
        uncached_url_dicts = list(all_urls_to_scrape)
        try:
            from vector.store import bulk_check_cache

            url_strings = [
                u.get("link", u) if isinstance(u, dict) else str(u)
                for u in all_urls_to_scrape
            ]
            cached_pages_list, urls_needing_scrape = bulk_check_cache(
                url_strings, max_age_hours=24
            )
            cached_dict = {p["link"]: p["content"] for p in cached_pages_list}
            uncached_set = set(urls_needing_scrape)
            uncached_url_dicts = [
                u for u in all_urls_to_scrape
                if (u.get("link", u) if isinstance(u, dict) else str(u))
                in uncached_set
            ]
            logger.info(
                "[%s] Cache: %d hits, %d misses (need Tor)",
                inv_uuid,
                len(cached_dict),
                len(uncached_url_dicts),
            )
        except Exception as exc:
            logger.info("[%s] Cache check failed (non-fatal): %s", inv_uuid, exc)
            cached_dict = {}
            uncached_url_dicts = list(all_urls_to_scrape)

        # ===== STEP 5: Scraping (no session held) =====
        uncached_url_dicts, ssrf_blocked = validate_urls_for_scraping(uncached_url_dicts)
        if ssrf_blocked:
            logger.info(
                "[%s] SSRF: blocked %d unsafe URLs",
                inv_uuid,
                len(ssrf_blocked),
            )
        logger.info(
            "[%s] STEP 5: Scraping %d URLs (skipped %d cached)...",
            inv_uuid,
            len(uncached_url_dicts),
            len(cached_dict),
        )
        freshly_scraped = await scrape_multiple(uncached_url_dicts, max_workers=12)
        await _update_progress(inv_uuid, 4, scraped_pages=freshly_scraped)

        # ===== STEP 5.5: Store new pages in vector cache (no session held) =====
        try:
            from vector.store import store_page

            stored_count = 0
            for page_url, page_text in freshly_scraped.items():
                if page_text and len(page_text) > 100:
                    if store_page(url=page_url, content=page_text, metadata={"source": "scraper"}):
                        stored_count += 1
            logger.info("[%s] Stored %d new pages in vector cache", inv_uuid, stored_count)
        except Exception as exc:
            logger.info("[%s] Cache store failed (non-fatal): %s", inv_uuid, exc)

        scraped_pages = {**cached_dict, **freshly_scraped}
        scraped_count = len(scraped_pages)
        logger.info(
            "[%s] Total for extraction: %d pages (%d cached + %d fresh)",
            inv_uuid,
            scraped_count,
            len(cached_dict),
            len(freshly_scraped),
        )

        page_records = [
            {"url": page_url, "text": page_text, "content": page_text}
            for page_url, page_text in scraped_pages.items()
        ]

        if enrichment_pages:
            enrichment_count = 0
            for ep in enrichment_pages:
                u = ep.get("url") or ep.get("link") or ""
                t = ep.get("text") or ep.get("content") or ""
                if u and (t or "").strip():
                    page_records.append({"url": u, "text": t, "content": t})
                    enrichment_count += 1

            logger.info(
                "[%s] Total pages for extraction: %s (%s scraped + %s enrichment)",
                inv_uuid,
                len(page_records),
                scraped_count,
                enrichment_count,
            )
        else:
            logger.info(
                "[%s] Total pages for extraction: %s (%s scraped + 0 enrichment)",
                inv_uuid,
                len(page_records),
                scraped_count,
            )

        non_empty_records = [r for r in page_records if len((r.get("text") or "").strip()) > 100]
        logger.info("[%s] Non-empty pages (>100 chars): %s", inv_uuid, len(non_empty_records))
        if not non_empty_records:
            first_length = len(page_records[0].get("text", "")) if page_records else 0
            logger.info("[%s] WARNING: All scraped pages are empty/short", inv_uuid)
            logger.info("[%s] First page content length: %s", inv_uuid, first_length)

        # ===== STEP 5.7: Detect content languages (no session held) =====
        try:
            from i18n.detect import detect_language

            lang_distribution: dict[str, int] = {}
            for page in page_records:
                text = page.get("content") or page.get("text") or ""
                if len(text) >= 50:
                    lang = detect_language(text[:500])
                    if lang:
                        lang_distribution[lang] = lang_distribution.get(lang, 0) + 1

            if lang_distribution:
                total_pages = sum(lang_distribution.values())
                non_english = {k: v for k, v in lang_distribution.items() if k != "en"}
                logger.info(
                    "[%s] Content languages: %s (%d/%d non-English pages)",
                    inv_uuid,
                    lang_distribution,
                    sum(non_english.values()),
                    total_pages,
                )
        except Exception as e:
            logger.info("[%s] Language detection failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 6: Entity extraction (no session held) =====
        logger.info("[%s] STEP 6: Extracting entities...", inv_uuid)
        extraction_input = non_empty_records if non_empty_records else page_records
        try:
            extraction_results = await extract_entities_from_pages(
                extraction_input,
                investigation_id=inv_uuid,
                llm=llm_client,
                run_llm_extraction=True,
            )
            total_entities = sum(r.entity_count for r in extraction_results)
            logger.info("[%s] Extracted %s entities", inv_uuid, total_entities)
            if total_entities == 0:
                logger.info("[%s] WARNING: No entities extracted", inv_uuid)
                logger.info(
                    "[%s] Pages passed to extractor: %s",
                    inv_uuid,
                    len(extraction_input),
                )
        except Exception as exc:
            logger.exception("[%s] Extraction failed: %s", inv_uuid, str(exc))
            extraction_results = []
            total_entities = 0

        await _update_progress(inv_uuid, 5, extracted_entities=extraction_results)

        # ===== STEP 6.5: Cross-reference against seed data (short-lived session) =====
        logger.info("[%s] STEP 6.5: Cross-referencing with historical data...", inv_uuid)
        try:
            from db.queries import cross_reference_with_seeds

            with get_session() as session:
                seed_matches = cross_reference_with_seeds(session, inv_uuid)
                logger.info("[%s] Found %s historical matches", inv_uuid, seed_matches)
        except Exception as e:
            logger.info("[%s] Cross-reference failed (non-fatal): %s", inv_uuid, e)

        # ===== STEP 6.6: Build Stylometry Profiles (wrapped in to_thread with own session) =====
        logger.info(f"[{inv_uuid}] STEP 6.6: Building actor style profiles...")
        try:
            profiles_built = await asyncio.to_thread(
                _build_investigation_profiles,
                inv_uuid,
            )
            logger.info(f"[{inv_uuid}] Built {profiles_built} actor profiles")
        except Exception as e:
            logger.info(f"[{inv_uuid}] Profile building failed (non-fatal): {e}")

        # ===== STEP 6.7: Blockchain Wallet Enrichment (wrapped in to_thread with own session) =====
        logger.info(f"[{inv_uuid}] STEP 6.7: Enriching wallet entities...")
        try:
            from sources.blockchain import enrich_wallets_for_investigation
            from config import BLOCKCYPHER_TOKEN, ETHERSCAN_API_KEY

            blockchain_stats = await asyncio.to_thread(
                _enrich_wallets_sync,
                inv_uuid,
                BLOCKCYPHER_TOKEN,
                ETHERSCAN_API_KEY,
            )

            logger.info(
                f"[{inv_uuid}] Blockchain enrichment: "
                f"{blockchain_stats['successful_lookups']}/{blockchain_stats['wallets_looked_up']} lookups successful, "
                f"{blockchain_stats['edges_created']} PAID_TO edges created, "
                f"{blockchain_stats['connected_wallets_found']} connected wallets found"
            )
        except Exception as e:
            logger.info(f"[{inv_uuid}] Blockchain enrichment failed (non-fatal): {e}")

        await _update_progress(inv_uuid, 6)

        # ===== STEP 7: Graph building (wrapped in to_thread with own session) =====
        logger.info("[%s] STEP 7: Building graph...", inv_uuid)
        try:
            from graph.builder import build_graph_from_db, persist_graph_edges

            graph_obj = await asyncio.to_thread(build_graph_from_db, investigation_id=inv_uuid)
            node_count = len(graph_obj.nodes())
            edge_count = len(graph_obj.edges())
            logger.info(
                "[%s] Graph: %s nodes, %s edges",
                inv_uuid,
                node_count,
                edge_count,
            )

            try:
                persist_result = await asyncio.to_thread(
                    _persist_graph_edges_sync,
                    graph_obj,
                    inv_uuid,
                )
                graph_status = persist_result.get("status", "written")
                edges_written = persist_result.get("edges_written", 0)
                logger.info(
                    "[%s] Graph edges persisted: %s (%s)",
                    inv_uuid,
                    edges_written,
                    graph_status,
                )

                new_graph_status = "skipped_overflow" if graph_status == "skipped_overflow" else "built"
                with get_session() as session:
                    session.query(Investigation).filter_by(id=inv_uuid).update(
                        {"graph_status": new_graph_status}
                    )
                    session.commit()
            except Exception as e:
                logger.info("[%s] Edge persistence failed (non-fatal): %s", inv_uuid, e)

        except Exception as exc:
            logger.exception("[%s] Graph building failed: %s", inv_uuid, str(exc))

        await _update_progress(inv_uuid, 7)

        # ===== STEP 8: Summary (no session held) =====
        logger.info("[%s] STEP 8: Generating summary (%d pages available)...", inv_uuid, len(page_records))
        if llm_client is None:
            summary = (
                f"Investigation completed without LLM summary. "
                f"Scraped {scraped_count} pages; extracted {total_entities} entities."
            )
        else:
            try:
                summary_entities = []
                if extraction_results:
                    for result in extraction_results:
                        summary_entities.extend(result.entities)

                summary = await _llm_with_backoff(
                    generate_summary,
                    llm=llm_client,
                    query=refined_query,
                    content=page_records,
                    entities=summary_entities if summary_entities else None,
                    investigation_id=inv_uuid,
                )
                logger.info("[%s] Summary generated (%d chars)", inv_uuid, len(summary or ""))
            except Exception as exc:
                logger.exception("[%s] Summary generation failed, using fallback summary: %s", inv_uuid, exc)
                summary = (
                    f"Investigation complete for '{refined_query}'. "
                    f"Analysis pipeline completed successfully, but summary generation failed: {exc}."
                )

        logger.info("[%s] Summary preview: %s", inv_uuid, (summary or "")[:100])

        await _update_progress(inv_uuid, 8)

        # ===== Final: Update summary and mark completed (short-lived session) =====
        with get_session() as session:
            update_investigation_summary(session, inv_uuid, summary)
            session.query(Investigation).filter_by(id=inv_uuid).update(
                {"status": "completed"}
            )
            session.commit()
        await _update_progress(inv_uuid, 9)
        logger.info("[%s] Investigation COMPLETED (run_id=%s)", inv_uuid, run_id)

    except Exception as exc:
        logger.exception("[%s] Investigation FAILED with exception: %s", investigation_id, exc)
        try:
            from db.models import Investigation
            from db.session import get_session

            with get_session() as session:
                session.query(Investigation).filter_by(id=uuid.UUID(investigation_id)).update(
                    {"status": "failed", "summary": f"Investigation failed: {exc!s}"[:500]}
                )
                session.commit()
        except Exception as update_exc:
            logger.warning("Failed to persist investigation failure status: %s", update_exc)


def _enrich_wallets_sync(investigation_id, blockcypher_token, etherscan_key):
    """Sync wrapper for blockchain enrichment - creates its own session."""
    from sources.blockchain import enrich_wallets_for_investigation
    from db.session import get_session

    with get_session() as session:
        return enrich_wallets_for_investigation(
            investigation_id=investigation_id,
            session=session,
            blockcypher_token=blockcypher_token,
            etherscan_key=etherscan_key,
            max_wallets=10,
        )


def _persist_graph_edges_sync(graph_obj, investigation_id):
    """Sync wrapper for graph edge persistence - creates its own session."""
    from graph.builder import persist_graph_edges
    from db.session import get_session

    with get_session() as session:
        return persist_graph_edges(
            graph_obj,
            investigation_id,
            session,
        )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post("")
@_rate_limit("3/minute")
async def create_investigation(
    request: Request,
    body: InvestigationRequest,
    background_tasks: BackgroundTasks,
    current_user: CurrentUser = Depends(get_current_user),
) -> dict:
    """Trigger an investigation asynchronously.

    Creates the investigation row in the DB synchronously before returning so
    that GET /investigations/{run_id} returns a valid record immediately while
    the background pipeline runs.
    """

    run_id = str(uuid.uuid4())

    if os.getenv("DATABASE_URL"):
        try:
            from db.session import get_session
            from db.queries import create_investigation as db_create

            with get_session() as session:
                inv = db_create(session, query=body.query, user_id=current_user.user.id)
                inv.run_id = uuid.UUID(run_id)
                inv.status = "pending"
                session.commit()
                investigation_id = str(inv.id)
        except Exception as exc:
            logger.exception("Failed to create investigation record: %s", exc)
            raise HTTPException(
                status_code=500,
                detail=f"Could not persist investigation: {exc!s}"[:300],
            )
    else:
        investigation_id = str(uuid.uuid4())

    background_tasks.add_task(
        _run_investigation_task,
        investigation_id=investigation_id,
        run_id=run_id,
        query=body.query,
        model=body.model,
        run_crawler=body.run_crawler,
    )
    return {"run_id": run_id, "status": "pending", "query": body.query}


@router.get("")
async def list_investigations(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[dict]:
    """Return a paginated list of investigation summaries."""
    if not os.getenv("DATABASE_URL"):
        return []
    try:
        from db.session import get_session
        from db.models import Investigation

        with get_session() as session:
            invs = (
                session.query(Investigation)
                .filter(Investigation.is_seed == False)
                .order_by(Investigation.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": str(inv.id),
                    "run_id": str(inv.run_id),
                    "query": inv.query,
                    "status": inv.status,
                    "model_used": inv.model_used,
                    "created_at": inv.created_at.isoformat() if inv.created_at else None,
                    "entity_count": inv.entity_count or 0,
                    "page_count": inv.page_count or 0,
                }
                for inv in invs
            ]
    except Exception as exc:
        logger.exception("list_investigations failed: %s", exc)
        return []


@router.get("/{investigation_id}/progress")
async def investigation_progress(
    investigation_id: str,
    current_user: "CurrentUser" = Depends(get_current_user),
) -> StreamingResponse:
    """
    SSE stream of investigation pipeline progress.
    Emits step updates every 5 seconds until a terminal state is reached.
    """
    from db.session import get_session
    from db.models import Investigation

    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    async def event_stream():
        last_step = None
        last_status = None
        timeout_count = 0
        max_timeout = 360

        while timeout_count < max_timeout:
            try:
                with get_session() as session:
                    inv = session.query(Investigation).filter_by(id=inv_uuid).first()
            except Exception:
                break

            if inv is None:
                break

            current_step = getattr(inv, "current_step", 0) or 0
            current_status = getattr(inv, "status", "unknown")
            step_label = getattr(inv, "current_step_label", "") or ""
            progress_pct = int((current_step / 13) * 100)

            if current_step != last_step or current_status != last_status:
                data = {
                    "step": current_step,
                    "step_label": step_label,
                    "progress": progress_pct,
                    "status": current_status,
                    "entity_count": getattr(inv, "entity_count", 0) or 0,
                    "page_count": getattr(inv, "page_count", 0) or 0,
                }
                yield f"data: {json.dumps(data)}\n\n"
                last_step = current_step
                last_status = current_status

            if current_status in ("completed", "failed", "completed_no_results"):
                yield f"data: {json.dumps({**data, 'done': True})}\n\n"
                break

            timeout_count += 1
            await asyncio.sleep(5)

        yield ": stream closed\n\n"

    with get_session() as session:
        inv = session.query(Investigation).filter_by(id=inv_uuid).first()
        if inv is None:
            raise HTTPException(status_code=404, detail="Investigation not found")

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{investigation_id}/analysis/temporal")
async def get_temporal_analysis(investigation_id: str) -> dict:
    """
    Run temporal analysis on pages from this investigation.

    Returns activity patterns by hour/day, anomalies, and silence breaks.
    Returns {"error": "insufficient_data"} (not 500) when there is not enough data.
    """
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        from db.session import get_session
        from db.models import Entity, Page
        from db.queries import get_investigation_by_id_or_run
        from collections import defaultdict
        from analysis.temporal import detect_anomalies, detect_silence_breaks, Z_SCORE_THRESHOLD

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")

            entities = session.query(Entity).filter(
                Entity.investigation_id == inv.id
            ).all()

            if not entities:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": "No entities found for this investigation",
                }

            page_ids = list({e.page_id for e in entities if e.page_id is not None})
            if not page_ids:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": "No page timestamps available",
                }

            pages = session.query(Page).filter(Page.id.in_(page_ids)).all()
            real_post_ts = sum(1 for p in pages if p.posted_at is not None)
            skipped_no_posted_at = len(pages) - real_post_ts
            if skipped_no_posted_at > 0:
                logger.debug(
                    "Temporal analysis: skipped %d pages due to missing posted_at (using content timestamp, not scrape time)",
                    skipped_no_posted_at,
                )
            timestamps = []
            for p in pages:
                if p.posted_at is not None:
                    timestamps.append(p.posted_at)

            if len(timestamps) < 3:
                return {
                    "investigation_id": investigation_id,
                    "error": "insufficient_data",
                    "message": f"Only {len(timestamps)} timestamps available (minimum 3)",
                    "data_points": len(timestamps),
                }

            by_hour: dict[int, int] = defaultdict(int)
            for ts in timestamps:
                by_hour[ts.hour] += 1
            activity_by_hour = {str(h): int(by_hour.get(h, 0)) for h in range(24)}

            day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
            by_day: dict[int, int] = defaultdict(int)
            for ts in timestamps:
                by_day[ts.weekday()] += 1
            activity_by_day = {day_names[d]: int(by_day.get(d, 0)) for d in range(7)}

            peak_hour_key = max(activity_by_hour, key=lambda h: activity_by_hour[h], default=None)
            peak_day_key = max(activity_by_day, key=lambda d: activity_by_day[d], default=None)

            daily_counts: dict = defaultdict(int)
            for ts in timestamps:
                daily_counts[ts.date()] += 1
            timeline = [
                {"date": d, "count": c} for d, c in sorted(daily_counts.items())
            ]

            anomalies_raw = detect_anomalies(timeline, z_threshold=Z_SCORE_THRESHOLD)
            anomalies = [
                {
                    "date": str(a["date"]),
                    "count": a["count"],
                    "z_score": round(a["z_score"], 2),
                    "type": a["type"],
                    "description": (
                        f"Activity {'spike' if a['z_score'] > 0 else 'drop'}: "
                        f"z-score {a['z_score']:.1f}"
                    ),
                }
                for a in anomalies_raw
            ]

            silence_raw = detect_silence_breaks(timeline, silence_days=7)
            silence_breaks = [
                {
                    "before": str(s["silent_from"]),
                    "after": str(s["silent_to"]),
                    "gap_days": s["gap_days"],
                    "significance": "high" if s["gap_days"] >= 14 else "medium",
                }
                for s in silence_raw
            ]

            all_dates = sorted(daily_counts.keys())
            timespan_days = (
                (all_dates[-1] - all_dates[0]).days if len(all_dates) >= 2 else 0
            )

            return {
                "investigation_id": investigation_id,
                "activity_by_hour": activity_by_hour,
                "activity_by_day": activity_by_day,
                "anomalies": anomalies,
                "silence_breaks": silence_breaks,
                "peak_hour": int(peak_hour_key) if peak_hour_key is not None else None,
                "peak_day": peak_day_key,
                "total_timespan_days": timespan_days,
                "data_points": len(timestamps),
            }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_temporal_analysis failed: %s", exc)
        return {"error": "analysis_failed", "message": str(exc)[:300]}


@router.get("/{investigation_id}")
async def get_investigation(investigation_id: str) -> dict:
    """Return full investigation record including entity count. 404 if not found."""
    return _get_db_investigation(investigation_id)


@router.get("/{investigation_id}/entities")
async def get_investigation_entities(
    investigation_id: str,
    entity_type: Optional[str] = Query(default=None),
    min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
) -> dict:
    """Return paginated entities for an investigation, optionally filtered by type and confidence."""
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")
    try:
        from db.session import get_session
        from db.models import Entity, InvestigationEntityLink
        from db.queries import get_investigation_by_id_or_run
        from graph.builder import _make_node_id
        from sqlalchemy import func

        inv_uuid = uuid.UUID(investigation_id)
        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")

            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            query = session.query(Entity).filter(
                (Entity.investigation_id == inv.id)
                | Entity.id.in_(linked_ids_subq)
            )
            if entity_type:
                query = query.filter(Entity.entity_type == entity_type)
            if min_confidence > 0.0:
                query = query.filter(Entity.confidence >= min_confidence)

            total = query.count()
            entities = (
                query.order_by(Entity.created_at.desc())
                .offset(offset)
                .limit(limit)
                .all()
            )

            out: list[dict] = []
            for e in entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass
                graph_node_id = _make_node_id(e.entity_type, e.value, source_url)
                out.append(
                    {
                        "id": str(e.id),
                        "entity_type": e.entity_type,
                        "value": e.value,
                        "confidence": e.confidence,
                        "context": e.context,
                        "created_at": e.created_at.isoformat() if e.created_at else None,
                        "first_seen": e.first_seen.isoformat() if e.first_seen else None,
                        "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                        "graph_node_id": graph_node_id,
                    }
                )
            return {"items": out, "total": total, "skip": offset, "limit": limit}
    except HTTPException:
        raise
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")
    except Exception as exc:
        logger.exception("get_investigation_entities failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {exc!s}"[:500],
        )


@router.get("/{investigation_id}/entities/export/csv")
async def export_investigation_entities_csv(
    investigation_id: str,
) -> Response:
    """
    Export entities for an investigation as a CSV file download.

    Returns CSV with columns: entity_type, canonical_value, confidence,
    occurrence_count, first_seen_page, context_snippet
    """
    if not os.getenv("DATABASE_URL"):
        raise HTTPException(status_code=503, detail="Database not configured")

    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    try:
        from db.session import get_session
        from db.models import Entity, InvestigationEntityLink
        from db.queries import get_investigation_by_id_or_run
        from sqlalchemy import func

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")

            linked_ids_subq = (
                session.query(InvestigationEntityLink.entity_id)
                .filter(InvestigationEntityLink.investigation_id == inv.id)
                .subquery()
            )
            entities = (
                session.query(Entity)
                .filter(
                    (Entity.investigation_id == inv.id)
                    | Entity.id.in_(linked_ids_subq)
                )
                .all()
            )

            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "entity_type",
                "canonical_value",
                "confidence",
                "occurrence_count",
                "first_seen_page",
                "context_snippet",
            ])

            for e in entities:
                source_url = ""
                try:
                    if e.page:
                        source_url = e.page.url or ""
                except Exception:
                    pass
                context = (e.context_snippet or "").replace(
                    "\n", " "
                ).replace(
                    "\r", " "
                ).strip()
                writer.writerow([
                    e.entity_type,
                    e.canonical_value or e.value,
                    e.confidence,
                    1,
                    source_url,
                    context[:500],
                ])

            csv_content = output.getvalue()

        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=voidaccess_{investigation_id}_entities.csv"
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("export_investigation_entities_csv failed: %s", exc)
        raise HTTPException(
            status_code=500,
            detail=f"Internal error: {exc!s}"[:500],
        )


MAX_GRAPH_NODES = 500


@router.get("/{investigation_id}/graph")
async def get_investigation_graph(
    investigation_id: str,
    force_rebuild: bool = False,
    max_nodes: int = Query(default=MAX_GRAPH_NODES, ge=1, le=MAX_GRAPH_NODES),
    min_confidence: float = Query(default=0.75, ge=0.0, le=1.0),
) -> dict:
    """
    Return graph JSON for the investigation.

    Requires investigation_id (now enforced - no more global graph).
    Uses persisted edges from the DB with O(1) lookup.

    Use ?force_rebuild=true to recompute from scratch.
    Use ?max_nodes=N to limit node count (default 500, max 500).
    Use ?min_confidence=N to filter nodes/edges by confidence (default 0.75).
    Returns 400 if node count exceeds max_nodes - filter by entity type first.
    Returns 200 with {"graph_status": "skipped_overflow", ...} if graph was skipped due to size.
    """
    try:
        inv_uuid = uuid.UUID(investigation_id)
    except ValueError:
        raise HTTPException(status_code=422, detail="Invalid investigation ID format")

    try:
        from db.session import get_session
        from db.queries import get_investigation_by_id_or_run
        from graph.builder import build_graph_from_db, build_graph_from_db_cached
        from graph.export import to_json
        from db.models import EntityRelationship, Entity
        from sqlalchemy import func

        with get_session() as session:
            inv = get_investigation_by_id_or_run(session, inv_uuid)
            if inv is None:
                raise HTTPException(status_code=404, detail="Investigation not found")
            internal_id = inv.id
            graph_status = getattr(inv, "graph_status", "pending")

            if graph_status == "skipped_overflow":
                entity_count = (
                    session.query(func.count(Entity.id))
                    .filter(Entity.investigation_id == internal_id)
                    .scalar() or 0
                )
                return {
                    "graph_status": "skipped_overflow",
                    "message": "Graph too large to render. Use the entity list or download the CSV export instead.",
                    "total_entities": entity_count,
                    "nodes": [],
                    "edges": [],
                }

            persisted_edge_count = (
                session.query(func.count(EntityRelationship.id))
                .filter(EntityRelationship.investigation_id == internal_id)
                .scalar() or 0
            )

            total_entity_count = (
                session.query(func.count(Entity.id))
                .filter(Entity.investigation_id == internal_id)
                .scalar() or 0
            )

        if persisted_edge_count > 0 and not force_rebuild:
            logger.debug(
                "Graph cache hit: %s edges from DB for investigation %s",
                persisted_edge_count,
                investigation_id,
            )
            graph = build_graph_from_db_cached(investigation_id=internal_id)
        else:
            graph = build_graph_from_db(investigation_id=internal_id)

        node_count = len(graph.nodes)
        if node_count > max_nodes:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Graph has {node_count} nodes, exceeds max_nodes={max_nodes}. "
                    "Filter by entity type first using the /entities endpoint "
                    "with entity_type filter, then rebuild the graph."
                ),
            )

        graph_data = to_json(graph)

        nodes_to_keep = set()
        total_entities = len(graph_data["nodes"])
        for node in graph_data["nodes"]:
            node_confidence = node.get("confidence", 0.0)
            if node_confidence >= min_confidence:
                nodes_to_keep.add(node["id"])

        filtered_nodes = [n for n in graph_data["nodes"] if n["id"] in nodes_to_keep]
        filtered_edges = [
            e for e in graph_data["edges"]
            if e["source"] in nodes_to_keep and e["target"] in nodes_to_keep
        ]

        return {
            "graph_status": graph_status,
            "total_entities": total_entities,
            "filtered_entities": len(filtered_nodes),
            "min_confidence": min_confidence,
            "nodes": filtered_nodes,
            "edges": filtered_edges,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("get_investigation_graph failed: %s", exc)
        return {"nodes": [], "edges": []}


def _build_investigation_profiles(investigation_id) -> int:
    """
    For each THREAT_ACTOR entity in this investigation,
    build/update their style profile from available text.

    Uses context_snippets collected across all appearances
    of the same canonical entity.

    NOTE: This function creates its own session - never pass a session
    across thread boundaries.
    """
    from db.models import Entity
    from db.session import get_session
    from fingerprint.profiler import build_actor_profile, save_profile_to_db
    from sqlalchemy import func

    count = 0
    with get_session() as session:
        actors = (
            session.query(Entity.canonical_value, Entity.entity_type)
            .filter(
                Entity.investigation_id == investigation_id,
                Entity.entity_type.in_(["THREAT_ACTOR", "THREAT_ACTOR_HANDLE", "MALWARE_FAMILY", "RANSOMWARE_GROUP"]),
                Entity.canonical_value.isnot(None),
            )
            .distinct()
            .all()
        )

        for canonical_value, entity_type in actors:
            texts = (
                session.query(Entity.context_snippet)
                .filter(
                    Entity.entity_type == entity_type,
                    Entity.canonical_value == canonical_value,
                    Entity.context_snippet.isnot(None),
                    func.length(Entity.context_snippet) >= 50,
                )
                .all()
            )

            text_list = [t[0] for t in texts if t[0]]
            total_chars = sum(len(t) for t in text_list)

            if len(text_list) < 2 or total_chars < 200:
                continue

            try:
                profile = build_actor_profile(text_list)
                if profile:
                    save_profile_to_db(
                        profile=profile,
                        canonical_value=canonical_value,
                        entity_type=entity_type,
                        session=session,
                    )
                    count += 1
            except Exception as e:
                logger.debug(f"Profile build failed for {canonical_value}: {e}")
                continue

        session.commit()

    return count
