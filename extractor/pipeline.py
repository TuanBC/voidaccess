"""
extractor/pipeline.py — Pipeline orchestrator for entity extraction.

Single entry point that the rest of the system calls.  Runs:
    1. Regex extraction  (extractor/regex_patterns.py)
    2. NER extraction    (extractor/ner.py)
    3. LLM extraction    (extractor/llm_extract.py)  — optional
    4. Normalisation     (extractor/normalizer.py)
    5. DB persistence    (extractor/normalizer.merge_with_db)

Public interface
----------------
async extract_entities_from_page(...)   → ExtractionResult
async extract_entities_from_pages(...)  → list[ExtractionResult]

ExtractionResult is a dataclass exported through extractor/__init__.py.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
import uuid

from extractor.regex_patterns import extract_all as _regex_extract_all
from extractor.ner import extract_named_entities as _ner_extract
from extractor.llm_extract import extract_with_llm as _llm_extract
from extractor.normalizer import (
    normalize_entities as _normalize,
    merge_with_db as _merge_db,
    NormalizedEntity,
    resolve_entity_type_conflicts as _resolve_conflicts,
    _REGEX_TYPES as _HIGH_CONFIDENCE_REGEX_TYPES,
)

logger = logging.getLogger(__name__)

PER_TYPE_CAPS = {
    "ORGANIZATION_NAME": 50,
    "PERSON_NAME": 30,
    "LOCATION": 20,
    "THREAT_ACTOR_HANDLE": 80,
}

# ---------------------------------------------------------------------------
# LLM-extraction page selection
# ---------------------------------------------------------------------------
#
# `extract_entities_from_pages` is invoked on 15-22 pages per investigation
# and each page is chunked into ~3 LLM calls, yielding 45-66 LLM calls per
# investigation.  That's expensive.  We pre-score the pages and only run the
# LLM tier on the top `max_llm_pages` of them.
#
# Score components (higher = LLM adds more value):
#   - low regex entity count (< 3 entities)        +10.0  (LLM can fill gaps)
#   - text content length 500+ chars                up to +5.0
#   - source_type in {tor, onion} or .onion URL     +5.0  (dark-web specific)
#   - tie-breaker: text length / 1000              up to +1.0
#
# Pages with >= `_SKIP_LLM_THRESHOLD` high-confidence regex IOCs are
# already well-covered and get a strong negative score so they are never
# selected.  This implements step (a) of the optimisation brief.

_SKIP_LLM_THRESHOLD = 5  # high-confidence regex IOCs above which we skip LLM
_LLM_SKIP_PENALTY = -1000.0

# LLM tiers adds value for these entity types specifically:
# THREAT_ACTOR_HANDLE, MALWARE_FAMILY, DATE, ORGANIZATION_NAME (filtered),
# MITRE_TECHNIQUE, BTC/XMR/ETH wallets, file hashes.  The regex/NER tiers
# are weak for THREAT_ACTOR_HANDLE without @-prefix, MALWARE_FAMILY outside
# the dictionary, and DATE in informal contexts — so prioritising pages
# with low existing coverage maximises what LLM adds.


def _score_pages_for_llm(
    pages: list[dict],
    max_llm_pages: int,
) -> set[str]:
    """
    Return the set of page URLs that should get LLM extraction.

    Selection rules:
      1. Skip pages with >= 5 high-confidence regex IOCs (already covered).
      2. Prioritise pages with low regex coverage, long text, tor/onion source.
      3. Cap at `max_llm_pages` pages.

    Synchronous — runs once at the start of `extract_entities_from_pages`
    before the per-page async fan-out.  Regex is fast enough that doing
    it twice (once here for scoring, once inside each page's
    `extract_entities_from_page`) is cheaper than threading the result
    through the call graph.
    """
    if not pages or max_llm_pages <= 0:
        return set()

    scored: list[tuple[float, str]] = []
    for page in pages:
        url = (page.get("url") or "").strip()
        if not url:
            continue
        text = (
            page.get("text")
            or page.get("content")
            or page.get("cleaned_text")
            or ""
        )
        source_type = (page.get("source_type") or "").lower()
        is_tor_source = (
            source_type in ("tor", "onion")
            or ".onion" in url.lower()
        )

        # Cheap regex-only pass for the score
        try:
            regex_entities = _regex_extract_all(text)
        except Exception:
            regex_entities = {}

        high_conf_count = sum(
            len(v)
            for k, v in regex_entities.items()
            if k in _HIGH_CONFIDENCE_REGEX_TYPES
        )
        if high_conf_count >= _SKIP_LLM_THRESHOLD:
            logger.debug(
                "LLM-skip: %s has %d high-conf regex IOCs",
                url, high_conf_count,
            )
            continue

        total_count = sum(len(v) for v in regex_entities.values())
        text_len = len(text)

        score = 0.0
        if total_count < 3:
            score += 10.0
        if text_len > 500:
            score += min(text_len / 200.0, 5.0)
        if is_tor_source:
            score += 5.0
        # Tie-breaker: prefer longer pages (more LLM value per call)
        score += min(text_len / 1000.0, 1.0)

        scored.append((score, url))

    scored.sort(key=lambda pair: -pair[0])
    selected = {url for _, url in scored[:max_llm_pages]}
    logger.info(
        "LLM page selection: %d/%d pages selected (cap=%d)",
        len(selected), len(pages), max_llm_pages,
    )
    return selected

_ENTITY_TYPE_PRIORITY = {
    1: frozenset({"CVE", "CVE_NUMBER", "IP_ADDRESS", "IPV6_ADDRESS", "FILE_HASH", "FILE_HASH_MD5", "FILE_HASH_SHA1", "FILE_HASH_SHA256", "FILE_HASH_SHA512", "ONION_URL", "DOMAIN", "DOMAIN_NAME"}),
    2: frozenset({"MALWARE_FAMILY", "RANSOMWARE_GROUP", "THREAT_ACTOR", "THREAT_ACTOR_HANDLE"}),
    3: frozenset({"BITCOIN_ADDRESS", "MONERO_ADDRESS", "ETHEREUM_ADDRESS", "WALLET"}),
    4: frozenset({"EMAIL_ADDRESS", "PGP_KEY_BLOCK"}),
    5: frozenset({"ORGANIZATION_NAME", "PERSON_NAME"}),
}


def _type_priority(entity_type: str) -> int:
    for priority, types in _ENTITY_TYPE_PRIORITY.items():
        if entity_type in types:
            return priority
    return 99

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class ExtractionResult:
    page_url: str
    entity_count: int
    entities_by_type: dict[str, int] = field(default_factory=dict)
    entity_ids: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    entities: list = field(default_factory=list)

    def __iter__(self):
        return iter(self.entities)

    def __len__(self) -> int:
        return len(self.entities)

    def __getitem__(self, index):
        return self.entities[index]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


async def extract_entities_from_page(
    page_text: str,
    page_url: str,
    page_id: Optional[int] = None,
    investigation_id: Optional[uuid.UUID] = None,
    llm=None,
    run_llm_extraction: bool = False,
    disable_cache: Optional[bool] = None,
    persist: bool = True,
    force_skip_llm: bool = False,
) -> ExtractionResult:
    """
    Run the full extraction pipeline for a single page.

    Each stage is wrapped in its own try/except so a failure in one stage
    never prevents later stages from running.  Non-fatal errors are collected
    in ExtractionResult.errors.

    Set persist=False to skip DB persistence (used when collecting entities
    for batch capping before write).

    `force_skip_llm=True` overrides `run_llm_extraction` for this single
    page — used by `extract_entities_from_pages` after the page-priority
    pre-score decided this page should not get LLM (already well-covered
    by regex, or below the top-N priority cut).
    """
    errors: list[str] = []

    # -----------------------------------------------------------------------
    # Stage 1 — Regex
    # -----------------------------------------------------------------------
    try:
        regex_entities = _regex_extract_all(page_text)
    except Exception as exc:
        logger.error("Regex extraction failed for %s: %s", page_url, exc)
        errors.append(f"regex: {exc}")
        regex_entities = {}

    # -----------------------------------------------------------------------
    # Stage 2 — NER
    # -----------------------------------------------------------------------
    try:
        ner_entities = _ner_extract(page_text)
    except Exception as exc:
        logger.error("NER extraction failed for %s: %s", page_url, exc)
        errors.append(f"ner: {exc}")
        ner_entities = {}

    # Merge regex + NER (regex results take precedence for shared types)
    combined: dict[str, list[str]] = dict(regex_entities)
    for entity_type, values in ner_entities.items():
        if entity_type in combined:
            combined[entity_type] = _dedup(combined[entity_type] + values)
        else:
            combined[entity_type] = list(values)

    # -----------------------------------------------------------------------
    # Stage 3 — LLM (optional)
    #
    # The `force_skip_llm` flag wins over `run_llm_extraction` so the page
    # selector can deterministically drop a page even when the caller
    # requested LLM globally (e.g. cap reached, or already well-covered).
    # -----------------------------------------------------------------------
    if run_llm_extraction and llm is not None and not force_skip_llm:
        try:
            import hashlib
            page_hash = hashlib.sha256(page_text.encode()).hexdigest() if page_text else None
            combined = await _llm_extract(
                page_text, llm, combined, page_hash=page_hash, disable_cache=disable_cache
            )
        except Exception as exc:
            logger.error("LLM extraction failed for %s: %s", page_url, exc)
            errors.append(f"llm: {exc}")

    # -----------------------------------------------------------------------
    # Stage 4 — Normalise
    # -----------------------------------------------------------------------
    try:
        normalized = _normalize(combined, page_url, page_id, page_text=page_text)
    except Exception as exc:
        logger.error("Normalization failed for %s: %s", page_url, exc)
        errors.append(f"normalize: {exc}")
        normalized = []

    # -----------------------------------------------------------------------
    # Build result (no DB persist yet if persist=False)
    # -----------------------------------------------------------------------
    entities_by_type: dict[str, int] = {}
    for entity in normalized:
        entities_by_type[entity.entity_type] = (
            entities_by_type.get(entity.entity_type, 0) + 1
        )

    if not persist:
        return ExtractionResult(
            page_url=page_url,
            entity_count=len(normalized),
            entities_by_type=entities_by_type,
            entity_ids=[],
            errors=errors,
            entities=normalized,
        )

    # -----------------------------------------------------------------------
    # Stage 5 — DB persist
    # -----------------------------------------------------------------------
    try:
        entity_ids = _merge_db(normalized, investigation_id)
    except Exception as exc:
        logger.error("DB persist failed for %s: %s", page_url, exc)
        errors.append(f"db: {exc}")
        entity_ids = []

    return ExtractionResult(
        page_url=page_url,
        entity_count=len(normalized),
        entities_by_type=entities_by_type,
        entity_ids=entity_ids,
        errors=errors,
    )


async def extract_entities_from_pages(
    pages: list[dict],
    investigation_id: Optional[uuid.UUID] = None,
    llm=None,
    run_llm_extraction: bool = False,
    max_concurrent: int = 5,
    disable_cache: Optional[bool] = None,
    entity_cap: int = 400,
    max_llm_pages: int = 10,
    llm_progress_callback: Optional[Any] = None,
) -> list[ExtractionResult]:
    """
    Run extraction concurrently across a list of pages.

    Each page dict must have at least a "url" key.  Content is read from
    "text", "content", or "cleaned_text" keys (first found wins).

    A semaphore limits concurrency to *max_concurrent* simultaneous pages.
    One page failing never blocks others — failures are captured in each
    page's ExtractionResult.errors.

    Before DB persistence, applies entity cap (default 400) ranked by:
    confidence (primary), entity type priority (secondary), occurrence count (tertiary).

    LLM extraction cap
    ------------------
    When `run_llm_extraction` is True and `llm` is provided, the LLM tier
    only runs on up to `max_llm_pages` pages per call.  Pages are scored by
    LLM value (low regex coverage, long text, tor/onion source) so the
    most informative pages get the LLM call budget.  Pages with
    already-strong regex coverage (≥ 5 high-confidence IOCs) are skipped.

    The optional `llm_progress_callback` is an async or sync callable
    invoked after each LLM-extracted page completes:
        callback(page_index_1based, total_llm_pages, page_url)
    Used by the API route to emit SSE progress events.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    # -----------------------------------------------------------------------
    # Pre-score pages to decide which ones get LLM extraction.
    # Only runs when LLM is actually available — otherwise every page is
    # already in the regex/NER-only path.
    # -----------------------------------------------------------------------
    if run_llm_extraction and llm is not None and pages:
        llm_selected_urls = _score_pages_for_llm(pages, max_llm_pages)
    else:
        llm_selected_urls = set()

    llm_total = len(llm_selected_urls)
    llm_done_counter = {"n": 0}
    llm_done_lock = asyncio.Lock()

    async def _emit_progress(url: str) -> None:
        if llm_progress_callback is None or llm_total == 0:
            return
        async with llm_done_lock:
            llm_done_counter["n"] += 1
            current = llm_done_counter["n"]
        try:
            cb = llm_progress_callback(current, llm_total, url)
            if asyncio.iscoroutine(cb):
                await cb
        except Exception as exc:
            logger.debug("llm_progress_callback raised (non-fatal): %s", exc)

    async def _process(page: dict) -> ExtractionResult:
        async with semaphore:
            url = page.get("url", "")
            text = (
                page.get("text")
                or page.get("content")
                or page.get("cleaned_text")
                or ""
            )
            # Per-page LLM decision: only run LLM tier if the URL is in the
            # pre-scored selection set.  This caps LLM spend and prioritises
            # the pages where LLM adds the most value.
            page_runs_llm = (
                run_llm_extraction
                and llm is not None
                and url in llm_selected_urls
            )
            try:
                result = await extract_entities_from_page(
                    page_text=text,
                    page_url=url,
                    page_id=page.get("page_id"),
                    investigation_id=investigation_id,
                    llm=llm,
                    run_llm_extraction=run_llm_extraction,
                    disable_cache=disable_cache,
                    persist=False,
                    force_skip_llm=not page_runs_llm,
                )
            except Exception as exc:
                logger.error("Page processing failed for %s: %s", url, exc)
                return ExtractionResult(
                    page_url=url,
                    entity_count=0,
                    entities_by_type={},
                    entity_ids=[],
                    errors=[str(exc)],
                )

            if page_runs_llm:
                await _emit_progress(url)
            return result

    results = list(await asyncio.gather(*[_process(p) for p in pages]))

    all_normalized: list[NormalizedEntity] = []
    for result in results:
        all_normalized.extend(result.entities)

    if not all_normalized:
        return results

    all_normalized = _resolve_conflicts(all_normalized)

    # -----------------------------------------------------------------------
    # Content safety: drop prohibited entity values before capping/storing.
    # Only text-based types are checked; technical IOCs are never filtered.
    # The actual value is never logged — only type and count.
    # -----------------------------------------------------------------------
    from utils.content_safety import is_blocked_entity_value as _is_blocked_entity_value
    clean_entities: list[NormalizedEntity] = []
    blocked_entity_count = 0
    for _ent in all_normalized:
        if _is_blocked_entity_value(_ent.entity_type, _ent.value):
            blocked_entity_count += 1
            logger.debug(
                "Entity value blocked — prohibited content: type=%s",
                _ent.entity_type,
            )
        else:
            clean_entities.append(_ent)
    if blocked_entity_count > 0:
        logger.info(
            "Blocked %d entities for prohibited content",
            blocked_entity_count,
        )
    all_normalized = clean_entities

    capped_entities, original_count = apply_entity_cap(
        all_normalized, cap=entity_cap, investigation_id=investigation_id
    )

    if capped_entities:
        try:
            entity_id_map = _merge_db(capped_entities, investigation_id)
            url_to_ids: dict[str, list] = {}
            for ent, eid in zip(capped_entities, entity_id_map):
                if ent.source_url not in url_to_ids:
                    url_to_ids[ent.source_url] = []
                url_to_ids[ent.source_url].append(eid)

            for result in results:
                result.entity_ids = url_to_ids.get(result.page_url, [])
                result.entities = [e for e in capped_entities if e.source_url == result.page_url]
        except Exception as exc:
            logger.error("Batch entity persist failed: %s", exc)

    return results


# ---------------------------------------------------------------------------
# Entity cap logic
# ---------------------------------------------------------------------------

def _occurrence_count(entity: NormalizedEntity, all_entities: list[NormalizedEntity]) -> int:
    """Count how many times this entity value appears across all pages."""
    count = 0
    for other in all_entities:
        if other.entity_type == entity.entity_type and other.value == entity.value:
            count += 1
    return count


def _apply_per_type_caps(
    entities: list[NormalizedEntity],
    caps: dict = PER_TYPE_CAPS,
) -> list[NormalizedEntity]:
    """
    Apply per-type sub-caps before the global cap.

    This prevents high-volume low-specificity entity types (e.g., ORGANIZATION_NAME)
    from crowding out high-value IOCs (FILE_HASH, CVE, MITRE_TECHNIQUE).
    """
    type_counts: dict[str, int] = {}
    result: list[NormalizedEntity] = []

    for entity in entities:
        etype = entity.entity_type
        cap = caps.get(etype, float("inf"))
        count = type_counts.get(etype, 0)
        if count < cap:
            result.append(entity)
            type_counts[etype] = count + 1
        else:
            logger.debug(f"Per-type cap: {etype} capped at {cap}")

    return result


def apply_entity_cap(
    entities: list[NormalizedEntity],
    cap: int = 400,
    investigation_id: Optional[uuid.UUID] = None,
) -> tuple[list[NormalizedEntity], int]:
    """
    Apply quality-based entity filtering and hard cap.

    Steps:
    a) Remove any entity where confidence < 0.80
    b) Apply per-type sub-caps (see _apply_per_type_caps)
    c) Apply per-investigation hard cap of *cap* entities, ranked by:
       - confidence score (primary, descending)
       - entity type priority (secondary, ascending - lower number = higher priority)
       - occurrence count across pages (tertiary, descending)
    d) Log a warning when cap is applied

    Returns: (capped_entities, original_count)
    """
    original_count = len(entities)

    # Step a: confidence filter
    filtered = [e for e in entities if e.confidence >= 0.80]
    removed_confidence = original_count - len(filtered)
    if removed_confidence:
        logger.warning(f"Entity confidence filter removed {removed_confidence} low-confidence entities")

    # Count occurrences per entity (by type+value) and boost confidence
    total_pages = len(set(e.source_url for e in filtered)) or 1
    for ent in filtered:
        occ = _occurrence_count(ent, filtered)
        ent._occurrence = occ
        occurrence_ratio = occ / total_pages
        confidence_boost = min(occurrence_ratio * 0.10, 0.10)
        ent.confidence = min(ent.confidence + confidence_boost, 1.0)

    # Step b: per-type sub-caps
    filtered = _apply_per_type_caps(filtered)

    # Step c: sort and cap
    if len(filtered) > cap:
        filtered.sort(key=lambda e: (-e.confidence, _type_priority(e.entity_type), -e._occurrence))
        filtered = filtered[:cap]
        logger.warning(
            f"Entity cap applied: {original_count} entities reduced to {len(filtered)} "
            f"for investigation {investigation_id}"
        )

    # Clean up temporary attribute
    for ent in filtered:
        if hasattr(ent, "_occurrence"):
            del ent._occurrence

    return filtered, original_count


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------


def _dedup(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result
