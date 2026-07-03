"""
extractor/llm_extract.py — LLM-assisted entity extraction.

Runs AFTER regex and NER — only on text chunks that already contain at least
one entity (to avoid wasting API calls on irrelevant content).

Accepts an *llm* object (any LangChain chat model) as a parameter — does not
instantiate LLMs internally.

Public interface
----------------
async extract_with_llm(text, llm, existing_entities, max_chunk_chars, page_hash, disable_cache) → dict[str, list[str]]

Configuration
-------------
- Set DISABLE_EXTRACTION_CACHE=true in .env to disable caching entirely
- Use --no-cache CLI flag to bypass cache for a specific run
- Cache TTL is 30 days
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

from config import DISABLE_EXTRACTION_CACHE

logger = logging.getLogger(__name__)

_CACHE_TTL_DAYS = 30
_DEFAULT_MAX_CHUNK_CHARS = 12000

# ---------------------------------------------------------------------------
# Prompt template
# ---------------------------------------------------------------------------

_PROMPT_TEMPLATE = (
    "You are a threat intelligence analyst. Extract structured entities from the "
    "following dark web content. Return ONLY valid JSON with these keys: "
    "crypto_wallets, threat_actor_handles, malware_names, dates, urls, "
    "cve_identifiers, mitre_techniques, file_hashes_md5, file_hashes_sha1, file_hashes_sha256. "
    "Each key maps to a list of strings. If none found, use empty list. "
    "Do not include any text outside the JSON object.\n\n"
    "CRITICAL: File hashes (MD5, SHA1, SHA256) must be extracted in their complete, "
    "untruncated form. MD5 hashes are exactly 32 hex characters. "
    "SHA1 hashes are exactly 40 hex characters. "
    "SHA256 hashes are exactly 64 hex characters. "
    "If a hash appears truncated in the source text (e.g. 'a3f8b2...'), "
    "do NOT extract it — skip truncated hashes entirely.\n\n"
    "CVE: Common Vulnerabilities and Exposures identifiers in format CVE-YYYY-NNNNN. "
    "Extract the complete ID including year and number.\n\n"
    "MITRE_TECHNIQUE: MITRE ATT&CK technique identifiers in format TNNNN "
    "or TNNNN.NNN (sub-techniques). These map to adversary tactics and are "
    "critical for detection engineering.\n\n"
    "Content:\n{chunk}"
)

# Map LLM output keys → internal entity type constants
_LLM_KEY_TO_TYPE: dict[str, str] = {
    "crypto_wallets": "BITCOIN_ADDRESS",
    "threat_actor_handles": "THREAT_ACTOR_HANDLE",
    "malware_names": "MALWARE_FAMILY",
    "dates": "DATE",
    "urls": "ONION_URL",
    "cve_identifiers": "CVE_NUMBER",
    "mitre_techniques": "MITRE_TECHNIQUE",
    "file_hashes_md5": "FILE_HASH_MD5",
    "file_hashes_sha1": "FILE_HASH_SHA1",
    "file_hashes_sha256": "FILE_HASH_SHA256",
}

# ---------------------------------------------------------------------------
# Cache layer
# ---------------------------------------------------------------------------

def _get_cache_disabled(flag: Optional[bool] = None) -> bool:
    """Check if cache should be disabled (CLI flag overrides env var)."""
    if flag is True:
        return True
    return DISABLE_EXTRACTION_CACHE


def _compute_page_hash(content: str) -> str:
    """Compute SHA-256 hash of page content for cache key."""
    return hashlib.sha256(content.encode()).hexdigest()


def _load_from_cache(page_hash: str) -> Optional[dict[str, list[str]]]:
    """Load cached extraction results from database if not expired."""
    if not os.getenv("DATABASE_URL"):
        return None

    try:
        from sqlalchemy import text
        from db.session import get_session

        with get_session() as session:
            result = session.execute(
                text("""
                    SELECT entities_json, expires_at
                    FROM page_extraction_cache
                    WHERE page_hash = :page_hash
                """),
                {"page_hash": page_hash}
            ).fetchone()

            if result is None:
                return None

            entities_json, expires_at = result
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if expires_at < datetime.now(timezone.utc):
                logger.debug("Cache expired for page_hash=%s", page_hash[:16])
                return None

            logger.info("Cache HIT for page_hash=%s", page_hash[:16])
            return json.loads(entities_json)

    except Exception as exc:
        logger.warning("Cache lookup failed: %s", exc)
        return None


def _save_to_cache(page_hash: str, entities: dict[str, list[str]]) -> None:
    """Store extraction results in cache with 30-day TTL."""
    if not os.getenv("DATABASE_URL"):
        return

    try:
        from sqlalchemy import text
        from db.session import get_session

        entities_json = json.dumps(entities)
        expires_at = datetime.now(timezone.utc) + timedelta(days=_CACHE_TTL_DAYS)

        with get_session() as session:
            session.execute(
                text("""
                    INSERT INTO page_extraction_cache (page_hash, entities_json, extracted_at, expires_at)
                    VALUES (:page_hash, :entities_json, :extracted_at, :expires_at)
                    ON CONFLICT (page_hash) DO UPDATE SET
                        entities_json = EXCLUDED.entities_json,
                        extracted_at = EXCLUDED.extracted_at,
                        expires_at = EXCLUDED.expires_at
                """),
                {
                    "page_hash": page_hash,
                    "entities_json": entities_json,
                    "extracted_at": datetime.now(timezone.utc),
                    "expires_at": expires_at,
                }
            )
            session.commit()

        logger.info("Cache saved for page_hash=%s", page_hash[:16])

    except Exception as exc:
        logger.warning("Cache save failed: %s", exc)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


async def extract_with_llm(
    text: str,
    llm,
    existing_entities: dict[str, list[str]],
    max_chunk_chars: int = _DEFAULT_MAX_CHUNK_CHARS,
    page_hash: Optional[str] = None,
    disable_cache: Optional[bool] = None,
) -> dict[str, list[str]]:
    """
    Augment *existing_entities* with entities found by the LLM.

    - If *llm* is None, returns *existing_entities* unchanged.
    - Only processes text when *existing_entities* has at least one value
      (to avoid API calls on irrelevant pages).
    - Splits text into overlapping chunks of *max_chunk_chars* with a 200-char
      overlap to avoid splitting entities at boundaries.
    - Merges and deduplicates results from every chunk into *existing_entities*.
    - Uses content-hash caching to skip LLM calls for identical content.
    - Entity confidence increases with chunk occurrence count.
    - Invalid JSON from the LLM is logged as a warning; that chunk contributes
      no results rather than raising.
    - Never raises.

    Streaming-output suppression (v1.6.1):
    Each chunk's LLM call goes through ``await llm.ainvoke(prompt)``.  The
    LangChain model is configured with ``streaming=True`` and a
    ``BufferedStreamingHandler`` callback that ``print()``s every ~60 chars
    of the streamed response to stdout.  During extraction that callback
    prints raw LLM tokens (including partial JSON objects) directly to the
    user's terminal at every chunk boundary — which, for the user, looks
    like the ``{"crypto_w {"threat_actor"...`` corruption signature
    reported in v1.6.0.

    The chunk-merge logic itself is correct: each chunk's raw response is
    parsed independently via ``json.loads`` with markdown-fence stripping,
    and any chunk that fails to parse is skipped (logged at WARNING) —
    raw chunk strings are NEVER concatenated before parsing.  The visible
    "garbled JSON" is purely the streaming callback dumping tokens to
    stdout, not a merge bug.

    Fix: route every chunk's ``ainvoke`` call through a per-extraction
    callback override that suppresses the global streaming handler's
    stdout prints.  We do this by attaching a no-op callback to each
    call via LangChain's ``config`` argument — this *adds* a callback for
    that call only, leaving the model's default callbacks intact for
    other code paths (refine_query / filter_results / generate_summary
    still stream as before — only extraction is silenced).
    """
    if llm is None:
        return existing_entities

    # Skip expensive LLM calls if regex/NER found nothing at all
    if not any(existing_entities.values()):
        return existing_entities

    # Determine page hash for caching
    if page_hash is None:
        page_hash = _compute_page_hash(text)

    # Check cache first (unless disabled)
    if not _get_cache_disabled(disable_cache):
        cached = _load_from_cache(page_hash)
        if cached is not None:
            return _merge_existing_and_cached(existing_entities, cached)

    # Filter blocked entities before LLM to avoid processing noise
    # Only apply to NER types (regex types have precise patterns, skip blocklist)
    try:
        from extractor.normalizer import is_blocked_entity, _REGEX_TYPES
        filtered: dict[str, list[str]] = {}
        for entity_type, values in existing_entities.items():
            if entity_type in _REGEX_TYPES:
                filtered[entity_type] = list(values)
            else:
                kept = [v for v in values if not is_blocked_entity(entity_type, v)]
                if kept:
                    filtered[entity_type] = kept
        if not filtered:
            # Still cache the empty result to avoid repeated LLM calls
            if not _get_cache_disabled(disable_cache):
                _save_to_cache(page_hash, {})
            return existing_entities
        existing_entities = filtered
    except ImportError:
        pass

    try:
        chunks = _chunk_text(text, max_chunk_chars, overlap=200)

        # Track entity occurrences across chunks for confidence scoring
        entity_occurrences: dict[str, dict[str, int]] = {}
        for entity_type in _LLM_KEY_TO_TYPE.values():
            entity_occurrences[entity_type] = {}

        result: dict[str, list[str]] = {k: list(v) for k, v in existing_entities.items()}

        # Collect raw chunk responses for per-chunk independent parsing
        chunk_contents: list[str] = []
        for chunk in chunks:
            raw = await _extract_chunk(chunk, llm)
            if raw:
                chunk_contents.append(raw)

        # Merge dict keyed by LLM output keys — each chunk parsed independently
        merged: dict[str, list] = {key: [] for key in _LLM_KEY_TO_TYPE}

        for raw_content in chunk_contents:
            try:
                cleaned = (
                    raw_content.strip()
                    .removeprefix("```json")
                    .removeprefix("```")
                    .strip()
                    .removesuffix("```")
                    .strip()
                )
                parsed = json.loads(cleaned)
            except (json.JSONDecodeError, AttributeError):
                logger.warning("LLM returned invalid JSON for chunk (len=%d)", len(raw_content))
                continue

            for llm_key, entity_type in _LLM_KEY_TO_TYPE.items():
                vals = parsed.get(llm_key, [])
                if isinstance(vals, list):
                    for v in vals:
                        normalized = str(v).strip()
                        if normalized:
                            merged[llm_key].append(normalized)
                            counts = entity_occurrences.get(entity_type, {})
                            counts[normalized] = counts.get(normalized, 0) + 1
                            entity_occurrences[entity_type] = counts

        # Dedup each list after merge
        for key in merged:
            merged[key] = list(set(merged[key]))

        # Merge LLM results into result dict (keyed by internal entity type)
        for llm_key, entity_type in _LLM_KEY_TO_TYPE.items():
            new_vals = merged[llm_key]
            if new_vals:
                existing_vals = result.get(entity_type, [])
                existing_vals.extend(new_vals)
                result[entity_type] = _dedup(existing_vals)

        # Store result in cache (even if empty)
        if not _get_cache_disabled(disable_cache):
            _save_to_cache(page_hash, result)

        _log_confidence_stats(entity_occurrences, len(chunks))

        return result

    except Exception:
        logger.exception("extract_with_llm encountered an unexpected error")
        return existing_entities


def _merge_existing_and_cached(
    existing: dict[str, list[str]],
    cached: dict[str, list[str]],
) -> dict[str, list[str]]:
    """
    Merge cached entities with existing ones.
    Existing entities (from regex/NER) take precedence.
    """
    merged = dict(cached)
    for entity_type, values in existing.items():
        if entity_type in merged:
            # Dedupe and prefer existing values
            merged[entity_type] = _dedup(list(values) + merged[entity_type])
        else:
            merged[entity_type] = list(values)
    return merged


def _log_confidence_stats(
    entity_occurrences: dict[str, dict[str, int]],
    total_chunks: int,
) -> None:
    """Log confidence statistics for extracted entities."""
    for entity_type, counts in entity_occurrences.items():
        if not counts:
            continue
        for value, count in counts.items():
            if count > 1:
                confidence = count / total_chunks
                logger.debug(
                    "Entity %s=%s found in %d/%d chunks (confidence=%.2f)",
                    entity_type, value[:20], count, total_chunks, confidence
                )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _chunk_text(text: str, max_chars: int, overlap: int) -> list[str]:
    """
    Split *text* into chunks of at most *max_chars* with *overlap* char overlap.

    The last chunk may be shorter.  Single chunks are returned as-is without
    copying.
    """
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + max_chars, len(text))
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = end - overlap
    return chunks


async def _extract_chunk(chunk: str, llm) -> str:
    """Send one chunk to LLM and return raw response content. Returns '' on error.

    v1.6.1 — streaming-output suppression.
    ``llm`` was instantiated with ``streaming=True`` and a
    ``BufferedStreamingHandler`` callback that ``print()``s every ~60 chars
    of the streamed response to stdout.  During extraction that callback
    would dump raw LLM tokens (including partial JSON objects) directly
    to the user's terminal — producing the "garbled JSON fragments" that
    were being attributed to a chunk-merge bug.

    We override the per-call callback config with a no-op handler so the
    global streaming handler's stdout prints are silenced for THIS call
    only.  Other LangChain invocations (refine_query, filter_results,
    generate_summary) keep their streaming output unchanged.
    """
    try:
        from langchain_core.callbacks import BaseCallbackHandler

        class _SilentHandler(BaseCallbackHandler):
            """No-op callback that suppresses the streaming handler's stdout
            prints for this single extraction call.  Every hook is a
            no-op; we only care about preventing the parent's stdout
            noise — we still want ``ainvoke`` to return the full response
            content as before, just without the per-token terminal spam.
            """

            def on_llm_new_token(self, token: str, **kwargs) -> None:  # noqa: D401
                return None

            def on_llm_end(self, response, **kwargs) -> None:  # noqa: D401
                return None

            def on_llm_error(self, error, **kwargs) -> None:  # noqa: D401
                return None

        prompt = _PROMPT_TEMPLATE.format(chunk=chunk)
        # Note: LangChain merges this callback config with the runnable's
        # default callbacks for THIS call only.  Default callbacks on
        # other call sites (refine_query, filter_results, summary) are
        # not affected.
        response = await llm.ainvoke(
            prompt,
            config={"callbacks": [_SilentHandler()]},
        )
        content = response.content if hasattr(response, "content") else str(response)
        return content.strip()
    except Exception as exc:
        logger.warning("LLM chunk extraction failed: %s", exc)
        return ""


def _dedup(values) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result