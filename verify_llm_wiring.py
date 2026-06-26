"""
Local verification: exercise the LLM-extraction tier wiring with a mock LLM.

Simulates what a Docker investigation would do, but runs entirely in the
local Python process so we can verify the wiring without a running Docker
daemon.  This is the "docker compose exec fastapi python3 -c ..." equivalent
but portable.
"""
import asyncio
import sys

sys.path.insert(0, ".")

from extractor.pipeline import extract_entities_from_pages


# --- Mock LLM -------------------------------------------------------------
CALL_LOG: list[str] = []


class _MockMessage:
    def __init__(self, content):
        self.content = content


class _MockLLM:
    """Records every ainvoke call and returns a fixed JSON payload."""

    async def ainvoke(self, prompt):
        CALL_LOG.append("llm_called")
        return _MockMessage(
            '{"crypto_wallets": [], "threat_actor_handles": ["darkphoenix"], '
            '"malware_names": ["LockBit"], "dates": ["2024-03-15"], '
            '"urls": [], "cve_identifiers": [], "mitre_techniques": [], '
            '"file_hashes_md5": [], "file_hashes_sha1": [], '
            '"file_hashes_sha256": []}'
        )


# --- Pages: mix of high-coverage, low-coverage, tor/clearnet --------------
PAGES = [
    # High-confidence regex coverage (>5 high-conf IOCs) -> LLM SKIPPED
    {
        "url": "http://richioc.onion/page1",
        "text": (
            "IPv4 192.168.1.1 BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "
            "MD5 5d41402abc4b2a76b9719d911017c592 "
            "SHA1 aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d "
            "SHA256 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 "
            "CVE-2024-12345 CVE-2024-67890 CVE-2024-11111 CVE-2024-22222 "
            "BTC 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2 "
            "BTC 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        ),
        "source_type": "onion",
    },
    # Low coverage + long text + tor source -> LLM SELECTED
    {
        "url": "http://forum1.onion/thread",
        "text": ("Some prose. " * 80 + " Also mention darkphoenix actor. " * 20),
        "source_type": "tor",
    },
    # Low coverage + long text + clearnet github -> LLM SELECTED (lower pri)
    {
        "url": "http://github.com/user/repo",
        "text": ("Plain readme content. " * 60 + " LockBit ransomware notes."),
        "source_type": "github",
    },
    # Empty text -> NER/Regex yield nothing -> no LLM call
    {"url": "http://empty.onion/x", "text": "", "source_type": "onion"},
    # High coverage clearnet -> LLM SKIPPED
    {
        "url": "http://example.com/page",
        "text": (
            "10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5 "
            "CVE-2024-10001 CVE-2024-10002 CVE-2024-10003 "
            "CVE-2024-10004 CVE-2024-10005 CVE-2024-10006"
        ),
        "source_type": "clearnet",
    },
]


# --- Progress callback ----------------------------------------------------
PROGRESS_EVENTS: list[tuple[int, int, str]] = []


async def cb(current, total, url):
    PROGRESS_EVENTS.append((current, total, url))


async def main() -> None:
    results = await extract_entities_from_pages(
        pages=PAGES,
        investigation_id=None,
        llm=_MockLLM(),
        run_llm_extraction=True,
        max_llm_pages=2,            # cap LLM to 2 pages
        max_concurrent=4,
        llm_progress_callback=cb,
    )

    print("=== RESULTS ===")
    for r in results:
        types_str = ", ".join(f"{k}={v}" for k, v in r.entities_by_type.items())
        print(f"  {r.page_url}: count={r.entity_count} types=[{types_str}] errs={r.errors}")

    print()
    print("=== LLM CALLS ===")
    print(f"  Total LLM ainvoke calls: {len(CALL_LOG)}")
    print(f"  (Expected: 2 — one per selected page up to max_llm_pages=2)")

    print()
    print("=== PROGRESS EVENTS ===")
    if not PROGRESS_EVENTS:
        print("  (none)")
    for ev in PROGRESS_EVENTS:
        print(f"  page {ev[0]}/{ev[1]}: {ev[2]}")

    # --- Assertions --------------------------------------------------------
    assert len(CALL_LOG) <= 2, f"Expected <=2 LLM calls (cap=2), got {len(CALL_LOG)}"
    assert len(CALL_LOG) >= 1, f"Expected >=1 LLM call (some page was low-coverage), got 0"
    # The high-coverage pages should NOT have triggered LLM
    skipped_urls = {p["url"] for p in PAGES if "richioc" in p["url"] or "example.com" in p["url"]}
    for ev in PROGRESS_EVENTS:
        assert ev[2] not in skipped_urls, f"High-coverage page {ev[2]} was LLM-extracted; should have been skipped"

    print()
    print("ALL ASSERTIONS PASSED")


if __name__ == "__main__":
    asyncio.run(main())
