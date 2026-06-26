"""
Verify graceful degradation when llm_client is None.
"""
import asyncio
import sys

sys.path.insert(0, ".")

from extractor.pipeline import extract_entities_from_pages


PAGES = [
    {
        "url": "http://forum1.onion/thread",
        "text": "Some prose. " * 80 + " Also mention darkphoenix actor. " * 20,
        "source_type": "tor",
    },
]


async def main() -> None:
    # Test 1: llm=None, run_llm_extraction=True — should gracefully fall back
    print("=== Test 1: llm=None, run_llm_extraction=True (graceful degradation) ===")
    results = await extract_entities_from_pages(
        pages=PAGES,
        investigation_id=None,
        llm=None,
        run_llm_extraction=True,
        max_llm_pages=10,
        max_concurrent=2,
    )
    for r in results:
        print(f"  {r.page_url}: count={r.entity_count} errs={r.errors}")
    assert results[0].errors == [], f"Expected no errors with llm=None, got {results[0].errors}"
    print("  OK: no errors, regex+NER still ran")

    # Test 2: llm=None, run_llm_extraction=False — same outcome, explicit
    print()
    print("=== Test 2: llm=None, run_llm_extraction=False ===")
    results = await extract_entities_from_pages(
        pages=PAGES,
        investigation_id=None,
        llm=None,
        run_llm_extraction=False,
        max_llm_pages=10,
        max_concurrent=2,
    )
    for r in results:
        print(f"  {r.page_url}: count={r.entity_count} errs={r.errors}")
    assert results[0].errors == [], f"Expected no errors, got {results[0].errors}"
    print("  OK: no errors")

    print()
    print("BOTH TESTS PASSED — graceful degradation works")


if __name__ == "__main__":
    asyncio.run(main())
