"""Smoke test: ensure existing actor profile functionality still works."""
import asyncio
import os
import uuid as uuid_module
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["VOIDACCESS_DB_PATH"] = str(DB_PATH)

from db.models import Base
from db.session import get_engine

engine = get_engine()
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)


async def smoke():
    from sources.actor_profiles import ActorProfileManager

    mgr = ActorProfileManager()

    inv_1 = str(uuid_module.uuid4())

    # Basic upsert
    id1 = await mgr.upsert_actor('testuser', inv_1, 0.85, None)
    assert id1, "upsert_actor returned None"
    print(f"upsert_actor: OK -> {id1}")

    # Re-upsert same handle should return same id
    id1_again = await mgr.upsert_actor('testuser', inv_1, 0.90, None)
    assert id1 == id1_again, f"Expected same id, got {id1} != {id1_again}"
    print(f"re-upsert: OK -> {id1_again}")

    # Add infrastructure
    await mgr.add_infrastructure(
        actor_id=id1, entity_type='IP_ADDRESS',
        entity_value='1.2.3.4', investigation_id=inv_1, confidence=0.9,
    )
    print("add_infrastructure: OK")

    # Add alias
    await mgr.add_alias(
        actor_id=id1, alias_value='testuser2',
        alias_type='manual', investigation_id=inv_1, confidence=0.9,
    )
    print("add_alias: OK")

    # Get profile
    profile = await mgr.get_profile('testuser')
    assert profile is not None
    assert profile['canonical_handle'] == 'testuser'
    assert len(profile['aliases']) == 1
    assert len(profile['infrastructure']) == 1
    print(f"get_profile: OK -> {len(profile['aliases'])} aliases, {len(profile['infrastructure'])} infra")

    # List profiles
    profiles = await mgr.list_profiles(limit=10)
    assert len(profiles) >= 1
    print(f"list_profiles: OK -> {len(profiles)} profiles")

    # Search profiles
    matches = await mgr.search_profiles('test')
    assert len(matches) >= 1
    print(f"search_profiles: OK -> {len(matches)} matches")

    # Get by id
    profile2 = await mgr.get_profile_by_id(id1)
    assert profile2 is not None
    assert profile2['id'] == id1
    print(f"get_profile_by_id: OK")

    # Get actors by investigation
    actors = await mgr.get_actors_by_investigation(inv_1)
    assert len(actors) >= 1
    print(f"get_actors_by_investigation: OK -> {len(actors)} actors")

    # Find alias candidates (no candidates since we only have 1 actor)
    candidates = await mgr.find_alias_candidates(id1, min_confidence=0.10)
    print(f"find_alias_candidates: OK -> {len(candidates)} candidates (1 actor = 0 expected)")

    # Run alias resolution
    from sources.actor_profiles import run_alias_resolution
    new = await run_alias_resolution(inv_1)
    print(f"run_alias_resolution: OK -> {new} new aliases")

    print("\nALL SMOKE TESTS PASSED")


asyncio.run(smoke())
