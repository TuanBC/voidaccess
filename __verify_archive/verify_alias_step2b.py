"""Verify step 2b: full alias resolution with auto-persistence.

Tests the `run_alias_resolution` function.  Uses real UUIDs for
investigation_id since the model's source_investigation_id is a
UUID column.  The brief's test 2 uses 'inv-1' / 'inv-2' as
placeholders, but those never get linked to a real investigation
row in the DB; the production pipeline always passes a UUID.
"""
import asyncio
import logging
import os
import uuid as uuid_module
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["VOIDACCESS_DB_PATH"] = str(DB_PATH)

logging.basicConfig(level=logging.INFO, format='%(levelname)s %(name)s: %(message)s')

from db.models import Base
from db.session import get_engine

engine = get_engine()
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)


async def test():
    from sources.actor_profiles import (
        ActorProfileManager,
        run_alias_resolution,
    )

    mgr = ActorProfileManager()

    inv_1 = str(uuid_module.uuid4())
    inv_2 = str(uuid_module.uuid4())

    id1 = await mgr.upsert_actor('lockbitsupp', inv_1, 0.95, None)
    id2 = await mgr.upsert_actor('lockbit_supp', inv_2, 0.90, None)
    print(f"id1={id1} (lockbitsupp)  id2={id2} (lockbit_supp)")

    # Shared IP infrastructure linked to inv_1
    await mgr.add_infrastructure(
        actor_id=id1, entity_type='IP_ADDRESS',
        entity_value='185.220.101.45', investigation_id=inv_1, confidence=0.94,
    )
    await mgr.add_infrastructure(
        actor_id=id2, entity_type='IP_ADDRESS',
        entity_value='185.220.101.45', investigation_id=inv_1, confidence=0.92,
    )

    # Shared PGP key
    shared_pgp = 'ABCD1234EF567890ABCD1234EF567890ABCD1234'
    for actor_id in [id1, id2]:
        await mgr.add_infrastructure(
            actor_id=actor_id, entity_type='PGP_KEY_BLOCK',
            entity_value=shared_pgp, investigation_id=inv_1, confidence=0.95,
        )

    # Shared domain
    shared_domain = 'lockbit-leaks.example'
    for actor_id in [id1, id2]:
        await mgr.add_infrastructure(
            actor_id=actor_id, entity_type='DOMAIN',
            entity_value=shared_domain, investigation_id=inv_1, confidence=0.90,
        )

    # Find candidates for actor 1 (pre-resolution view)
    candidates = await mgr.find_alias_candidates(
        id1, min_confidence=0.20
    )
    print(f'\n=== Candidates for actor 1 (pre-resolution) ===')
    for c in candidates:
        handle = c.get('candidate_handle')
        conf = c.get('confidence', 0.0)
        sigs = c.get('signals', [])
        shared = c.get('shared_infrastructure', [])
        pgp = c.get('shared_pgp', [])
        print(f'  {handle} (conf: {conf:.2f})')
        print(f'    signals: {sigs}')
        print(f'    shared_infra: {shared}')
        print(f'    shared_pgp: {pgp}')

    # Run the background resolution pass — should persist the alias row.
    new_aliases = await run_alias_resolution(inv_1, min_confidence=0.75)
    print(f'\n=== run_alias_resolution ===')
    print(f'New aliases persisted: {new_aliases}')

    # Re-load profiles
    print(f'\n=== Final state ===')
    for label, aid in [("actor 1 (lockbitsupp)", id1), ("actor 2 (lockbit_supp)", id2)]:
        profile = await mgr.get_profile_by_id(aid)
        aliases = (profile or {}).get('aliases', [])
        print(f"  {label} has {len(aliases)} aliases:")
        for a in aliases:
            print(f"    {a.get('alias_type')}={a.get('alias_value')} conf={a.get('confidence')}")

    assert new_aliases >= 1, 'Expected at least one alias to be persisted'
    profile1 = await mgr.get_profile_by_id(id1)
    aliases1 = (profile1 or {}).get('aliases', [])
    assert any(
        a.get('alias_type') in ('likely_same_actor', 'confirmed_same_actor')
        for a in aliases1
    ), f'Expected likely/confirmed alias, got: {aliases1}'
    print('\nAuto-persistence: OK')


asyncio.run(test())
