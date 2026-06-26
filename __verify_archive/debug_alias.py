"""Debug the run_alias_resolution flow."""
import asyncio
import logging
import os
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["VOIDACCESS_DB_PATH"] = str(DB_PATH)

logging.basicConfig(level=logging.DEBUG, format='%(levelname)s %(name)s: %(message)s')

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

    # Create two actors with multiple shared signals
    id1 = await mgr.upsert_actor(
        'lockbitsupp', 'inv-1', 0.95, None
    )
    id2 = await mgr.upsert_actor(
        'lockbit_supp', 'inv-2', 0.90, None
    )
    print(f"id1={id1} (lockbitsupp)  id2={id2} (lockbit_supp)")

    # Shared IP infrastructure
    await mgr.add_infrastructure(
        actor_id=id1, entity_type='IP_ADDRESS',
        entity_value='185.220.101.45', investigation_id='inv-1', confidence=0.94,
    )
    await mgr.add_infrastructure(
        actor_id=id2, entity_type='IP_ADDRESS',
        entity_value='185.220.101.45', investigation_id='inv-1', confidence=0.92,
    )

    # Shared PGP key
    shared_pgp = 'ABCD1234EF567890ABCD1234EF567890ABCD1234'
    for actor_id in [id1, id2]:
        await mgr.add_infrastructure(
            actor_id=actor_id, entity_type='PGP_KEY_BLOCK',
            entity_value=shared_pgp, investigation_id='inv-1', confidence=0.95,
        )

    # Shared domain
    shared_domain = 'lockbit-leaks.example'
    for actor_id in [id1, id2]:
        await mgr.add_infrastructure(
            actor_id=actor_id, entity_type='DOMAIN',
            entity_value=shared_domain, investigation_id='inv-1', confidence=0.90,
        )

    # Check what get_actors_by_investigation returns
    print("\n=== get_actors_by_investigation('inv-1') ===")
    actors_inv1 = await mgr.get_actors_by_investigation('inv-1')
    for a in actors_inv1:
        print(f"  {a.get('id')} -> {a.get('canonical_handle')}")

    # Run the resolution pass
    print("\n=== run_alias_resolution('inv-1', 0.75) ===")
    new_aliases = await run_alias_resolution('inv-1', min_confidence=0.75)
    print(f"New aliases persisted: {new_aliases}")

    # Re-load profiles
    print("\n=== Final state ===")
    for label, aid in [("actor 1 (lockbitsupp)", id1), ("actor 2 (lockbit_supp)", id2)]:
        profile = await mgr.get_profile_by_id(aid)
        aliases = (profile or {}).get('aliases', [])
        print(f"  {label} has {len(aliases)} aliases:")
        for a in aliases:
            print(f"    {a.get('alias_type')}={a.get('alias_value')} conf={a.get('confidence')}")


asyncio.run(test())
