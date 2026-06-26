"""Verify step 2: alias candidate detection via shared infrastructure.

Uses the local SQLite DB configured for the CLI to avoid needing
PostgreSQL during the verify pass.
"""
import asyncio
import os
import sys
from pathlib import Path

# Force SQLite for verify — read URL from existing .env if present,
# otherwise default to the CLI's local DB path.
DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["VOIDACCESS_DB_PATH"] = str(DB_PATH)

# Ensure tables exist for the local SQLite DB.
from db.models import Base
from db.session import get_engine

engine = get_engine()
Base.metadata.create_all(engine)
print(f"DB: {engine.url}")


async def test():
    from sources.actor_profiles import ActorProfileManager

    mgr = ActorProfileManager()

    # Create two actors with shared infra
    id1 = await mgr.upsert_actor(
        'lockbitsuppp', 'inv-1', 0.95, None
    )
    id2 = await mgr.upsert_actor(
        'lb_admin', 'inv-2', 0.90, None
    )
    print(f"id1={id1} id2={id2}")

    # Add shared infrastructure
    shared_ip = '185.220.101.45'
    for actor_id in [id1, id2]:
        await mgr.add_infrastructure(
            actor_id=actor_id,
            entity_type='IP_ADDRESS',
            entity_value=shared_ip,
            investigation_id='inv-1',
            confidence=0.94,
        )

    # Find candidates for actor 1
    candidates = await mgr.find_alias_candidates(
        id1, min_confidence=0.20
    )

    print(f'Candidates found: {len(candidates)}')
    for c in candidates:
        handle = c.get('candidate_handle')
        conf = c.get('confidence', 0.0)
        sigs = c.get('signals', [])
        shared = c.get('shared_infrastructure', [])
        print(f'  {handle} (conf: {conf:.2f}) signals: {sigs} shared: {shared}')

    assert len(candidates) >= 1, f'Expected at least 1 candidate, got {len(candidates)}'
    print('Alias detection: OK')


asyncio.run(test())
