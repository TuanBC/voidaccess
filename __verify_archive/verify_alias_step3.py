"""Verify step 3: `voidaccess actor <handle>` shows alias candidates.

Sets up a pair of related actor profiles in the local SQLite DB, then
invokes the `voidaccess actor` command to render the profile.
"""
import asyncio
import os
import subprocess
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


async def setup_data():
    from sources.actor_profiles import ActorProfileManager

    mgr = ActorProfileManager()
    inv_1 = str(uuid_module.uuid4())

    id1 = await mgr.upsert_actor('lockbitsupp', inv_1, 0.95, None)
    id2 = await mgr.upsert_actor(
        'lockbit_supp', str(uuid_module.uuid4()), 0.90, None,
    )

    # Shared IP infrastructure
    await mgr.add_infrastructure(
        actor_id=id1, entity_type='IP_ADDRESS',
        entity_value='185.220.101.45', investigation_id=inv_1, confidence=0.94,
    )
    await mgr.add_infrastructure(
        actor_id=id2, entity_type='IP_ADDRESS',
        entity_value='185.220.101.45', investigation_id=inv_1, confidence=0.92,
    )

    # Shared PGP
    shared_pgp = 'ABCD1234EF567890ABCD1234EF567890ABCD1234'
    for actor_id in [id1, id2]:
        await mgr.add_infrastructure(
            actor_id=actor_id, entity_type='PGP_KEY_BLOCK',
            entity_value=shared_pgp, investigation_id=inv_1, confidence=0.95,
        )
    print("Seeded actor profiles in SQLite DB.")


asyncio.run(setup_data())

# Now invoke the CLI
env = {
    **os.environ,
    "DATABASE_URL": f"sqlite:///{DB_PATH}",
    "VOIDACCESS_DB_PATH": str(DB_PATH),
    "PYTHONIOENCODING": "utf-8",
    "PYTHONUTF8": "1",
}

print()
print("=" * 70)
print("=== voidaccess actor lockbitsupp ===")
print("=" * 70)
result = subprocess.run(
    ["voidaccess", "actor", "lockbitsupp"],
    cwd="C:\\void.access\\voidaccess",
    capture_output=True,
    text=True,
    env=env,
    encoding="utf-8",
    errors="replace",
)
print("STDOUT:")
print(result.stdout)
if result.stderr:
    print("STDERR (truncated):")
    print(result.stderr[:2000])
print(f"Return code: {result.returncode}")
