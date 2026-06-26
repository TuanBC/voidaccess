"""Verify API imports cleanly."""
import os
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"

# Import the routes module to confirm it loads without errors
from api.routes.actors import (
    get_actor,
    get_actor_aliases,
    add_actor_alias,
    add_actor_note,
    list_actors,
    get_actor_investigations,
    ActorAliasRequest,
)
print("API endpoints import OK")
print()
print("Available endpoints:")
print("  GET  /actors")
print("  GET  /actors/{handle}")
print("  GET  /actors/{handle}/investigations")
print("  POST /actors/{handle}/notes")
print("  GET  /actors/{handle}/aliases       (NEW)")
print("  POST /actors/{handle}/aliases       (NEW)")
print()
print("New schema:")
import json
sample = {
    "alias": "lb_admin",
    "alias_type": "confirmed_same_actor",
    "note": "Confirmed by PGP reuse",
    "confidence": 0.95,
}
print(json.dumps(ActorAliasRequest(**sample).model_dump(), indent=2))
