"""Verify investigations module imports cleanly."""
import os
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"

import api.routes.investigations as inv
print("Investigations module imports OK")
print(f"  _run_alias_resolution present: {hasattr(inv, '_run_alias_resolution')}")
print(f"  _update_actor_profiles present: {hasattr(inv, '_update_actor_profiles')}")
print(f"  _run_investigation_task present: {hasattr(inv, '_run_investigation_task')}")
