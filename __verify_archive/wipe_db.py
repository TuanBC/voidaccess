"""Wipe actor profile tables for a clean verify run."""
import os
from pathlib import Path

DB_PATH = Path(os.path.expanduser("~/.voidaccess/investigations.db"))
os.environ["DATABASE_URL"] = f"sqlite:///{DB_PATH}"
os.environ["VOIDACCESS_DB_PATH"] = str(DB_PATH)

from db.models import Base
from db.session import get_engine

engine = get_engine()
Base.metadata.drop_all(engine)
Base.metadata.create_all(engine)
print(f"Wiped and recreated tables on: {engine.url}")
