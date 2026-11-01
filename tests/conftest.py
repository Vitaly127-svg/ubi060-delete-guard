import pytest
from sqlalchemy import update
from app.db import Database, datasets
from app.domain import Controller
from app.security import keypair, sign_policy
from app.storage import LocalStorage


@pytest.fixture(scope="session")
def keys():
    return keypair()


@pytest.fixture
def rig(tmp_path, keys):
    db = Database("sqlite:///"+str(tmp_path/"catalog.db"))
    db.initialize()
    storage = LocalStorage(tmp_path/"payload.db")
    now = [1000.0]
    core = Controller(db, storage, keys[1], clock=lambda: now[0])
    admin = {"sub": "admin", "role": "admin"}
    owner = {"sub": "alice", "role": "owner"}

    def seed(id="free", limit=10, age=200):
        policy = {"dataset_id": id, "version": 1, "retention_seconds": 100,
                  "minimum_seconds": 100, "delete_limit": limit, "window_seconds": 60,
                  "quarantine_seconds": 10}
        core.create(id, "alice", {"data": id}, policy, sign_policy(policy, keys[0]), admin)
        with db.transaction() as c:
            c.execute(update(datasets).where(datasets.c.id == id).values(created_at=now[0]-age))
        return policy

    return core, now, seed, admin, owner
