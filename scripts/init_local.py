import json
import secrets
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sqlalchemy import select, update
from app.db import Database, datasets
from app.domain import Controller
from app.security import keypair, password_hash, sign_policy
from app.storage import LocalStorage


def initialize(root=ROOT/".local"):
    root.mkdir(parents=True, exist_ok=True)
    if (root/"config.json").exists():
        return root
    jwt_private, jwt_public = keypair()
    policy_private, policy_public = keypair()
    for name, value in {"jwt-private.pem": jwt_private, "jwt-public.pem": jwt_public,
                        "policy-private.pem": policy_private, "policy-public.pem": policy_public}.items():
        (root/name).write_bytes(value)
    credentials = {name: secrets.token_urlsafe(18) for name in ["admin", "alice", "analyst", "scheduler"]}
    users = {name: {"role": role, "hash": password_hash(credentials[name])} for name, role in
             [("admin", "admin"), ("alice", "owner"), ("analyst", "analyst"), ("scheduler", "scheduler")]}
    config = {"database_url": "sqlite:///"+str(root/"catalog.db"), "payload_path": str(root/"payloads.db"),
              "storage_backend": "local", "workers": False, "guard_url": "http://127.0.0.1:8002"}
    (root/"credentials.json").write_text(json.dumps(credentials, indent=2), encoding="utf-8")
    (root/"users.json").write_text(json.dumps(users, indent=2), encoding="utf-8")
    db = Database(config["database_url"]);db.initialize()
    core = Controller(db, LocalStorage(config["payload_path"]), policy_public)
    seed(core, policy_private, quarantine_seconds=8)
    (root/"config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    return root


def seed(core, private, quarantine_seconds=60):
    admin = {"sub": "admin", "role": "admin"}
    for id in ["free", "reference", "dependent", "tampered", "purge-demo"]:
        with core.db.engine.connect() as c:
            exists = c.execute(select(datasets.c.id).where(datasets.c.id == id)).first()
        if exists:
            continue
        policy = {"dataset_id": id, "version": 1, "retention_seconds": 30*86400,
                  "minimum_seconds": 30*86400, "delete_limit": 20, "window_seconds": 60,
                  "quarantine_seconds": quarantine_seconds}
        core.create(id, "alice", {"records": [{"id": 1, "value": "demo-"+id}]},
                    policy, sign_policy(policy, private), admin)
        # Synthetic, explicitly dated fixtures make expiry reproducible without waiting 30 days.
        with core.db.transaction() as c:
            values = {"created_at": time.time()-31*86400}
            if id == "tampered":
                values["policy"] = dict(policy, retention_seconds=3600)
            c.execute(update(datasets).where(datasets.c.id == id).values(**values))
    core.link("dependent", "reference", admin)


if __name__ == "__main__":
    print("Local fixture ready:", initialize())
    print("Passwords are stored only in .local/credentials.json; do not commit them.")
