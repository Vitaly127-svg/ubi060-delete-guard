import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1];sys.path.insert(0, str(ROOT))
import psycopg
from psycopg import sql
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider
from cassandra.io.asyncioreactor import AsyncioConnection
from cassandra.policies import DCAwareRoundRobinPolicy
from app.db import Database
from app.domain import Controller
from app.storage import CassandraStorage
from scripts.init_local import seed


def bootstrap():
    root = Path(os.environ.get("SECRET_DIR", "/run/config"));cfg = json.loads((root/"config.json").read_text())
    pg_url = f"postgresql+psycopg://postgres:{cfg['postgres_password']}@postgres.pattern.svc.cluster.local:5432/ubi060"
    db = Database(pg_url);db.initialize()
    grants = {"reader": {"datasets": "SELECT", "transaction_mutex": "SELECT, UPDATE"},
        "guard": {"datasets": "SELECT, INSERT, UPDATE", "dependency_graph": "SELECT, INSERT, DELETE",
                  "deletion_requests": "SELECT, INSERT", "outbox": "SELECT, INSERT, UPDATE", "transaction_mutex": "SELECT, UPDATE"},
        "quarantine": {"datasets": "SELECT, UPDATE", "dependency_graph": "SELECT, DELETE",
                       "outbox": "SELECT, INSERT", "transaction_mutex": "SELECT, UPDATE"},
        "audit": {"audit_log": "SELECT, INSERT", "notifications": "SELECT, INSERT", "transaction_mutex": "SELECT, UPDATE"}}
    with psycopg.connect(pg_url.replace("postgresql+psycopg", "postgresql"), autocommit=True) as c:
        for role, password in cfg["roles"].items():
            exists = c.execute("SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
            verb = "ALTER" if exists else "CREATE"
            c.execute(sql.SQL(verb+" ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            c.execute(sql.SQL("GRANT CONNECT ON DATABASE ubi060 TO {}").format(sql.Identifier(role)))
            c.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(role)))
            for table, rights in grants[role].items():
                c.execute(sql.SQL("GRANT "+rights+" ON TABLE {} TO {}").format(sql.Identifier(table), sql.Identifier(role)))
            if role == "audit":c.execute("GRANT USAGE, SELECT ON SEQUENCE audit_log_seq_seq TO audit")
    cluster = None
    for password in [cfg["cassandra_password"], "cassandra"]:
        try:
            cluster = Cluster(["cassandra.data.svc.cluster.local"],
                auth_provider=PlainTextAuthProvider("cassandra", password), connection_class=AsyncioConnection,
                load_balancing_policy=DCAwareRoundRobinPolicy(local_dc="dc1"))
            session = cluster.connect();break
        except Exception:
            if cluster:cluster.shutdown()
    else:raise RuntimeError("Cassandra bootstrap authentication failed")
    try:
        rf = cfg["replication"]
        assert rf in [1, 3]
        session.execute("CREATE KEYSPACE IF NOT EXISTS ubi060 WITH replication = {'class':'NetworkTopologyStrategy','dc1':"+str(rf)+"}")
        session.execute("CREATE TABLE IF NOT EXISTS ubi060.payloads(id text PRIMARY KEY, body text) WITH default_time_to_live=0")
        # Generated passwords contain only URL-safe ASCII; role names come from a fixed list.
        for role in ["reader", "guard", "quarantine"]:
            password = cfg["roles"][role]
            assert all(ch.isalnum() or ch in "_-" for ch in password)
            session.execute(f"CREATE ROLE IF NOT EXISTS {role} WITH PASSWORD='{password}' AND LOGIN=true")
            session.execute(f"GRANT SELECT ON TABLE ubi060.payloads TO {role}")
            if role != "reader":session.execute(f"GRANT MODIFY ON TABLE ubi060.payloads TO {role}")
        new_password = cfg["cassandra_password"]
        assert all(ch.isalnum() or ch in "_-" for ch in new_password)
        session.execute(f"ALTER ROLE cassandra WITH PASSWORD='{new_password}'")
    finally:
        cluster.shutdown()
    storage = CassandraStorage(["cassandra.data.svc.cluster.local"], "guard", cfg["roles"]["guard"])
    core = Controller(db, storage, (root/"policy-public.pem").read_bytes())
    seed(core, (root/"policy-private.pem").read_bytes(), quarantine_seconds=60)
    print("Bootstrap complete: schema, least-privilege roles, TTL=0, five synthetic fixtures.")


if __name__ == "__main__":
    # DNS, authentication and the Cassandra native protocol may become ready at different times.
    for attempt in range(30):
        try:bootstrap();break
        except Exception as exc:
            print("Bootstrap retry:", type(exc).__name__, flush=True)
            if attempt == 29:raise
            time.sleep(5)
