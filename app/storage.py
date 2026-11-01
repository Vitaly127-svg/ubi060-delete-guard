"""A real Cassandra adapter and an explicitly selected local test adapter."""
import json
import sqlite3
import threading


class StorageUnavailable(Exception):
    pass


class LocalStorage:
    """SQLite payloads for local execution; NOT a simulation of Cassandra replicas."""
    def __init__(self, path):
        self.path = str(path)
        with sqlite3.connect(self.path) as c:
            c.execute("CREATE TABLE IF NOT EXISTS payloads(id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        self.available = True

    def put(self, id, body):
        self._check()
        with sqlite3.connect(self.path, timeout=30) as c:
            c.execute("INSERT OR REPLACE INTO payloads VALUES (?, ?)", (id, json.dumps(body)))

    def get(self, id):
        self._check()
        with sqlite3.connect(self.path, timeout=30) as c:
            row = c.execute("SELECT body FROM payloads WHERE id=?", (id,)).fetchone()
        return json.loads(row[0]) if row else None

    def delete(self, id):
        self._check()
        with sqlite3.connect(self.path, timeout=30) as c:
            c.execute("DELETE FROM payloads WHERE id=?", (id,))

    def _check(self):
        if not self.available:
            raise StorageUnavailable("Storage is unavailable")


class CassandraStorage:
    def __init__(self, hosts, user, password):
        self.hosts, self.user, self.password = hosts, user, password
        self.session = None
        self.lock = threading.Lock()

    def _connect(self):
        if self.session is None:
            with self.lock:
                if self.session is None:
                    from cassandra.cluster import Cluster
                    from cassandra.auth import PlainTextAuthProvider
                    from cassandra.io.asyncioreactor import AsyncioConnection
                    from cassandra.policies import DCAwareRoundRobinPolicy
                    self.cluster = Cluster(self.hosts,
                        auth_provider=PlainTextAuthProvider(self.user, self.password),
                        connection_class=AsyncioConnection,
                        load_balancing_policy=DCAwareRoundRobinPolicy(local_dc="dc1"))
                    self.session = self.cluster.connect("ubi060")
        return self.session

    def _execute(self, query, args):
        from cassandra import ConsistencyLevel
        try:
            stmt = self._connect().prepare(query)
            stmt.consistency_level = ConsistencyLevel.ALL
            return self.session.execute(stmt, args, timeout=8)
        except Exception as exc:
            raise StorageUnavailable(type(exc).__name__) from exc

    def put(self, id, body):
        self._execute("INSERT INTO payloads(id, body) VALUES (?, ?)", (id, json.dumps(body)))

    def get(self, id):
        row = self._execute("SELECT body FROM payloads WHERE id=?", (id,)).one()
        return json.loads(row.body) if row else None

    def delete(self, id):
        # Cassandra writes tombstones here. Disk reclamation happens later in compaction.
        self._execute("DELETE FROM payloads WHERE id=?", (id,))
