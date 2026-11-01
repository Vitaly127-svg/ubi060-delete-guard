import importlib
from types import SimpleNamespace

from cassandra import ConsistencyLevel
from app.storage import CassandraStorage


def test_cluster_bootstrap_imports_installed_driver():
    module = importlib.import_module("scripts.bootstrap_cluster")
    assert module.AsyncioConnection.__module__ == "cassandra.io.asyncioreactor"


def test_cassandra_statements_use_all_without_ttl():
    executed = []
    class Session:
        def prepare(self, query):
            return SimpleNamespace(query=query, consistency_level=None)
        def execute(self, statement, args, timeout):
            assert statement.consistency_level == ConsistencyLevel.ALL
            assert "TTL" not in statement.query
            executed.append(statement.query)
            return SimpleNamespace(one=lambda: SimpleNamespace(body='{"value":1}'))
    storage = CassandraStorage(["unused"], "reader", "unused")
    storage.session = Session()
    storage.put("a", {"value": 1})
    assert storage.get("a") == {"value": 1}
    storage.delete("a")
    assert len(executed) == 3
