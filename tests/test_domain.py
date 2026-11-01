from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import func, select, update

from app.db import audit, datasets, outbox
from app.domain import Problem
from app.security import digest, sign_policy
from app.storage import StorageUnavailable


def state(core, id="free"):
    with core.db.engine.connect() as c:
        return c.execute(select(datasets.c.state).where(datasets.c.id == id)).scalar_one()


def test_accept_hides_then_restore(rig):
    core, now, seed, admin, owner = rig
    seed()
    assert core.request_delete("free", "k1", owner)[0] == 202
    with pytest.raises(Problem) as e:
        core.read("free", owner)
    assert e.value.status == 410
    assert core.restore("free", owner)["state"] == "ACTIVE"
    assert core.read("free", owner)["body"] == {"data": "free"}


def test_idempotency_does_not_extend_deadline(rig):
    core, now, seed, admin, owner = rig
    seed()
    first = core.request_delete("free", "same", owner)
    now[0] += 5
    assert core.request_delete("free", "same", owner) == first
    with core.db.engine.connect() as c:
        assert c.execute(select(datasets.c.deadline)).scalar_one() == 1010
        events = list(c.execute(select(outbox.c.payload)).scalars())
    assert sum(e["kind"] == "quarantined" for e in events) == 1


def test_key_cannot_be_reused_for_other_dataset(rig):
    core, now, seed, admin, owner = rig
    seed("a");seed("b")
    core.request_delete("a", "same", owner)
    with pytest.raises(Problem) as e:
        core.request_delete("b", "same", owner)
    assert e.value.status == 409


@pytest.mark.parametrize("rule", ["R1", "R2", "R3"])
def test_policy_rules(rig, keys, rule):
    core, now, seed, admin, owner = rig
    policy = seed()
    values = {}
    if rule == "R1":
        values = {"signature": "broken"}
    elif rule == "R2":
        values = {"policy": dict(policy, retention_seconds=1)}
    else:
        bad = dict(policy, retention_seconds=1)
        values = {"policy": bad, "baseline": bad, "signature": sign_policy(bad, keys[0])}
    with core.db.transaction() as c:
        c.execute(update(datasets).values(**values))
    code, result = core.request_delete("free", "k", owner)
    assert (code, result["rule"]) == (403, rule)
    assert state(core) == "ACTIVE"
    assert core.storage.get("free") is not None


def test_r4_counter_shared_by_two_controllers(rig):
    from app.domain import Controller
    core, now, seed, admin, owner = rig
    for id in ["a", "b", "c"]:seed(id, limit=2)
    other = Controller(core.db, core.storage, core.public_key, core.clock)
    assert core.request_delete("a", "a", owner)[0] == 202
    assert other.request_delete("b", "b", owner)[0] == 202
    assert core.request_delete("c", "c", owner)[1]["rule"] == "R4"


def test_dependency_prevents_deletion(rig):
    core, now, seed, admin, owner = rig
    seed("reference");seed("dependent")
    core.link("dependent", "reference", owner)
    code, result = core.request_delete("reference", "x", owner)
    assert (code, result["rule"]) == (409, "R5_dependencies")
    assert core.read("reference", owner)["state"] == "DEFERRED"


def test_unavailable_storage_defers(rig):
    core, now, seed, admin, owner = rig
    seed();core.storage.available = False
    assert core.request_delete("free", "x", owner)[1]["rule"] == "R5_unavailable"
    assert state(core) == "DEFERRED"


def test_content_mismatch_defers(rig):
    core, now, seed, admin, owner = rig
    seed();core.storage.put("free", {"corrupt": True})
    assert core.request_delete("free", "x", owner)[1]["rule"] == "R5_content"


def test_minimum_age_is_enforced(rig):
    core, now, seed, admin, owner = rig
    seed(age=50)
    assert core.request_delete("free", "x", owner)[1]["rule"] == "retention_not_expired"


def test_purge_expiration_and_exactly_one_event(rig):
    core, now, seed, admin, owner = rig
    seed();core.request_delete("free", "x", owner)
    assert core.purge_one("free") is False
    now[0] += 11
    assert core.purge_one("free") is True
    assert core.purge_one("free") is False
    assert state(core) == "PURGED"
    assert core.storage.get("free") is None
    with core.db.engine.connect() as c:
        events = list(c.execute(select(outbox.c.payload)).scalars())
    assert sum(e["kind"] == "purged" for e in events) == 1


def test_purge_rechecks_policy(rig):
    core, now, seed, admin, owner = rig
    policy = seed();core.request_delete("free", "x", owner);now[0] += 11
    with core.db.transaction() as c:
        c.execute(update(datasets).values(policy=dict(policy, retention_seconds=1)))
    assert core.purge_one("free") is False
    assert state(core) == "QUARANTINED"
    assert core.storage.get("free") is not None


def test_crash_after_cassandra_delete_is_recoverable(rig):
    core, now, seed, admin, owner = rig
    seed();core.request_delete("free", "x", owner);now[0] += 11
    original = core.storage.delete
    def crash(id):
        original(id)
        raise StorageUnavailable("Crash after DELETE")
    core.storage.delete = crash
    with pytest.raises(StorageUnavailable):core.purge_one("free")
    assert state(core) == "PURGING"
    with pytest.raises(Problem):core.restore("free", owner)
    core.storage.delete = original
    assert core.purge_one("free") is True
    assert state(core) == "PURGED"


def test_frozen_catalog_rejects_link_and_policy_change(rig, keys):
    core, now, seed, admin, owner = rig
    policy = seed();seed("other");core.request_delete("free", "x", owner)
    with pytest.raises(Problem):core.link("other", "free", owner)
    policy = dict(policy, version=2)
    with pytest.raises(Problem):core.policy("free", policy, sign_policy(policy, keys[0]), admin)


def test_concurrent_delete_is_idempotent(rig):
    core, now, seed, admin, owner = rig
    seed()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: core.request_delete("free", "same", owner), range(2)))
    assert results[0] == results[1]
    with core.db.engine.connect() as c:
        events = list(c.execute(select(outbox.c.payload)).scalars())
    assert sum(e["kind"] == "quarantined" for e in events) == 1


def test_audit_deduplication_and_tamper_detection(rig):
    core, now, seed, admin, owner = rig
    seed()
    with core.db.engine.connect() as c:
        event = c.execute(select(outbox.c.payload)).scalar_one()
    assert core.consume(event)
    assert not core.consume(event)
    assert core.verify_audit()
    with core.db.transaction() as c:
        c.execute(update(audit).values(record=dict(event, kind="forged")))
    assert not core.verify_audit()


def test_foreign_owner_and_analyst_cannot_delete(rig):
    core, now, seed, admin, owner = rig
    seed()
    for actor in [{"sub": "bob", "role": "owner"}, {"sub": "alice", "role": "analyst"}]:
        with pytest.raises(Problem) as e:core.request_delete("free", "x", actor)
        assert e.value.status == 403


def test_policy_version_cannot_roll_back(rig, keys):
    core, now, seed, admin, owner = rig
    policy = seed()
    with pytest.raises(Problem) as e:core.policy("free", policy, sign_policy(policy, keys[0]), admin)
    assert e.value.status == 409
