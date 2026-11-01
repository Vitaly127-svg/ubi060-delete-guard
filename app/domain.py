import time
import uuid

from sqlalchemy import delete, func, insert, select, update

from app.db import audit, datasets, dependencies, notifications, outbox, requests
from app.security import digest, valid_policy
from app.storage import StorageUnavailable


class Problem(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail
        super().__init__(detail)


class Controller:
    def __init__(self, db, storage, public_key, clock=time.time):
        self.db, self.storage, self.public_key, self.clock = db, storage, public_key, clock

    def _row(self, c, id):
        row = c.execute(select(datasets).where(datasets.c.id == id)).mappings().first()
        if row is None:
            raise Problem(404, "Набор не найден")
        return dict(row)

    @staticmethod
    def authorize(row, actor, write=True):
        if actor["role"] == "admin":
            return
        if actor["role"] == "scheduler" and write:
            return
        if actor["sub"] != row["owner"] or (write and actor["role"] != "owner"):
            raise Problem(403, "Недостаточно прав на набор")

    def event(self, c, row, actor, kind, rule=None):
        event = {"id": str(uuid.uuid4()), "time": self.clock(), "dataset_id": row["id"],
                 "owner": row["owner"], "actor": actor["sub"], "kind": kind, "rule": rule}
        c.execute(insert(outbox).values(id=event["id"], created_at=event["time"], payload=event, published=False))
        return event

    def create(self, id, owner, body, policy, signature, actor):
        if actor["role"] != "admin":
            raise Problem(403, "Создавать наборы может администратор")
        self.validate_policy(policy, signature)
        if policy["dataset_id"] != id:
            raise Problem(422, "Эталон выписан для другого набора")
        with self.db.transaction() as c:
            if c.execute(select(datasets.c.id).where(datasets.c.id == id)).first():
                raise Problem(409, "Набор уже существует")
            # An orphan payload is harmless if the SQL transaction fails; reads require a catalog row.
            self.storage.put(id, body)
            c.execute(insert(datasets).values(id=id, owner=owner, state="ACTIVE", created_at=self.clock(),
                deadline=None, content_hash=digest(body), policy=policy, baseline=policy,
                signature=signature, revision=1))
            self.event(c, {"id": id, "owner": owner}, actor, "created")
        return {"id": id, "state": "ACTIVE"}

    def validate_policy(self, policy, signature):
        keys = {"dataset_id", "version", "retention_seconds", "minimum_seconds", "delete_limit",
                "window_seconds", "quarantine_seconds"}
        if set(policy) != keys or any(type(policy[k]) is not int or policy[k] <= 0 for k in keys - {"dataset_id"}):
            raise Problem(422, "Неверная структура эталона")
        if not valid_policy(policy, signature, self.public_key):
            raise Problem(403, "Подпись эталона недействительна")
        if policy["retention_seconds"] < policy["minimum_seconds"]:
            raise Problem(422, "Эталон ниже минимального срока")

    def read(self, id, actor):
        with self.db.transaction() as c:
            row = self._row(c, id)
            self.authorize(row, actor, write=False)
            if row["state"] not in {"ACTIVE", "DEFERRED"}:
                raise Problem(410, "Набор скрыт карантином или удалён")
            body = self.storage.get(id)
            if body is None or digest(body) != row["content_hash"]:
                raise Problem(503, "Целостность данных не подтверждена")
            return {"id": id, "state": row["state"], "body": body}

    def policy(self, id, policy, signature, actor):
        if actor["role"] != "admin":
            raise Problem(403, "Политики меняет только администратор")
        self.validate_policy(policy, signature)
        with self.db.transaction() as c:
            row = self._row(c, id)
            if row["state"] not in {"ACTIVE", "DEFERRED"}:
                raise Problem(409, "Политика заморожена на время карантина")
            if policy["dataset_id"] != id or policy["version"] <= row["baseline"]["version"]:
                raise Problem(409, "Нужна новая версия эталона для этого набора")
            c.execute(update(datasets).where(datasets.c.id == id).values(policy=policy, baseline=policy,
                signature=signature, revision=row["revision"]+1, state="ACTIVE"))
            self.event(c, row, actor, "policy_updated")
        return {"id": id, "version": policy["version"]}

    def link(self, source, target, actor):
        if source == target:
            raise Problem(422, "Ссылка на сам набор запрещена")
        with self.db.transaction() as c:
            a, b = self._row(c, source), self._row(c, target)
            self.authorize(a, actor)
            if a["state"] not in {"ACTIVE", "DEFERRED"} or b["state"] not in {"ACTIVE", "DEFERRED"}:
                raise Problem(409, "Нельзя связать данные в карантине")
            if not c.execute(select(dependencies).where(dependencies.c.source == source,
                                                       dependencies.c.target == target)).first():
                c.execute(insert(dependencies).values(source=source, target=target))
            self.event(c, a, actor, "dependency_added")
        return {"source": source, "target": target}

    def _rules(self, c, row, actor, count=True, age=True):
        p = row["policy"]
        if not valid_policy(row["baseline"], row["signature"], self.public_key):
            return 403, "R1"
        if digest(p) != digest(row["baseline"]):
            return 403, "R2"
        if p["retention_seconds"] < p["minimum_seconds"]:
            return 403, "R3"
        if count:
            attempts = c.execute(select(func.count()).select_from(requests).where(
                requests.c.actor == actor["sub"], requests.c.created_at > self.clock()-p["window_seconds"])).scalar_one()
            if attempts >= p["delete_limit"]:
                return 403, "R4"
        if c.execute(select(dependencies.c.source).where(dependencies.c.target == row["id"])).first():
            return 409, "R5_dependencies"
        try:
            body = self.storage.get(row["id"])
        except StorageUnavailable:
            return 409, "R5_unavailable"
        if body is None or digest(body) != row["content_hash"]:
            return 409, "R5_content"
        if age and self.clock() < row["created_at"]+p["retention_seconds"]:
            return 409, "retention_not_expired"
        return 202, None

    def request_delete(self, id, key, actor):
        if actor["role"] not in {"owner", "admin", "scheduler"}:
            raise Problem(403, "Удаление запрещено для роли")
        if not key or len(key) > 100:
            raise Problem(422, "Нужен Idempotency-Key длиной 1–100")
        scope = actor["sub"]+":"+key
        fingerprint = digest({"dataset_id": id, "actor": actor["sub"]})
        with self.db.transaction() as c:
            row = self._row(c, id)
            self.authorize(row, actor)
            old = c.execute(select(requests).where(requests.c.id == scope)).mappings().first()
            if old:
                if old["fingerprint"] != fingerprint:
                    raise Problem(409, "Ключ уже использован для другого запроса")
                return old["code"], old["response"]
            if row["state"] == "QUARANTINED":
                code, rule = 202, None
            elif row["state"] == "PURGED":
                raise Problem(410, "Набор уже удалён")
            elif row["state"] == "PURGING":
                raise Problem(409, "Окончательное удаление уже началось")
            else:
                code, rule = self._rules(c, row, actor)
                state = "QUARANTINED" if code == 202 else ("ACTIVE" if code == 403 else "DEFERRED")
                deadline = self.clock()+row["policy"]["quarantine_seconds"] if code == 202 else None
                c.execute(update(datasets).where(datasets.c.id == id).values(state=state, deadline=deadline))
                self.event(c, row, actor, {202: "quarantined", 403: "blocked", 409: "deferred"}[code], rule)
            response = {"dataset_id": id, "decision": "allow" if code == 202 else "deny", "rule": rule,
                        "status": code}
            c.execute(insert(requests).values(id=scope, actor=actor["sub"], dataset_id=id,
                fingerprint=fingerprint, created_at=self.clock(), code=code, response=response))
            return code, response

    def restore(self, id, actor):
        with self.db.transaction() as c:
            row = self._row(c, id)
            if actor["role"] not in {"owner", "admin"}:
                raise Problem(403, "Восстановление разрешено владельцу и администратору")
            self.authorize(row, actor)
            if row["state"] == "ACTIVE":
                return {"id": id, "state": "ACTIVE"}
            if row["state"] not in {"QUARANTINED", "DEFERRED"}:
                raise Problem(409, "Восстановление уже невозможно")
            body = self.storage.get(id)
            if body is None or digest(body) != row["content_hash"]:
                raise Problem(409, "Данные для восстановления не подтверждены")
            c.execute(update(datasets).where(datasets.c.id == id).values(state="ACTIVE", deadline=None))
            self.event(c, row, actor, "restored")
        return {"id": id, "state": "ACTIVE"}

    def purge_one(self, id):
        # Phase 1 is durable BEFORE the nontransactional Cassandra DELETE.
        # PURGING is retried after crashes and can never be restored or linked.
        system = {"sub": "quarantine-worker", "role": "scheduler"}
        with self.db.transaction() as c:
            row = self._row(c, id)
            if row["state"] == "QUARANTINED":
                if row["deadline"] > self.clock():
                    return False
                code, rule = self._rules(c, row, system, count=False)
                if code != 202:
                    self.event(c, row, system, "purge_deferred", rule)
                    return False
                c.execute(update(datasets).where(datasets.c.id == id).values(state="PURGING"))
            elif row["state"] != "PURGING":
                return False
        self.storage.delete(id)  # Idempotent tombstone; a crash here leaves PURGING, never ACTIVE.
        with self.db.transaction() as c:
            row = self._row(c, id)
            if row["state"] == "PURGING":
                c.execute(update(datasets).where(datasets.c.id == id).values(state="PURGED"))
                c.execute(delete(dependencies).where(dependencies.c.source == id))
                self.event(c, row, system, "purged")
        return True

    def consume(self, event):
        with self.db.transaction() as c:
            if c.execute(select(audit.c.seq).where(audit.c.event_id == event["id"])).first():
                return False
            previous = c.execute(select(audit.c.record_hash).order_by(audit.c.seq.desc()).limit(1)).scalar()
            previous = previous or "0"*64
            record_hash = digest({"previous_hash": previous, "event": event})
            c.execute(insert(audit).values(event_id=event["id"], record=event,
                previous_hash=previous, record_hash=record_hash))
            recipient = "admin" if event["kind"] in {"blocked", "purge_deferred"} else event["owner"]
            c.execute(insert(notifications).values(event_id=event["id"], recipient=recipient, payload=event, read=False))
        return True

    def verify_audit(self):
        previous = "0"*64
        with self.db.transaction() as c:
            for row in c.execute(select(audit).order_by(audit.c.seq)).mappings():
                if row["previous_hash"] != previous or row["record_hash"] != digest({"previous_hash": previous, "event": row["record"]}):
                    return False
                previous = row["record_hash"]
        return True
