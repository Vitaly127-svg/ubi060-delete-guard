from contextlib import contextmanager

from sqlalchemy import (JSON, Boolean, Column, Float, Index, Integer, MetaData, String,
                        Table, Text, create_engine, insert, select)
from sqlalchemy.dialects.postgresql import JSONB

J = JSON().with_variant(JSONB(), "postgresql")

meta = MetaData()
mutex = Table("transaction_mutex", meta, Column("id", Integer, primary_key=True))
datasets = Table("datasets", meta,
    Column("id", String(80), primary_key=True), Column("owner", String(80), nullable=False),
    Column("state", String(20), nullable=False), Column("created_at", Float, nullable=False),
    Column("deadline", Float), Column("content_hash", String(64), nullable=False),
    Column("policy", J, nullable=False), Column("baseline", J, nullable=False),
    Column("signature", Text, nullable=False), Column("revision", Integer, nullable=False, default=1))
dependencies = Table("dependency_graph", meta,
    Column("source", String(80), primary_key=True), Column("target", String(80), primary_key=True))
requests = Table("deletion_requests", meta,
    Column("id", String(220), primary_key=True), Column("actor", String(80), index=True),
    Column("dataset_id", String(80), index=True), Column("created_at", Float, index=True),
    Column("fingerprint", String(64)), Column("code", Integer), Column("response", J))
outbox = Table("outbox", meta, Column("id", String(36), primary_key=True),
    Column("created_at", Float, index=True), Column("payload", J, nullable=False),
    Column("published", Boolean, nullable=False, default=False))
audit = Table("audit_log", meta,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("event_id", String(36), nullable=False, unique=True), Column("record", J, nullable=False),
    Column("previous_hash", String(64), nullable=False), Column("record_hash", String(64), nullable=False))
notifications = Table("notifications", meta, Column("event_id", String(36), primary_key=True),
    Column("recipient", String(80), nullable=False), Column("payload", J, nullable=False),
    Column("read", Boolean, nullable=False, default=False))
Index("ix_dependency_target", dependencies.c.target)
Index("ix_policy_baseline_gin", datasets.c.baseline, postgresql_using="gin")


class Database:
    def __init__(self, url: str):
        options = {"check_same_thread": False, "timeout": 30} if url.startswith("sqlite") else {}
        self.engine = create_engine(url, pool_pre_ping=True, connect_args=options)

    def initialize(self):
        # Invoked by the one-off bootstrap job, never concurrently by API replicas.
        meta.create_all(self.engine)
        with self.engine.begin() as c:
            if c.execute(select(mutex.c.id)).first() is None:
                c.execute(insert(mutex).values(id=1))

    @contextmanager
    def transaction(self):
        with self.engine.connect() as c:
            if self.engine.dialect.name == "sqlite":
                c.exec_driver_sql("BEGIN IMMEDIATE")
            else:
                c.begin()
                c.execute(select(mutex.c.id).where(mutex.c.id == 1).with_for_update()).one()
            try:
                yield c
                c.commit()
            except BaseException:
                c.rollback()
                raise

    def ready(self):
        with self.engine.connect() as c:
            return c.execute(select(mutex.c.id).where(mutex.c.id == 1)).scalar_one() == 1
