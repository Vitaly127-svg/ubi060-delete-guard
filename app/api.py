import asyncio
from contextlib import asynccontextmanager
from typing import Annotated

import httpx
import jwt
from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from app.config import Settings
from app.db import Database, audit, datasets, notifications
from app.domain import Controller, Problem
from app.messaging import consumer, publisher, sweeper
from app.security import issue_token, password_matches, verify_token
from app.storage import CassandraStorage, LocalStorage, StorageUnavailable


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class PolicyUpdate(BaseModel):
    policy: dict
    signature: str = Field(max_length=4096)


class DatasetInput(PolicyUpdate):
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    owner: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    body: dict


class Link(BaseModel):
    source: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    target: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")


def create_app(settings=None, controller=None):
    cfg = settings or Settings.environment()
    db = controller.db if controller else Database(cfg.database_url)
    if controller is None:
        storage = (LocalStorage(cfg.payload_path) if cfg.storage_backend == "local" else
                   CassandraStorage(cfg.cassandra_hosts, cfg.cassandra_user, cfg.cassandra_password))
        controller = Controller(db, storage, cfg.policy_public)
    registry = CollectorRegistry()
    decisions = Counter("deletion_requests_total", "HTTP deletion responses", ["decision"], registry=registry)
    blocked = Counter("deletion_blocked_total", "Denied deletion requests", ["rule"], registry=registry)
    duration = Histogram("guard_check_seconds", "Deletion decision duration", registry=registry)
    quarantine = Gauge("quarantine_datasets", "Current quarantined datasets", registry=registry)
    http_count = Counter("http_requests_total", "Requests handled by this service", ["service", "status"], registry=registry)

    @asynccontextmanager
    async def lifespan(app):
        tasks = []
        if cfg.workers:
            if cfg.service == "delete-guard":
                tasks.append(asyncio.create_task(publisher(controller, cfg.amqp_url)))
            elif cfg.service == "audit-service":
                tasks.append(asyncio.create_task(consumer(controller, cfg.amqp_url)))
            elif cfg.service == "quarantine-service":
                tasks.append(asyncio.create_task(sweeper(controller, cfg.sweep_seconds)))
        yield
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(title=cfg.service, lifespan=lifespan)
    app.state.controller = controller
    bearer = HTTPBearer(auto_error=False)

    def actor(credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)]):
        if credentials is None:
            raise Problem(401, "Нужен Bearer JWT")
        try:
            return verify_token(credentials.credentials, cfg.jwt_public)
        except jwt.InvalidTokenError:
            raise Problem(401, "JWT недействителен или истёк")

    @app.exception_handler(Problem)
    async def problem_handler(request, exc):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status,
                            headers={"WWW-Authenticate": "Bearer"} if exc.status == 401 else None)

    @app.exception_handler(StorageUnavailable)
    async def unavailable_handler(request, exc):
        return JSONResponse({"detail": "Хранилище временно недоступно"}, status_code=503)

    @app.exception_handler(SQLAlchemyError)
    async def database_unavailable(request, exc):
        return JSONResponse({"detail": "База данных временно недоступна; операция не разрешена"}, status_code=503)

    @app.middleware("http")
    async def metrics(request, call_next):
        response = await call_next(request)
        http_count.labels(cfg.service, str(response.status_code)).inc()
        return response

    @app.get("/healthz")
    def health():
        return {"service": cfg.service, "status": "alive"}

    @app.get("/readyz")
    def ready():
        if cfg.service != "auth-service":
            try:
                if not db.ready():
                    raise ValueError()
            except Exception:
                raise Problem(503, "База данных ещё не готова")
        return {"ready": True}

    @app.get("/metrics")
    def metric_values():
        if cfg.service == "quarantine-service":
            with db.engine.connect() as c:
                quarantine.set(c.execute(select(func.count()).select_from(datasets).where(
                    datasets.c.state.in_(["QUARANTINED", "PURGING"]))).scalar_one())
        return Response(generate_latest(registry), media_type="text/plain; version=0.0.4")

    if cfg.service == "auth-service":
        @app.post("/token")
        def token(data: Login):
            user = (cfg.users or {}).get(data.username)
            # Unknown users still pay the PBKDF2 cost.
            encoded = user["hash"] if user else "pbkdf2$600000$"+"00"*16+"$"+"00"*32
            if not password_matches(data.password, encoded) or user is None:
                raise Problem(401, "Неверный логин или пароль")
            return {"access_token": issue_token(data.username, user["role"], cfg.jwt_private), "token_type": "bearer"}

        @app.get("/verify")
        def verify(who=Depends(actor)):
            return {"sub": who["sub"], "role": who["role"]}

    elif cfg.service == "delete-guard":
        @app.post("/catalog", status_code=201)
        def create(data: DatasetInput, who=Depends(actor)):
            return controller.create(data.id, data.owner, data.body, data.policy, data.signature, who)

        @app.put("/policies/{id}")
        def policy(id: str, data: PolicyUpdate, who=Depends(actor)):
            return controller.policy(id, data.policy, data.signature, who)

        @app.post("/dependencies", status_code=201)
        def link(data: Link, who=Depends(actor)):
            return controller.link(data.source, data.target, who)

        @app.get("/catalog/due")
        def due(who=Depends(actor)):
            if who["role"] not in {"scheduler", "admin"}:
                raise Problem(403, "Только для задания очистки")
            with db.engine.connect() as c:
                rows = c.execute(select(datasets).where(datasets.c.state.in_(["ACTIVE", "DEFERRED"]))).mappings()
                return [r["id"] for r in rows if controller.clock() >= r["created_at"]+r["policy"]["retention_seconds"]]

        @app.delete("/deletions/{id}")
        def deletion(id: str, idempotency_key: Annotated[str, Header(min_length=1, max_length=100)], who=Depends(actor)):
            with duration.time():
                code, result = controller.request_delete(id, idempotency_key, who)
            decisions.labels(str(code)).inc()
            if code != 202:
                blocked.labels(result["rule"] or "unknown").inc()
            return JSONResponse(result, status_code=code)

    elif cfg.service == "data-api":
        @app.get("/datasets/{id}")
        def read(id: str, who=Depends(actor)):
            return controller.read(id, who)

        @app.post("/datasets", status_code=201)
        def create(data: DatasetInput, authorization: Annotated[str, Header()], who=Depends(actor)):
            if who["role"] != "admin":
                raise Problem(403, "Загрузка разрешена администратору")
            # data-api has only Cassandra SELECT; the trusted guard performs writes.
            try:
                response = httpx.post(cfg.guard_url+"/catalog", json=data.model_dump(),
                                      headers={"Authorization": authorization}, timeout=15)
            except httpx.HTTPError:
                raise Problem(503, "Сервис записи недоступен")
            return JSONResponse(response.json(), status_code=response.status_code)

    elif cfg.service == "quarantine-service":
        @app.post("/quarantine/{id}/restore")
        def restore(id: str, who=Depends(actor)):
            return controller.restore(id, who)

        @app.get("/quarantine")
        def quarantine_list(who=Depends(actor)):
            with db.engine.connect() as c:
                query = select(datasets.c.id, datasets.c.owner, datasets.c.state, datasets.c.deadline).where(
                    datasets.c.state.in_(["QUARANTINED", "PURGING"]))
                if who["role"] != "admin":
                    query = query.where(datasets.c.owner == who["sub"])
                return [dict(r) for r in c.execute(query).mappings()]

    elif cfg.service == "audit-service":
        @app.get("/audit/verify")
        def verify_audit(who=Depends(actor)):
            if who["role"] != "admin":
                raise Problem(403, "Только для администратора")
            return {"valid": controller.verify_audit()}

        @app.get("/notifications")
        def inbox(who=Depends(actor)):
            recipient = "admin" if who["role"] == "admin" else who["sub"]
            with db.engine.connect() as c:
                return [dict(r) for r in c.execute(select(notifications).where(
                    notifications.c.recipient == recipient).limit(100)).mappings()]

        @app.get("/audit")
        def journal(who=Depends(actor)):
            if who["role"] != "admin":
                raise Problem(403, "Только для администратора")
            with db.engine.connect() as c:
                return [dict(r) for r in c.execute(select(audit).order_by(audit.c.seq.desc()).limit(100)).mappings()]
    else:
        raise ValueError("Unknown SERVICE: "+cfg.service)
    return app
