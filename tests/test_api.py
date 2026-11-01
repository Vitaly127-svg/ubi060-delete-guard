from dataclasses import replace
from fastapi.testclient import TestClient
import pytest
from app.api import create_app
from app.config import Settings
from app.security import issue_token, password_hash


def config(keys, service):
    return Settings(service, "sqlite://", "", keys[1], keys[1], keys[0],
                    {"alice": {"role": "owner", "hash": password_hash("testing-password")}})


def test_http_login_delete_hidden_restore(rig, keys):
    core, now, seed, admin, owner = rig
    seed()
    with TestClient(create_app(config(keys, "auth-service"), core)) as auth:
        assert auth.post("/token", json={"username": "alice", "password": "wrong"}).status_code == 401
        token = auth.post("/token", json={"username": "alice", "password": "testing-password"}).json()["access_token"]
        headers = {"Authorization": "Bearer "+token}
        assert auth.get("/verify", headers=headers).status_code == 200
    with TestClient(create_app(config(keys, "delete-guard"), core)) as guard:
        assert guard.delete("/deletions/free", headers={"X-Role": "admin", "Idempotency-Key": "x"}).status_code == 401
        assert guard.delete("/deletions/free", headers=headers).status_code == 422
        response = guard.delete("/deletions/free", headers=headers | {"Idempotency-Key": "x"})
        assert response.status_code == 202
        assert response.json()["decision"] == "allow"
        assert 'deletion_requests_total{decision="202"} 1.0' in guard.get("/metrics").text
    with TestClient(create_app(config(keys, "data-api"), core)) as data:
        assert data.get("/datasets/free", headers=headers).status_code == 410
    with TestClient(create_app(config(keys, "quarantine-service"), core)) as q:
        assert q.post("/quarantine/free/restore", headers=headers).status_code == 200
    with TestClient(create_app(config(keys, "data-api"), core)) as data:
        assert data.get("/datasets/free", headers=headers).status_code == 200


@pytest.mark.parametrize("token_kind", ["expired", "wrong_key", "malformed"])
def test_bad_jwt_rejected(rig, keys, token_kind):
    from app.security import keypair
    core, now, seed, admin, owner = rig
    seed()
    token = {"expired": issue_token("alice", "owner", keys[0], lifetime=-1),
             "wrong_key": issue_token("alice", "owner", keypair()[0]), "malformed": "abc"}[token_kind]
    with TestClient(create_app(config(keys, "data-api"), core)) as data:
        assert data.get("/datasets/free", headers={"Authorization": "Bearer "+token}).status_code == 401


def test_audit_http_requires_admin(rig, keys):
    core, now, seed, admin, owner = rig
    with TestClient(create_app(config(keys, "audit-service"), core)) as client:
        ordinary = issue_token("alice", "owner", keys[0])
        administrator = issue_token("admin", "admin", keys[0])
        assert client.get("/audit", headers={"Authorization": "Bearer "+ordinary}).status_code == 403
        assert client.get("/audit/verify", headers={"Authorization": "Bearer "+administrator}).json() == {"valid": True}
