import json
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Settings:
    service: str
    database_url: str
    payload_path: str
    jwt_public: bytes
    policy_public: bytes
    jwt_private: bytes = b""
    users: dict | None = None
    storage_backend: str = "local"
    cassandra_hosts: tuple = ("cassandra.data.svc.cluster.local",)
    cassandra_user: str = ""
    cassandra_password: str = ""
    amqp_url: str = ""
    guard_url: str = "http://delete-guard.pattern.svc.cluster.local:8002"
    sweep_seconds: int = 3600
    workers: bool = False

    @classmethod
    def environment(cls):
        root = Path(os.environ.get("SECRET_DIR", ".local"))
        config = json.loads((root/"config.json").read_text())
        service = os.environ.get("SERVICE", "delete-guard")
        return cls(service=service, database_url=config["database_url"],
            payload_path=config.get("payload_path", ".local/payloads.db"),
            jwt_public=(root/"jwt-public.pem").read_bytes(),
            policy_public=(root/"policy-public.pem").read_bytes(),
            jwt_private=(root/"jwt-private.pem").read_bytes() if service == "auth-service" else b"",
            users=json.loads((root/"users.json").read_text()) if service == "auth-service" else {},
            storage_backend=config.get("storage_backend", "cassandra"),
            cassandra_hosts=tuple(config.get("cassandra_hosts", ["cassandra.data.svc.cluster.local"])),
            cassandra_user=config.get("cassandra_user", ""), cassandra_password=config.get("cassandra_password", ""),
            amqp_url=config.get("amqp_url", ""), guard_url=config.get("guard_url", cls.guard_url),
            sweep_seconds=config.get("sweep_seconds", 3600), workers=config.get("workers", True))
