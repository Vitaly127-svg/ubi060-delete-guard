"""Create per-service Secrets without writing their contents to stdout or Git."""
import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import secrets
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from app.security import keypair, password_hash


def apply_secret(name, ns, files=None, literals=None):
    args = ["kubectl", "-n", ns, "create", "secret", "generic", name]
    args += ["--from-file="+k+"="+str(v) for k, v in (files or {}).items()]
    # Values are piped as JSON to kubectl apply, never printed.
    manifest = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": ns},
                "type": "Opaque", "stringData": {k: Path(v).read_text() for k, v in (files or {}).items()} | (literals or {})}
    result = subprocess.run(["kubectl", "apply", "-f", "-"], input=json.dumps(manifest),
                            text=True, encoding="utf-8", capture_output=True)
    if result.returncode:raise RuntimeError("Secret creation failed for "+name+": "+result.stderr)
    print("Secret ready:", ns+"/"+name)


def main():
    p = argparse.ArgumentParser();p.add_argument("--ip", default="127.0.0.1");p.add_argument("--replication", type=int, choices=[1, 3], default=1)
    args = p.parse_args();root = ROOT/".local/cluster";root.mkdir(parents=True, exist_ok=True)
    material = root/"material.json"
    if material.exists():
        data = json.loads(material.read_text())
    else:
        data = {key: secrets.token_urlsafe(24) for key in ["postgres", "rabbit", "cassandra", "guard", "quarantine", "reader", "audit", "grafana"]}
        data["users"] = {name: secrets.token_urlsafe(18) for name in ["admin", "alice", "analyst", "scheduler"]}
        for prefix in ["jwt", "policy"]:
            private, public = keypair();(root/(prefix+"-private.pem")).write_bytes(private);(root/(prefix+"-public.pem")).write_bytes(public)
        material.write_text(json.dumps(data, indent=2), encoding="utf-8")
        (root/"credentials.json").write_text(json.dumps(data["users"], indent=2), encoding="utf-8")
    jwt_public, policy_public = root/"jwt-public.pem", root/"policy-public.pem"
    users = {name: {"role": role, "hash": password_hash(data["users"][name])} for name, role in
             [("admin", "admin"), ("alice", "owner"), ("analyst", "analyst"), ("scheduler", "scheduler")]}
    (root/"users.json").write_text(json.dumps(users), encoding="utf-8")
    apply_secret("infrastructure", "pattern", literals={"postgres-password": data["postgres"], "rabbit-password": data["rabbit"]})
    apply_secret("grafana-auth", "monitoring", literals={"password": data["grafana"]})
    service_roles = {"auth-service": ("reader", "reader"), "data-api": ("reader", "reader"),
                     "delete-guard": ("guard", "guard"), "quarantine-service": ("quarantine", "quarantine"), "audit-service": ("audit", "reader")}
    for name, (pg_role, cass_role) in service_roles.items():
        config = {"database_url": f"postgresql+psycopg://{pg_role}:{data[pg_role]}@postgres.pattern.svc.cluster.local:5432/ubi060",
            "storage_backend": "cassandra", "cassandra_hosts": ["cassandra.data.svc.cluster.local"],
            "cassandra_user": cass_role, "cassandra_password": data[cass_role], "workers": True,
            "sweep_seconds": 5, "amqp_url": f"amqp://ubi060:{data['rabbit']}@rabbitmq.pattern.svc.cluster.local:5672/ubi060"}
        config_path = root/(name+".json");config_path.write_text(json.dumps(config), encoding="utf-8")
        files = {"config.json": config_path, "jwt-public.pem": jwt_public, "policy-public.pem": policy_public}
        if name == "auth-service":files |= {"jwt-private.pem": root/"jwt-private.pem", "users.json": root/"users.json"}
        apply_secret(name+"-config", "data" if name == "data-api" else "pattern", files=files)
    init = {"postgres_password": data["postgres"], "cassandra_password": data["cassandra"],
            "roles": {name: data[name] for name in ["reader", "guard", "quarantine", "audit"]}, "replication": args.replication}
    (root/"bootstrap.json").write_text(json.dumps(init), encoding="utf-8")
    apply_secret("bootstrap-config", "pattern", files={"config.json": root/"bootstrap.json", "policy-private.pem": root/"policy-private.pem", "policy-public.pem": policy_public})
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ubi060-development")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=5))
        .not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.DNSName("nginx-gateway.pattern.svc.cluster.local"),
            x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address(args.ip))]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(tls_key, hashes.SHA256()))
    (ROOT/".local/tls.key").write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (ROOT/".local/tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    apply_secret("gateway-tls", "pattern", files={"tls.crt": ROOT/".local/tls.crt", "tls.key": ROOT/".local/tls.key"})
    cleanup = {"username": "scheduler", "password": data["users"]["scheduler"]}
    (root/"cleanup.json").write_text(json.dumps(cleanup), encoding="utf-8")
    apply_secret("cleanup-config", "pattern", files={"credentials.json": root/"cleanup.json", "tls.crt": ROOT/".local/tls.crt"})
    print("Private material stays in .local. Do not publish or regenerate it for existing persistent volumes.")


if __name__ == "__main__":main()
