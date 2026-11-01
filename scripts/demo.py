import argparse
import json
import time
import uuid
from pathlib import Path

import httpx


def demonstrate(base, credentials, verify=True, direct=False, wait=True):
    client = httpx.Client(verify=verify, timeout=15)
    results = []
    def url(service, path):
        if direct:
            ports = {"auth": 8001, "guard": 8002, "data": 8000, "q": 8003, "audit": 8004}
            return "http://127.0.0.1:"+str(ports[service])+path
        return base.rstrip("/")+path
    def check(label, method, service, path, expected, token=None, **kwargs):
        headers = kwargs.pop("headers", {})
        if token:headers["Authorization"] = "Bearer "+token
        r = client.request(method, url(service, path), headers=headers, **kwargs)
        results.append({"step": label, "status": r.status_code, "expected": expected, "ok": r.status_code == expected})
        r.raise_for_status() if expected < 400 and r.status_code >= 400 else None
        assert r.status_code == expected, (label, r.status_code, r.text)
        return r
    owner = check("login owner", "POST", "auth", "/token", 200,
        json={"username": "alice", "password": credentials["alice"]}).json()["access_token"]
    admin = check("login admin", "POST", "auth", "/token", 200,
        json={"username": "admin", "password": credentials["admin"]}).json()["access_token"]
    check("read available dataset", "GET", "data", "/datasets/free", 200, owner)
    key = str(uuid.uuid4())
    check("quarantine", "DELETE", "guard", "/deletions/free", 202, owner, headers={"Idempotency-Key": key})
    check("idempotent retry", "DELETE", "guard", "/deletions/free", 202, owner, headers={"Idempotency-Key": key})
    check("quarantined data hidden", "GET", "data", "/datasets/free", 410, owner)
    check("restore", "POST", "q", "/quarantine/free/restore", 200, owner)
    check("restored data readable", "GET", "data", "/datasets/free", 200, owner)
    check("R5 reference protected", "DELETE", "guard", "/deletions/reference", 409, owner,
          headers={"Idempotency-Key": str(uuid.uuid4())})
    check("R2 tampered policy blocked", "DELETE", "guard", "/deletions/tampered", 403, owner,
          headers={"Idempotency-Key": str(uuid.uuid4())})
    if wait:
        check("purge fixture quarantined", "DELETE", "guard", "/deletions/purge-demo", 202, owner,
              headers={"Idempotency-Key": str(uuid.uuid4())})
        until = time.monotonic()+90
        while time.monotonic() < until:
            rows = client.get(url("q", "/quarantine"), headers={"Authorization": "Bearer "+admin}).json()
            if not any(row["id"] == "purge-demo" for row in rows):break
            time.sleep(1)
        else:raise AssertionError("Purge worker did not finish")
        check("purged data unavailable", "GET", "data", "/datasets/purge-demo", 410, owner)
    until = time.monotonic()+15
    while time.monotonic() < until:
        notices = client.get(url("audit", "/notifications"), headers={"Authorization": "Bearer "+owner}).json()
        if len(notices) >= 2:break
        time.sleep(.5)
    assert len(notices) >= 2, "Audit consumer did not create notifications"
    r = check("audit chain", "GET", "audit", "/audit/verify", 200, admin)
    assert r.json()["valid"] is True
    client.close()
    return {"mode": "local-http-sqlite" if direct else "cluster-https", "steps": results,
            "all_passed": all(row["ok"] for row in results), "notification_count": len(notices)}


if __name__ == "__main__":
    p = argparse.ArgumentParser();p.add_argument("--base", default="https://127.0.0.1:30443")
    p.add_argument("--direct", action="store_true");p.add_argument("--ca", default=".local/tls.crt")
    p.add_argument("--no-wait", action="store_true");p.add_argument("--credentials", default=".local/credentials.json")
    args = p.parse_args()
    report = demonstrate(args.base, json.loads(Path(args.credentials).read_text()),
        verify=args.ca if not args.direct else True, direct=args.direct, wait=not args.no_wait)
    Path("artifacts").mkdir(exist_ok=True)
    Path("artifacts/demo.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
