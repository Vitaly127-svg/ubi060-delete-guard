"""Run five real HTTP processes, using SQLite instead of PostgreSQL/Cassandra/RabbitMQ."""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import httpx
from sqlalchemy import select, update
from app.config import Settings
from app.db import Database, datasets, outbox
from app.domain import Controller
from app.storage import LocalStorage
from scripts.init_local import initialize
from scripts.demo import demonstrate


def main():
    parser = argparse.ArgumentParser();parser.add_argument("--smoke", action="store_true");args = parser.parse_args()
    os.chdir(ROOT)
    root = initialize()
    config = json.loads((root/"config.json").read_text())
    core = Controller(Database(config["database_url"]), LocalStorage(config["payload_path"]),
                      (root/"policy-public.pem").read_bytes())
    stop = threading.Event()
    def local_worker():
        while not stop.is_set():
            try:
                with core.db.engine.connect() as c:
                    pending = list(c.execute(select(outbox).where(outbox.c.published.is_(False))).mappings())
                    ids = list(c.execute(select(datasets.c.id).where(datasets.c.state.in_(["QUARANTINED", "PURGING"]))).scalars())
                for row in pending:
                    core.consume(row["payload"])
                    with core.db.transaction() as c:
                        c.execute(update(outbox).where(outbox.c.id == row["id"]).values(published=True))
                for id in ids:core.purge_one(id)
            except Exception as exc:
                print("Local worker retry:", type(exc).__name__, flush=True)
            stop.wait(.5)
    processes = []
    logs = []
    Path("artifacts").mkdir(exist_ok=True)
    try:
        for name, port in [("data-api", 8000), ("auth-service", 8001), ("delete-guard", 8002),
                           ("quarantine-service", 8003), ("audit-service", 8004)]:
            env = os.environ | {"SERVICE": name, "SECRET_DIR": str(root)}
            output = open(ROOT/"artifacts"/(name+".log"), "w", encoding="utf-8");logs.append(output)
            processes.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.api:create_app", "--factory",
                "--host", "127.0.0.1", "--port", str(port)], env=env, cwd=ROOT, stdout=output, stderr=output))
        worker = threading.Thread(target=local_worker, daemon=True);worker.start()
        deadline = time.monotonic()+40
        for port in range(8000, 8005):
            while True:
                try:
                    if httpx.get(f"http://127.0.0.1:{port}/readyz", timeout=1).status_code == 200:break
                except httpx.HTTPError:pass
                if time.monotonic() > deadline:raise RuntimeError("HTTP services failed to start; inspect artifacts/*.log")
                time.sleep(.3)
        print("Five HTTP services ready. This local mode does NOT test Kubernetes or Cassandra replicas.", flush=True)
        if args.smoke:
            report = demonstrate("", json.loads((root/"credentials.json").read_text()), direct=True)
            (ROOT/"artifacts/local-smoke.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(json.dumps(report, indent=2), flush=True)
        else:
            print("Run: python scripts/demo.py --direct  ; Ctrl+C to stop.", flush=True)
            while all(p.poll() is None for p in processes):time.sleep(1)
    finally:
        stop.set()
        for p in processes:
            p.terminate()
        for p in processes:
            try:p.wait(timeout=8)
            except subprocess.TimeoutExpired:p.kill();p.wait()
        for output in logs:output.close()


if __name__ == "__main__":
    main()
