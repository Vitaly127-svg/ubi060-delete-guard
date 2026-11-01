import json
import time
from pathlib import Path
import httpx

root = Path("/run/config")
credentials = json.loads((root/"credentials.json").read_text())
base = "https://nginx-gateway.pattern.svc.cluster.local:8443"
with httpx.Client(verify=str(root/"tls.crt"), timeout=20) as client:
    auth = client.post(base+"/token", json=credentials);auth.raise_for_status()
    headers = {"Authorization": "Bearer "+auth.json()["access_token"]}
    due = client.get(base+"/catalog/due", headers=headers);due.raise_for_status()
    for id in due.json():
        response = client.delete(base+"/deletions/"+id, headers=headers |
            {"Idempotency-Key": f"cleanup-{id}-{int(time.time())//300}"})
        if response.status_code not in [202, 403, 409]:response.raise_for_status()
        print(json.dumps({"dataset_id": id, "status": response.status_code}), flush=True)
