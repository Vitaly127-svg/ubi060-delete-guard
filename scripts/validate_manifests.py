from pathlib import Path
import yaml
from kubernetes_validate import validate

root = Path(__file__).resolve().parents[1]
docs = [doc for path in (root/"deploy/k8s").glob("*.yaml") for doc in yaml.safe_load_all(path.read_text()) if doc]
seen = set()
for doc in docs:
    validate(doc, desired_version="1.33.0", strict=True)
    assert {"apiVersion", "kind", "metadata"} <= doc.keys()
    key = (doc["kind"], doc["metadata"].get("namespace"), doc["metadata"]["name"])
    assert key not in seen, key
    seen.add(key)
    assert doc["kind"] != "Secret", "Secrets must be generated locally, not committed"
    if doc["kind"] in {"Deployment", "StatefulSet"}:
        spec = doc["spec"]
        assert spec["selector"]["matchLabels"].items() <= spec["template"]["metadata"]["labels"].items()
        for c in spec["template"]["spec"]["containers"]:
            assert ":" in c["image"] and not c["image"].endswith(":latest")
            assert "resources" in c and "readinessProbe" in c
    if doc["kind"] == "NetworkPolicy":
        for direction in ["ingress", "egress"]:
            for rule in doc["spec"].get(direction, []):
                for peer in rule.get("from" if direction == "ingress" else "to", []):
                    if "namespaceSelector" in peer and "podSelector" in peer:
                        assert peer["namespaceSelector"]["matchLabels"]
assert ("NetworkPolicy", "pattern", "default-deny") in seen
assert ("NetworkPolicy", "data", "default-deny") in seen
assert ("NetworkPolicy", "monitoring", "default-deny") in seen
print(f"PASS: {len(docs)} resources checked against strict Kubernetes 1.33 JSON schemas. Cluster execution is checked separately.")
