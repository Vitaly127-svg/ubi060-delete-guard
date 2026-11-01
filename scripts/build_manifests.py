"""Generate the committed, explicit Kubernetes YAML; no secrets are embedded."""
from pathlib import Path
import json
import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT/"deploy/k8s"
SERVICES = {"auth-service": ("pattern", 8001, 1), "delete-guard": ("pattern", 8002, 2),
            "quarantine-service": ("pattern", 8003, 1), "audit-service": ("pattern", 8004, 1),
            "data-api": ("data", 8000, 1)}


def resource(kind, name, namespace=None, spec=None, **fields):
    api = {"Deployment": "apps/v1", "StatefulSet": "apps/v1", "Job": "batch/v1", "CronJob": "batch/v1",
           "NetworkPolicy": "networking.k8s.io/v1"}.get(kind, "v1")
    metadata = {"name": name}
    if namespace:metadata["namespace"] = namespace
    result = {"apiVersion": api, "kind": kind, "metadata": metadata}
    if spec is not None:result["spec"] = spec
    return result | fields


def service(name, ns, port, headless=False, node=None, app=None):
    spec = {"selector": {"app": app or name}, "ports": [{"name": "tcp", "port": port, "targetPort": port}]}
    if headless:spec["clusterIP"] = "None"
    if name == "cassandra":spec["publishNotReadyAddresses"] = True
    if node:spec.update(type="NodePort");spec["ports"][0]["nodePort"] = node
    return resource("Service", name, ns, spec)


def deployment(name, ns, image, port, replicas=1, command=None, env=None, volumes=None, mounts=None, stateful=False, memory="256Mi"):
    container = {"name": name, "image": image, "imagePullPolicy": "IfNotPresent", "ports": [{"containerPort": port}],
        "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"cpu": "1", "memory": memory}},
        "readinessProbe": {"tcpSocket": {"port": port}, "initialDelaySeconds": 5, "periodSeconds": 5},
        "startupProbe": {"tcpSocket": {"port": port}, "failureThreshold": 120, "periodSeconds": 5}}
    if command:container["command"] = command
    if env:container["env"] = env
    if mounts:container["volumeMounts"] = mounts
    pod = {"automountServiceAccountToken": False, "containers": [container]}
    if volumes:pod["volumes"] = volumes
    spec = {"replicas": replicas, "selector": {"matchLabels": {"app": name}},
            "template": {"metadata": {"labels": {"app": name}}, "spec": pod}}
    if stateful:
        spec["serviceName"] = name
        spec["volumeClaimTemplates"] = [{"metadata": {"name": "storage"}, "spec": {
            "accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "2Gi"}}}}]
    return resource("StatefulSet" if stateful else "Deployment", name, ns, spec)


def write(name, docs):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/name).write_text(yaml.safe_dump_all(docs, allow_unicode=True, sort_keys=False), encoding="utf-8")


def env(name, value):return {"name": name, "value": str(value)}
def secret_env(name, secret, key):return {"name": name, "valueFrom": {"secretKeyRef": {"name": secret, "key": key}}}
def mount(name, path):return {"name": name, "mountPath": path, "readOnly": True}


def build():
    write("00-namespaces.yaml", [resource("Namespace", ns, metadata={"name": ns, "labels": {"project": "ubi060"}})
        for ns in ["pattern", "data", "monitoring"]])
    pg = deployment("postgres", "pattern", "postgres:16-alpine", 5432, stateful=True, memory="512Mi",
        env=[env("POSTGRES_DB", "ubi060"), secret_env("POSTGRES_PASSWORD", "infrastructure", "postgres-password"),
             env("PGDATA", "/var/lib/postgresql/data/pgdata")], mounts=[{"name": "storage", "mountPath": "/var/lib/postgresql/data"}])
    write("10-postgres.yaml", [service("postgres", "pattern", 5432), pg])
    rabbit = deployment("rabbitmq", "pattern", "rabbitmq:4.1-management-alpine", 5672, stateful=True, memory="512Mi",
        env=[env("RABBITMQ_DEFAULT_USER", "ubi060"), env("RABBITMQ_DEFAULT_VHOST", "ubi060"),
             secret_env("RABBITMQ_DEFAULT_PASS", "infrastructure", "rabbit-password")],
        mounts=[{"name": "storage", "mountPath": "/var/lib/rabbitmq"}])
    write("11-rabbitmq.yaml", [service("rabbitmq", "pattern", 5672), rabbit])
    cass = deployment("cassandra", "data", "cassandra:4.1", 9042, stateful=True, memory="1200Mi",
        env=[env("CASSANDRA_CLUSTER_NAME", "ubi060"), env("CASSANDRA_DC", "dc1"),
             env("CASSANDRA_ENDPOINT_SNITCH", "GossipingPropertyFileSnitch"),
             env("CASSANDRA_SEEDS", "cassandra-0.cassandra.data.svc.cluster.local"),
             env("MAX_HEAP_SIZE", "512M"), env("HEAP_NEWSIZE", "100M")],
        command=["bash", "-ec", "sed -ri 's/^authenticator:.*/authenticator: PasswordAuthenticator/; s/^authorizer:.*/authorizer: CassandraAuthorizer/' /etc/cassandra/cassandra.yaml; exec docker-entrypoint.sh cassandra -f"],
        mounts=[{"name": "storage", "mountPath": "/var/lib/cassandra"}])
    cass["spec"]["template"]["spec"]["containers"][0]["resources"]["requests"]["memory"] = "768Mi"
    write("12-cassandra.yaml", [service("cassandra", "data", 9042, headless=True), cass])
    secret_volume = [{"name": "config", "secret": {"secretName": "bootstrap-config"}}]
    job = resource("Job", "bootstrap", "pattern", {"backoffLimit": 4, "template": {"metadata": {"labels": {"app": "bootstrap"}},
        "spec": {"restartPolicy": "OnFailure", "automountServiceAccountToken": False,
        "containers": [{"name": "bootstrap", "image": "ubi060:dev", "imagePullPolicy": "IfNotPresent",
                        "command": ["python", "scripts/bootstrap_cluster.py"], "env": [env("SECRET_DIR", "/run/config")],
                        "volumeMounts": [mount("config", "/run/config")]}], "volumes": secret_volume}}})
    write("20-bootstrap.yaml", [job])
    apps = []
    for name, (ns, port, replicas) in SERVICES.items():
        dep = deployment(name, ns, "ubi060:dev", port, replicas,
            env=[env("SERVICE", name), env("PORT", port), env("SECRET_DIR", "/run/config")],
            volumes=[{"name": "config", "secret": {"secretName": name+"-config"}}, {"name": "tmp", "emptyDir": {}}],
            mounts=[mount("config", "/run/config"), {"name": "tmp", "mountPath": "/tmp"}])
        pod = dep["spec"]["template"]["spec"]
        pod["securityContext"] = {"runAsNonRoot": True, "runAsUser": 10001}
        container = pod["containers"][0]
        container["securityContext"] = {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}}
        container["readinessProbe"] = {"httpGet": {"path": "/readyz", "port": port}, "periodSeconds": 5}
        container["livenessProbe"] = {"httpGet": {"path": "/healthz", "port": port}, "periodSeconds": 10}
        apps += [service(name, ns, port), dep]
    apps.append(service("guard-metrics", "pattern", 8002, headless=True, app="delete-guard"))
    write("30-microservices.yaml", apps)
    gateway = deployment("nginx-gateway", "pattern", "nginx:1.28-alpine", 8443, 2,
        command=["nginx", "-c", "/etc/ubi060/nginx.conf", "-g", "daemon off;"],
        volumes=[{"name": "nginx", "configMap": {"name": "nginx"}}, {"name": "tls", "secret": {"secretName": "gateway-tls"}},
                 {"name": "tmp", "emptyDir": {}}],
        mounts=[mount("nginx", "/etc/ubi060"), mount("tls", "/etc/tls"), {"name": "tmp", "mountPath": "/tmp"}])
    write("31-gateway.yaml", [resource("ConfigMap", "nginx", "pattern", data={"nginx.conf": (ROOT/"deploy/nginx.conf").read_text()}),
         service("nginx-gateway", "pattern", 8443, node=30443), gateway])
    policies = []
    for ns in ["pattern", "data", "monitoring"]:
        policies.append(resource("NetworkPolicy", "default-deny", ns,
            {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}))
        policies.append(resource("NetworkPolicy", "allow-dns", ns, {"podSelector": {}, "policyTypes": ["Egress"],
            "egress": [{"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                               "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
                        "ports": [{"protocol": protocol, "port": 53} for protocol in ["UDP", "TCP"]]}]}))
    locations = {n: ns for n, (ns, _, _) in SERVICES.items()} | {"nginx-gateway": "pattern", "postgres": "pattern", "rabbitmq": "pattern",
        "cassandra": "data", "bootstrap": "pattern", "cleanup": "pattern", "prometheus": "monitoring", "grafana": "monitoring"}
    links = [("nginx-gateway", n, port) for n, (_, port, _) in SERVICES.items()]
    links += [(n, "postgres", 5432) for n in ["delete-guard", "quarantine-service", "audit-service", "data-api", "bootstrap"]]
    links += [(n, "cassandra", 9042) for n in ["delete-guard", "quarantine-service", "data-api", "bootstrap"]]
    links += [(n, "rabbitmq", 5672) for n in ["delete-guard", "audit-service"]]
    links += [("data-api", "delete-guard", 8002), ("cleanup", "nginx-gateway", 8443), ("grafana", "prometheus", 9090)]
    links += [("prometheus", n, port) for n, (_, port, _) in SERVICES.items()]
    links += [("cassandra", "cassandra", p) for p in [7000, 7001, 7199]]
    for index, (source, target, port) in enumerate(links):
        peer = lambda n: {"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": locations[n]}},
                          "podSelector": {"matchLabels": {"app": n}}}
        policies.append(resource("NetworkPolicy", f"ingress-{index}-{source}", locations[target],
            {"podSelector": {"matchLabels": {"app": target}}, "policyTypes": ["Ingress"],
             "ingress": [{"from": [peer(source)], "ports": [{"protocol": "TCP", "port": port}]}]}))
        policies.append(resource("NetworkPolicy", f"egress-{index}-{target}", locations[source],
            {"podSelector": {"matchLabels": {"app": source}}, "policyTypes": ["Egress"],
             "egress": [{"to": [peer(target)], "ports": [{"protocol": "TCP", "port": port}]}]}))
    policies.append(resource("NetworkPolicy", "public-gateway", "pattern", {"podSelector": {"matchLabels": {"app": "nginx-gateway"}},
        "policyTypes": ["Ingress"], "ingress": [{"ports": [{"protocol": "TCP", "port": 8443}]}]}))
    write("40-network-policies.yaml", policies)
    scrape = [{"job_name": name, "static_configs": [{"targets": [f"{name}.{ns}.svc.cluster.local:{port}"]}]}
              for name, (ns, port, _) in SERVICES.items() if name != "delete-guard"]
    scrape.append({"job_name": "delete-guard", "dns_sd_configs": [{"names": ["guard-metrics.pattern.svc.cluster.local"], "type": "A", "port": 8002}]})
    prom_conf = {"global": {"scrape_interval": "5s"}, "rule_files": ["/etc/prometheus/alerts.yml"], "scrape_configs": scrape}
    alerts = {"groups": [{"name": "ubi060", "rules": [{"alert": "DeletionBlocks", "expr": "sum(rate(deletion_blocked_total[1m])) > 0.1",
               "for": "30s", "labels": {"severity": "warning"}, "annotations": {"summary": "Рост числа отказов удаления"}}]}]}
    prom = deployment("prometheus", "monitoring", "prom/prometheus:v3.3.0", 9090,
        volumes=[{"name": "config", "configMap": {"name": "prometheus"}}, {"name": "storage", "emptyDir": {}}],
        mounts=[mount("config", "/etc/prometheus"), {"name": "storage", "mountPath": "/prometheus"}])
    dashboard = {"uid": "ubi060", "title": "UBI.060 controlled deletion", "schemaVersion": 39, "version": 1,
        "panels": [{"id": i+1, "type": "timeseries", "title": title, "gridPos": {"x": (i%2)*12, "y": (i//2)*8, "w": 12, "h": 8},
                    "datasource": {"type": "prometheus", "uid": "prometheus"}, "targets": [{"refId": "A", "expr": expr}]}
                   for i, (title, expr) in enumerate([("Решения", "sum by(decision)(rate(deletion_requests_total[1m]))"),
                   ("Блокировки", "sum by(rule)(rate(deletion_blocked_total[1m]))"), ("Карантин", "sum(quarantine_datasets)"),
                   ("Время проверки p95", "histogram_quantile(0.95, sum by(le)(rate(guard_check_seconds_bucket[1m])))")])]}
    graf = deployment("grafana", "monitoring", "grafana/grafana:11.6.0", 3000,
        env=[env("GF_SECURITY_ADMIN_USER", "admin"), secret_env("GF_SECURITY_ADMIN_PASSWORD", "grafana-auth", "password")],
        volumes=[{"name": "provision", "configMap": {"name": "grafana-provision"}}, {"name": "dashboards", "configMap": {"name": "grafana-dashboard"}},
                 {"name": "storage", "emptyDir": {}}],
        mounts=[{"name": "provision", "mountPath": "/etc/grafana/provisioning/datasources/datasource.yaml", "subPath": "datasource.yaml"},
                {"name": "provision", "mountPath": "/etc/grafana/provisioning/dashboards/provider.yaml", "subPath": "provider.yaml"},
                mount("dashboards", "/etc/grafana/dashboards"), {"name": "storage", "mountPath": "/var/lib/grafana"}])
    graf["spec"]["template"]["spec"]["securityContext"] = {"fsGroup": 472}
    prom["spec"]["template"]["spec"]["securityContext"] = {"fsGroup": 65534}
    write("50-monitoring.yaml", [resource("ConfigMap", "prometheus", "monitoring", data={"prometheus.yml": yaml.safe_dump(prom_conf, sort_keys=False), "alerts.yml": yaml.safe_dump(alerts, allow_unicode=True)}),
        service("prometheus", "monitoring", 9090), prom,
        resource("ConfigMap", "grafana-provision", "monitoring", data={"datasource.yaml": yaml.safe_dump({"apiVersion": 1, "datasources": [
            {"name": "Prometheus", "type": "prometheus", "uid": "prometheus", "access": "proxy", "url": "http://prometheus:9090", "isDefault": True}]}),
            "provider.yaml": yaml.safe_dump({"apiVersion": 1, "providers": [{"name": "ubi060", "type": "file", "options": {"path": "/etc/grafana/dashboards"}}]})}),
        resource("ConfigMap", "grafana-dashboard", "monitoring", data={"ubi060.json": json.dumps(dashboard, ensure_ascii=False)}),
        service("grafana", "monitoring", 3000), graf])
    cleanup = resource("CronJob", "cleanup", "pattern", {"schedule": "*/5 * * * *", "concurrencyPolicy": "Forbid", "jobTemplate": {"spec": {
        "backoffLimit": 2, "template": {"metadata": {"labels": {"app": "cleanup"}}, "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
            "containers": [{"name": "cleanup", "image": "ubi060:dev", "command": ["python", "scripts/cleanup.py"],
                "volumeMounts": [mount("config", "/run/config")]}], "volumes": [{"name": "config", "secret": {"secretName": "cleanup-config"}}]}}}}})
    write("60-cleanup.yaml", [cleanup])
    print("Generated", len(list(OUT.glob('*.yaml'))), "Kubernetes manifest files")


if __name__ == "__main__":build()
