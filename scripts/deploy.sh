#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
command -v minikube >/dev/null
command -v kubectl >/dev/null
python3 -c 'import yaml, cryptography'
minikube status >/dev/null
minikube image build -t ubi060:dev .
python3 scripts/build_manifests.py
kubectl apply -f deploy/k8s/00-namespaces.yaml
python3 scripts/cluster_secrets.py --ip "$(minikube ip)"
kubectl apply -f deploy/k8s/40-network-policies.yaml
kubectl apply -f deploy/k8s/10-postgres.yaml -f deploy/k8s/11-rabbitmq.yaml -f deploy/k8s/12-cassandra.yaml
kubectl -n pattern rollout status statefulset/postgres --timeout=300s
kubectl -n pattern rollout status statefulset/rabbitmq --timeout=300s
kubectl -n data rollout status statefulset/cassandra --timeout=600s
kubectl apply -f deploy/k8s/20-bootstrap.yaml
kubectl -n pattern wait --for=condition=complete job/bootstrap --timeout=600s
kubectl apply -f deploy/k8s/30-microservices.yaml
for name in auth-service delete-guard quarantine-service audit-service; do
  kubectl -n pattern rollout status "deployment/$name" --timeout=300s
done
kubectl -n data rollout status deployment/data-api --timeout=300s
kubectl apply -f deploy/k8s/31-gateway.yaml -f deploy/k8s/50-monitoring.yaml -f deploy/k8s/60-cleanup.yaml
kubectl -n pattern rollout status deployment/nginx-gateway --timeout=300s
echo 'Deployment finished. Verify with scripts/demo.py; do not infer readiness from apply alone.'
