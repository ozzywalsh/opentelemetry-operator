#!/bin/bash
# Waits for the operator to come back after the APIServer profile change.
# The profile change triggers a graceful restart, and the webhook endpoint can
# lag pod readiness by a few seconds, so applying a collector too early fails.
set -euo pipefail

NS=opentelemetry-operator-system

kubectl rollout status deployment/opentelemetry-operator-controller-manager \
  -n "$NS" --timeout=180s

for i in $(seq 1 30); do
  addrs=$(kubectl get endpoints opentelemetry-operator-controller-manager-service \
    -n "$NS" -o jsonpath='{.subsets[0].addresses}' 2>/dev/null || true)
  if [ -n "$addrs" ] && [ "$addrs" != "null" ] && [ "$addrs" != "[]" ]; then
    echo "Webhook endpoint is ready"
    exit 0
  fi
  echo "Waiting for the webhook service endpoint... ($i/30)"
  sleep 2
done

echo "ERROR: the webhook service endpoint did not become ready"
exit 1
