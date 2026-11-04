#!/bin/bash
# Flips the APIServer to a second Custom profile that differs from the first
# only in its groups list, then waits for the graceful restart to regenerate
# both ConfigMaps with the new curves.
#
# Holding minTLSVersion and ciphers steady means the groups change alone has
# to trigger the restart.
set -euo pipefail

SKIPPED=$(oc get configmap tls-curves-expected -n "$NAMESPACE" -o jsonpath='{.data.skipped}')
if [ "$SKIPPED" = "true" ]; then
  echo "SKIP: the cluster does not accept tlsSecurityProfile groups"
  exit 0
fi

CIPHERS='"ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES256-GCM-SHA384"'
PATCH_B="{\"spec\":{\"tlsSecurityProfile\":{\"type\":\"Custom\",\"custom\":{\"ciphers\":[${CIPHERS}],\"minTLSVersion\":\"VersionTLS12\",\"groups\":[\"X25519\",\"secp521r1\"]}}}}"

# Expected values for profile B. X25519=29, secp521r1=25.
EXPECTED_COLLECTOR_CURVES='["X25519","P521"]'
EXPECTED_TA_CURVES='[29,25]'

oc patch apiserver cluster --type merge -p "$PATCH_B"
echo "APIServer patched to Custom profile B (TLS 1.2, groups X25519 and secp521r1)"

oc create configmap tls-curves-expected -n "$NAMESPACE" \
  --from-literal=skipped="false" \
  --from-literal=collector_min_version="1.2" \
  --from-literal=collector_curves="$EXPECTED_COLLECTOR_CURVES" \
  --from-literal=ta_min_version="VersionTLS12" \
  --from-literal=ta_curves="$EXPECTED_TA_CURVES" \
  --dry-run=client -o yaml | oc apply -f -

# The operator restarts on a profile change, so poll for a ready operator pod
# before looking at the regenerated ConfigMaps.
for i in $(seq 1 60); do
  ready=$(kubectl get pods -n opentelemetry-operator-system \
    -l app.kubernetes.io/name=opentelemetry-operator \
    -o jsonpath='{range .items[*]}{.status.phase} {.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
    | grep -c "Running True" || true)
  if [ "$ready" -ge 1 ]; then
    echo "Operator pod is ready"
    break
  fi
  echo "Waiting for the operator pod to be ready... ($i/60)"
  sleep 5
done

# Wait for the StatefulSet to point at a ConfigMap carrying the new curves.
for i in $(seq 1 60); do
  CM_NAME=$(kubectl get statefulset tls-curves-collector -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.volumes[?(@.name=="otc-internal")].configMap.name}' 2>/dev/null || true)
  if [ -n "$CM_NAME" ]; then
    ACTUAL=$(kubectl get configmap "$CM_NAME" -n "$NAMESPACE" \
      -o jsonpath='{.data.collector\.yaml}' 2>/dev/null \
      | yq -o json 2>/dev/null \
      | jq -c '.receivers.otlp.protocols.grpc.tls.curve_preferences' 2>/dev/null || true)
    if [ "$ACTUAL" = "$EXPECTED_COLLECTOR_CURVES" ]; then
      echo "Collector ConfigMap $CM_NAME carries the new curves"
      break
    fi
    echo "Collector ConfigMap $CM_NAME has curve_preferences=$ACTUAL, expected $EXPECTED_COLLECTOR_CURVES ($i/60)"
  else
    echo "StatefulSet volume reference not found yet ($i/60)"
  fi
  sleep 5
done

# Wait for the Target Allocator ConfigMap to carry the new curves too.
for i in $(seq 1 60); do
  ACTUAL_TA=$(kubectl get configmap tls-curves-targetallocator -n "$NAMESPACE" \
    -o jsonpath='{.data.targetallocator\.yaml}' 2>/dev/null \
    | yq -o json 2>/dev/null | jq -c '.https.curve_preferences' 2>/dev/null || true)
  if [ "$ACTUAL_TA" = "$EXPECTED_TA_CURVES" ]; then
    echo "Target Allocator ConfigMap carries the new curves"
    break
  fi
  echo "Target Allocator ConfigMap has curve_preferences=$ACTUAL_TA, expected $EXPECTED_TA_CURVES ($i/60)"
  sleep 5
done

kubectl rollout status statefulset/tls-curves-collector -n "$NAMESPACE" --timeout=180s
kubectl rollout status deployment/tls-curves-targetallocator -n "$NAMESPACE" --timeout=180s
