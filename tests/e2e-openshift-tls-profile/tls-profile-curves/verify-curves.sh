#!/bin/bash
# Verifies that the cluster profile's groups reach both generated ConfigMaps.
#
# The collector ConfigMap carries curve_preferences in the collector's own
# spellings; the Target Allocator ConfigMap carries the https block in
# Go/component-base vocabulary with curves as IANA numeric group IDs.
#
# Expected values come from the tls-curves-expected ConfigMap, so the same
# script checks both the first profile and the one it is flipped to.
set -euo pipefail

fail() { echo "FAIL: $1"; exit 1; }

SKIPPED=$(oc get configmap tls-curves-expected -n "$NAMESPACE" -o jsonpath='{.data.skipped}')
if [ "$SKIPPED" = "true" ]; then
  echo "SKIP: the cluster does not accept tlsSecurityProfile groups"
  exit 0
fi

EXPECTED_COLLECTOR_MIN=$(oc get configmap tls-curves-expected -n "$NAMESPACE" -o jsonpath='{.data.collector_min_version}')
EXPECTED_COLLECTOR_CURVES=$(oc get configmap tls-curves-expected -n "$NAMESPACE" -o jsonpath='{.data.collector_curves}')
EXPECTED_TA_MIN=$(oc get configmap tls-curves-expected -n "$NAMESPACE" -o jsonpath='{.data.ta_min_version}')
EXPECTED_TA_CURVES=$(oc get configmap tls-curves-expected -n "$NAMESPACE" -o jsonpath='{.data.ta_curves}')
echo "Verifying collector curves=$EXPECTED_COLLECTOR_CURVES, target allocator curves=$EXPECTED_TA_CURVES"

# --- Collector ConfigMap ---

# The operator keeps the previous ConfigMap for one extra reconcile cycle so a
# rollback is possible, so listing by label can return a stale one. The volume
# reference on the StatefulSet always names the current one.
CM_NAME=$(kubectl get statefulset tls-curves-collector -n "$NAMESPACE" \
  -o jsonpath='{.spec.template.spec.volumes[?(@.name=="otc-internal")].configMap.name}' 2>/dev/null || true)
[ -n "$CM_NAME" ] || fail "collector ConfigMap not found in the StatefulSet volume spec"

CONFIG=$(kubectl get configmap "$CM_NAME" -n "$NAMESPACE" -o jsonpath='{.data.collector\.yaml}' | yq -o json)

GRPC_MIN=$(echo "$CONFIG" | jq -r '.receivers.otlp.protocols.grpc.tls.min_version // empty')
[ "$GRPC_MIN" = "$EXPECTED_COLLECTOR_MIN" ] \
  || fail "otlp.grpc.tls.min_version: expected '$EXPECTED_COLLECTOR_MIN', got '$GRPC_MIN'"

GRPC_CIPHERS=$(echo "$CONFIG" | jq '.receivers.otlp.protocols.grpc.tls.cipher_suites')
[ "$GRPC_CIPHERS" != "null" ] && [ "$GRPC_CIPHERS" != "[]" ] \
  || fail "otlp.grpc.tls.cipher_suites: expected non-empty, got '$GRPC_CIPHERS'"

GRPC_CURVES=$(echo "$CONFIG" | jq -c '.receivers.otlp.protocols.grpc.tls.curve_preferences')
[ "$GRPC_CURVES" = "$EXPECTED_COLLECTOR_CURVES" ] \
  || fail "otlp.grpc.tls.curve_preferences: expected '$EXPECTED_COLLECTOR_CURVES', got '$GRPC_CURVES'"

# --- Target Allocator ConfigMap ---

TA_CONFIG=$(kubectl get configmap tls-curves-targetallocator -n "$NAMESPACE" \
  -o jsonpath='{.data.targetallocator\.yaml}' | yq -o json)

TA_HTTPS_ENABLED=$(echo "$TA_CONFIG" | jq -r '.https.enabled // empty')
[ "$TA_HTTPS_ENABLED" = "true" ] || fail "https.enabled: expected 'true' with mTLS on, got '$TA_HTTPS_ENABLED'"

TA_MIN=$(echo "$TA_CONFIG" | jq -r '.https.min_version // empty')
[ "$TA_MIN" = "$EXPECTED_TA_MIN" ] || fail "https.min_version: expected '$EXPECTED_TA_MIN', got '$TA_MIN'"

TA_CIPHERS=$(echo "$TA_CONFIG" | jq '.https.cipher_suites')
[ "$TA_CIPHERS" != "null" ] && [ "$TA_CIPHERS" != "[]" ] \
  || fail "https.cipher_suites: expected non-empty, got '$TA_CIPHERS'"

TA_CURVES=$(echo "$TA_CONFIG" | jq -c '.https.curve_preferences')
[ "$TA_CURVES" = "$EXPECTED_TA_CURVES" ] \
  || fail "https.curve_preferences: expected '$EXPECTED_TA_CURVES', got '$TA_CURVES'"

echo "PASS: cluster profile groups reached the collector and the target allocator ConfigMaps"
