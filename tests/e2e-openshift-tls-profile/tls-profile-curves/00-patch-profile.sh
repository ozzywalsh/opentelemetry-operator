#!/bin/bash
# Saves the current APIServer TLS security profile and switches to a Custom
# profile that names an explicit groups list.
#
# The groups field is gated by the OpenShift TLSGroupPreferences feature gate.
# On a cluster where the gate is off the API server prunes the field, so a
# server-side dry run decides whether the test runs or is skipped. The skip
# flag is stored in the tls-curves-expected ConfigMap and read by every later
# script.
#
# Only groups with a collector curve_preferences spelling are used:
# SecP256r1MLKEM768 and SecP384r1MLKEM1024 have none, so naming them would
# make the collector fail to start with "invalid curve type".
set -euo pipefail

CIPHERS='"ECDHE-ECDSA-AES128-GCM-SHA256","ECDHE-RSA-AES128-GCM-SHA256","ECDHE-ECDSA-AES256-GCM-SHA384","ECDHE-RSA-AES256-GCM-SHA384"'
PATCH_A="{\"spec\":{\"tlsSecurityProfile\":{\"type\":\"Custom\",\"custom\":{\"ciphers\":[${CIPHERS}],\"minTLSVersion\":\"VersionTLS12\",\"groups\":[\"X25519MLKEM768\",\"X25519\",\"secp256r1\",\"secp384r1\"]}}}}"

# Save the current profile so teardown can put it back. An empty value means
# the APIServer had no tlsSecurityProfile and teardown removes the field.
CURRENT_PROFILE=$(oc get apiserver cluster -o jsonpath='{.spec.tlsSecurityProfile}')
echo "Current APIServer TLS profile: ${CURRENT_PROFILE:-<not set>}"
oc create configmap tls-curves-backup -n "$NAMESPACE" \
  --from-literal=profile="${CURRENT_PROFILE}" \
  --dry-run=client -o yaml | oc apply -f -

# Does this cluster accept the groups field? A server-side dry run returns the
# object as it would be stored, with unknown or gated fields already pruned.
DRY_RUN_GROUPS=$(oc patch apiserver cluster --type merge --dry-run=server \
  -p "$PATCH_A" -o jsonpath='{.spec.tlsSecurityProfile.custom.groups}' 2>/dev/null || true)
if [ -z "$DRY_RUN_GROUPS" ] || [ "$DRY_RUN_GROUPS" = "null" ]; then
  echo "SKIP: the APIServer does not accept spec.tlsSecurityProfile.custom.groups."
  echo "SKIP: enable the TLSGroupPreferences feature gate to run this test."
  oc create configmap tls-curves-expected -n "$NAMESPACE" \
    --from-literal=skipped="true" \
    --dry-run=client -o yaml | oc apply -f -
  exit 0
fi

oc patch apiserver cluster --type merge -p "$PATCH_A"
echo "APIServer patched to Custom profile A (TLS 1.2, 4 groups)"

# Expected values for profile A.
#   collector: OpenShift group names translated to the collector's spellings
#   target allocator: Go/component-base names, curves as IANA numeric group IDs
#     X25519MLKEM768=4588, X25519=29, secp256r1=23, secp384r1=24
oc create configmap tls-curves-expected -n "$NAMESPACE" \
  --from-literal=skipped="false" \
  --from-literal=collector_min_version="1.2" \
  --from-literal=collector_curves='["X25519MLKEM768","X25519","P256","P384"]' \
  --from-literal=ta_min_version="VersionTLS12" \
  --from-literal=ta_curves='[4588,29,23,24]' \
  --dry-run=client -o yaml | oc apply -f -
