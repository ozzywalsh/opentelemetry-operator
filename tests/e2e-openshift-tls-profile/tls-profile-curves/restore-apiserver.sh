#!/bin/bash
# Puts the APIServer TLS security profile back the way the test found it.
# A saved empty value means there was no profile, so the field is removed.
set -euo pipefail

# The catch handler can run before the namespace exists, so fall back to
# removing the field when the backup cannot be read.
SAVED=""
if [ -n "${NAMESPACE:-}" ]; then
  SAVED=$(oc get configmap tls-curves-backup -n "$NAMESPACE" -o jsonpath='{.data.profile}' 2>/dev/null || true)
fi

if [ -z "$SAVED" ]; then
  oc patch apiserver cluster --type json \
    -p '[{"op":"remove","path":"/spec/tlsSecurityProfile"}]' 2>/dev/null || true
  echo "APIServer TLS profile removed (none was set before the test)"
else
  oc patch apiserver cluster --type merge \
    -p "{\"spec\":{\"tlsSecurityProfile\":${SAVED}}}"
  echo "APIServer TLS profile restored to: $SAVED"
fi
