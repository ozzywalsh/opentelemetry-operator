#!/bin/bash
# Functional TLS verification via nmap ssl-enum-ciphers - Intermediate profile.
# Verifies the TA's HTTPS endpoint offers TLSv1.2 and TLSv1.3.
set -euo pipefail

fail() { echo "FAIL: $1"; exit 1; }

# Verify TLS profile via nmap ssl-enum-ciphers on a specific IP:port.
# Args: $1=ip, $2=ports (comma-separated), $3=expected_profile, $4=description
verify_nmap_tls_profile() {
  local ip="$1" ports="$2" expected="$3" description="$4"

  echo "=== nmap ssl-enum-ciphers: $description ($ip ports $ports) ==="
  local result
  result=$(kubectl exec tls-scanner -n "$NAMESPACE" -- nmap -Pn --script ssl-enum-ciphers -p "$ports" "$ip")
  echo "$result"

  for port in ${ports//,/ }; do
    local port_section
    port_section=$(echo "$result" | grep -A 50 "${port}/tcp" || true)
    if [ -z "$port_section" ]; then
      fail "$description: port $port not found in nmap output"
    fi

    if [ "$expected" = "intermediate" ]; then
      echo "$port_section" | grep "TLSv1.2" || fail "$description: port $port missing TLSv1.2"
      echo "$port_section" | grep "TLSv1.3" || fail "$description: port $port missing TLSv1.3"
    fi
  done

  echo "PASS: $description (ports $ports, profile=$expected)"
}

# Get TA service cluster IP.
# The TA service exposes port 443 (targeting container port 8443).
TA_IP=$(kubectl get service ta-tls-test-targetallocator -n "$NAMESPACE" \
  -o jsonpath='{.spec.clusterIP}')

# nmap ssl-enum-ciphers verification on the TA HTTPS service port.
verify_nmap_tls_profile "$TA_IP" "443" intermediate "Target Allocator HTTPS"

echo "PASS: Intermediate profile verified via nmap on TA"
