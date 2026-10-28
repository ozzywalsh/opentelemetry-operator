#!/bin/bash
# Creates the certificates the test needs:
#   - a CA, a Target Allocator server certificate and a collector client
#     certificate for Target Allocator mTLS without cert-manager
#   - a server certificate for the collector's TLS-enabled OTLP gRPC receiver
set -euo pipefail

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"

openssl genrsa -out ca.key 2048
openssl req -x509 -new -noenc -key ca.key -subj "/CN=tls-curves-ca" -days 1 -out ca.crt

openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=tls-curves-targetallocator" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 1 \
  -extfile <(printf "subjectAltName=DNS:tls-curves-targetallocator")

openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=tls-curves-collector" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 1

openssl req -x509 -newkey rsa:2048 -keyout otlp.key -out otlp.crt -days 1 -noenc \
  -subj "/CN=tls-curves-collector.${NAMESPACE}.svc" \
  -addext "subjectAltName=DNS:tls-curves-collector.${NAMESPACE}.svc"

kubectl create cm mtls-ca -n "$NAMESPACE" --from-file=ca.crt=ca.crt
kubectl create secret generic ta-server-cert -n "$NAMESPACE" --from-file=tls.crt=server.crt
kubectl create secret generic ta-server-key -n "$NAMESPACE" --from-file=tls.key=server.key
kubectl create secret tls ta-client-cert -n "$NAMESPACE" --cert=client.crt --key=client.key
kubectl create secret tls collector-tls-certs -n "$NAMESPACE" --cert=otlp.crt --key=otlp.key
