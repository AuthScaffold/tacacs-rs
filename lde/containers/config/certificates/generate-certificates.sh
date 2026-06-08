#!/bin/bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

server_ext="$(mktemp)"
client_ext="$(mktemp)"

cleanup() {
	rm -f "$server_ext" "$client_ext" server.csr client.csr ca.srl
}

trap cleanup EXIT

cat >"$server_ext" <<'EOF'
[server_cert]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:MyServer,DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

cat >"$client_ext" <<'EOF'
[client_cert]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF

# Generate CA private key and self-signed certificate.
openssl req -x509 -newkey rsa:4096 -nodes \
	-keyout ca.key \
	-out ca.crt \
	-days 365 \
	-subj "/CN=MyCA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-addext "subjectKeyIdentifier=hash"

# Generate server private key and certificate signing request (CSR).
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=MyServer"

# Sign the server CSR with the CA certificate and key as an X.509v3 server cert.
openssl x509 -req \
	-in server.csr \
	-CA ca.crt \
	-CAkey ca.key \
	-CAcreateserial \
	-out server.crt \
	-days 365 \
	-extfile "$server_ext" \
	-extensions server_cert

# Generate client private key and certificate signing request (CSR).
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=MyClient"

# Sign the client CSR with the CA certificate and key as an X.509v3 client cert.
openssl x509 -req \
	-in client.csr \
	-CA ca.crt \
	-CAkey ca.key \
	-CAcreateserial \
	-out client.crt \
	-days 365 \
	-extfile "$client_ext" \
	-extensions client_cert

# Export DER variants for CLI inputs that prefer binary certificate material.
openssl x509 -in client.crt -outform der -out client.crt.der
openssl rsa -in client.key -outform der -out client.key.der

echo "Certificates generated successfully!"