#!/bin/bash

# Generate CA private key and self-signed certificate
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -subj "/CN=MyCA"

# Generate server private key and certificate signing request (CSR)
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=MyServer"

# Sign the server CSR with the CA certificate and key
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# Generate client private key and certificate signing request (CSR)
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=MyClient"

# Sign the client CSR with the CA certificate and key
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

# Clean up intermediate files
rm ca.srl server.csr client.csr

echo "Certificates generated successfully!"