#!/bin/bash

set -e


DAYS_VALID=365
CA_SUBJ='/C=AU/ST=Queensland/L=Brisbane/O=AuthScaffold/OU=DevelopmentCA/CN=TacacsrsCA'

SERVER_URI='server.tacacsserver.local'
SERVER_SUBJ="/C=AU/ST=Queensland/L=Brisbane/O=AuthScaffold/OU=DevelopmentServer/CN=$SERVER_URI"

CLIENT_URI='client.tacacsserver.local'
CLIENT_SUBJ="/C=AU/ST=Queensland/L=Brisbane/O=AuthScaffold/OU=DevelopmentClient/CN=$CLIENT_URI"


# Generate CA private key and self-signed certificate
openssl genrsa -out ca.key 4096
openssl req -new -key ca.key -out ca.csr -subj $CA_SUBJ
openssl x509 -req -sha256 -in ca.csr -signkey ca.key -extfile /usr/local/scripts/ca.cnf -out ca.crt -days $DAYS_VALID

# Generate server private key and certificate signing request (CSR)
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -config /usr/local/scripts/server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extensions req_ext -extfile /usr/local/scripts/server.cnf -days $DAYS_VALID



# Generate client private key and certificate signing request (CSR)
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -config /usr/local/scripts/client.cnf
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -extensions req_ext -extfile /usr/local/scripts/client.cnf -days $DAYS_VALID



# Clean up intermediate files
rm ca.csr ca.srl server.csr client.csr

# Remove the ca.key file so we can't sign any more certificates (for security)
rm ca.key

echo "Certificates generated successfully!"