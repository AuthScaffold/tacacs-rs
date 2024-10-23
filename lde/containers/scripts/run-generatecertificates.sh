#/bin/sh

apk add openssl
apk add bash

# Generate CA private key and self-signed certificate
cd /usr/local/etc/certificates
bash /usr/local/scripts/generate-certificates.sh