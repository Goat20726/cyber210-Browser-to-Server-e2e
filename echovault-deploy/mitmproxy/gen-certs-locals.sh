#!/usr/bin/env bash
# ── Generate a local test CA + one leaf cert for both EchoVault hostnames ─────
# Produces, in ./certs:
#   ca.key / ca.crt          → the test CA. INSTALL ca.crt in the browser trust
#                              store (this is the file you distribute).
#   echovault.key/.crt       → the leaf cert (SAN: both hostnames + the box IP)
#   echovault.pem            → key + leaf + CA, concatenated, for mitmproxy --certs
#
# Re-running regenerates everything. Keep ca.key PRIVATE (never distribute it).
set -euo pipefail

# The test-env IP so direct https://10.188.199.221 also validates (optional).
BOX_IP="${BOX_IP:-127.0.0.1}"
CLIENT_HOST="echo.client.test"
SERVER_HOST="echo.server.test"

cd "$(dirname "$0")"
mkdir -p certs
cd certs

echo "[*] Generating test CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 1825 \
  -subj "/O=CYBER210/CN=EchoVault Test CA" -extensions v3 -config <(cat <<EOF
[req]
distinguished_name = dn
[dn]
[v3]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
) -out ca.crt

echo "[*] Generating leaf key + CSR..."
openssl genrsa -out echovault.key 2048
openssl req -new -key echovault.key \
  -subj "/O=CYBER210/CN=${SERVER_HOST}" -out echovault.csr

# Modern browsers reject leaf certs valid for more than 398 days (Apple/Chrome).
# Keep it at 397 days so https://echo.*.test shows NO warning once the CA is
# trusted. Key-identifier + EKU(serverAuth) + SAN are all required by Chrome.
cat > echovault.ext <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = DNS:${CLIENT_HOST}, DNS:${SERVER_HOST}, IP:${BOX_IP}
EOF

echo "[*] Signing leaf with the CA (SAN: ${CLIENT_HOST}, ${SERVER_HOST}, ${BOX_IP})..."
openssl x509 -req -in echovault.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 397 -sha256 -extfile echovault.ext -out echovault.crt

# mitmproxy --certs expects: unencrypted key + leaf cert (+ chain) in one PEM.
cat echovault.key echovault.crt ca.crt > echovault.pem
chmod 644 echovault.pem echovault.crt ca.crt

rm -f echovault.csr echovault.ext ca.srl
echo "[✓] Done. Distribute ./certs/ca.crt to browsers; mitmproxy uses echovault.pem."
