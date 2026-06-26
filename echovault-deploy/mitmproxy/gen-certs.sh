#!/usr/bin/env bash
# ── Generate a local test CA + one leaf cert for both EchoVault hostnames ─────
# Produces, in ./certs:
#   ca.key / ca.crt          → the test CA. INSTALL ca.crt in the browser trust
#                              store (this is the file you distribute).
#   echovault.key/.crt       → the leaf cert (SAN: the hostnames; IPs optional)
#   echovault.pem            → key + leaf + CA, concatenated, for mitmproxy --certs
#
# NAME-ONLY BY DEFAULT (location-independent):
#   TLS validates against the HOSTNAME, not the IP, and mitmproxy picks the cert
#   by SNI. So this leaf carries only DNS names — the same cert is valid wherever
#   echo.client.test / echo.server.test happen to resolve (hosts file or DNS),
#   on localhost or the test box, with NO rebuild when the IP changes.
#   You only need to rebuild if the HOSTNAMES change.
#
#   Add IP SANs ONLY if you want to browse https://<raw-ip> directly (rarely):
#     SAN_IPS="127.0.0.1 172.16.165.17" ./gen-certs.sh
#   Change the names with:
#     SAN_HOSTS="echo.client.test echo.server.test extra.test" ./gen-certs.sh
#
# CA is STABLE across runs: if ca.key/ca.crt already exist they are REUSED, so
# re-running this does NOT invalidate the CA your browser already trusts — only
# the leaf is reissued. Force a brand-new CA with  FORCE_CA=1 ./gen-certs.sh
# (then you must reinstall ca.crt). Keep ca.key PRIVATE (never distribute it).
set -euo pipefail

# Hostnames the cert is valid for (space-separated). The first is used as the CN.
SAN_HOSTS="${SAN_HOSTS:-echo.client.test echo.server.test}"
# Optional IP SANs — empty by default so the cert is location-independent.
SAN_IPS="${SAN_IPS:-}"

# Build the subjectAltName string (DNS:... , IP:...) and pick the CN.
SAN_LIST=""
CN=""
for h in $SAN_HOSTS; do
  [[ -z "$CN" ]] && CN="$h"
  SAN_LIST+="DNS:${h},"
done
for ip in $SAN_IPS; do
  SAN_LIST+="IP:${ip},"
done
SAN_LIST="${SAN_LIST%,}"   # strip trailing comma

cd "$(dirname "$0")"
mkdir -p certs
cd certs

if [[ "${FORCE_CA:-0}" == "1" ]]; then
  rm -f ca.key ca.crt
fi

if [[ -f ca.key && -f ca.crt ]]; then
  echo "[*] Reusing existing CA (ca.key/ca.crt). Set FORCE_CA=1 to mint a new one."
else
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
fi

echo "[*] Generating leaf key + CSR..."
openssl genrsa -out echovault.key 2048
openssl req -new -key echovault.key \
  -subj "/O=CYBER210/CN=${CN}" -out echovault.csr

# Modern browsers reject leaf certs valid for more than 398 days (Apple/Chrome).
# Keep it at 397 days so https://echo.*.test shows NO warning once the CA is
# trusted. Key-identifier + EKU(serverAuth) + SAN are all required by Chrome.
cat > echovault.ext <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
subjectAltName = ${SAN_LIST}
EOF

echo "[*] Signing leaf with the CA (SAN: ${SAN_LIST})..."
openssl x509 -req -in echovault.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 397 -sha256 -extfile echovault.ext -out echovault.crt

# mitmproxy --certs expects: unencrypted key + leaf cert (+ chain) in one PEM.
cat echovault.key echovault.crt ca.crt > echovault.pem
chmod 644 echovault.pem echovault.crt ca.crt

rm -f echovault.csr echovault.ext ca.srl
echo "[✓] Done. Distribute ./certs/ca.crt to browsers; mitmproxy uses echovault.pem."
echo "[i] CA fingerprint (must match the 'EchoVault Test CA' in your browser):"
openssl x509 -in ca.crt -noout -fingerprint -sha256 | sed 's/^/    /'
