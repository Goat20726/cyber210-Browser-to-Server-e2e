#!/usr/bin/env bash
# Run on your LOCAL machine. Bundles the three images into one tar and copies it
# plus the deployment configs to the test box. Adjust USER/BOX as needed.
set -euo pipefail
cd "$(dirname "$0")/.."

BOX="${BOX:-172.16.165.17}"
USER="${SSH_USER:-$USER}"

echo "[*] Saving images to echovault-images.tar ..."
docker save echo_server:1.0 echo_client:1.0 mitmproxy/mitmproxy:latest \
  -o echovault-images.tar
echo "    $(du -h echovault-images.tar | cut -f1) written."

echo "[*] Generating TLS certs locally (so ca.crt ships with the bundle) ..."
bash ./mitmproxy/gen-certs.sh

echo "[*] Copying image tarball to ${USER}@${BOX}:/tmp/ ..."
scp echovault-images.tar "${USER}@${BOX}:/tmp/"

echo "[*] Copying deployment configs to the box's /opt (needs sudo there) ..."
# Stage under /tmp first, then move into /opt on the box (next script).
ssh "${USER}@${BOX}" 'mkdir -p /tmp/echovault/{mitmproxy,echo_server,echo_client}'
scp -r ./mitmproxy/docker-compose.yml ./mitmproxy/route.py ./mitmproxy/certs \
      "${USER}@${BOX}:/tmp/echovault/mitmproxy/"
scp    ./echo_server/docker-compose.yml "${USER}@${BOX}:/tmp/echovault/echo_server/"
scp    ./echo_client/docker-compose.yml "${USER}@${BOX}:/tmp/echovault/echo_client/"
scp    ./scripts/03-deploy-on-box.sh    "${USER}@${BOX}:/tmp/echovault/"

echo "[✓] Shipped. Now SSH to the box and run /tmp/echovault/03-deploy-on-box.sh"
