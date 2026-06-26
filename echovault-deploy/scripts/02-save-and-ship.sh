#!/usr/bin/env bash
# Run on your LOCAL machine. Bundles the three images into one tar and copies it
# plus the deployment configs to the test box. Adjust USER/BOX as needed.
set -euo pipefail
cd "$(dirname "$0")/.."

BOX="${BOX:-10.188.199.221}"
USER="${SSH_USER:-$USER}"

echo "[*] Saving images to echovault-images.tar ..."
docker save echo_server:1.0 echo_client:1.0 mitmproxy/mitmproxy:latest \
  -o echovault-images.tar
echo "    $(du -h echovault-images.tar | cut -f1) written."

# Certs are generated ONCE and committed to the repo — we REUSE them here so we
# never invalidate the team's installed trust on a rebuild/ship. Only bootstrap
# them if they're missing (first-ever run). To deliberately reissue, run
# gen-certs.sh yourself with FORCE=1 (leaf) or FORCE_CA=1 (new CA) and commit.
if [[ -f ./mitmproxy/certs/echovault.pem && -f ./mitmproxy/certs/ca.crt ]]; then
  echo "[*] Reusing committed TLS certs in ./mitmproxy/certs (no regeneration)."
else
  echo "[!] No certs found — bootstrapping ONCE. Commit ./mitmproxy/certs after this."
  bash ./mitmproxy/gen-certs.sh
fi

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
