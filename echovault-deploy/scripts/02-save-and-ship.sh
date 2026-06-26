#!/usr/bin/env bash
# Run on your LOCAL machine. Bundles the three images into one tar and copies it
# plus the deployment configs to the test box. Adjust USER/BOX as needed.
#
# PASSWORD AUTH (no ssh-copy-id needed): this script opens ONE shared SSH
# connection up front (you type the password a single time), and every scp/ssh
# below reuses it via SSH connection multiplexing — so you are NOT prompted five
# separate times. The shared connection is closed automatically on exit.
#   • Prefer keys?  Run `ssh-copy-id $SSH_USER@$BOX` once and you won't be asked.
#   • Fully unattended?  Install `sshpass` and run with  SSHPASS='yourpw' ...
set -euo pipefail
cd "$(dirname "$0")/.."

BOX="${BOX:-10.188.199.221}"
USER="${SSH_USER:-$USER}"

# ── One authenticated SSH channel, reused by all scp/ssh calls ───────────────
# ControlMaster opens a single connection; ControlPath is its socket; the later
# commands attach to it instead of re-authenticating. ControlPersist keeps it
# briefly alive. Result with password auth: ONE prompt for the whole run.
CTRL="${TMPDIR:-/tmp}/echovault-ssh-%r@%h:%p"
SSH_OPTS=(-o ControlMaster=auto -o "ControlPath=${CTRL}" -o ControlPersist=120)

# Optional fully-unattended mode: SSHPASS='pw' ./02-save-and-ship.sh
SSH_RUN=(ssh "${SSH_OPTS[@]}")
SCP_RUN=(scp "${SSH_OPTS[@]}")
if [[ -n "${SSHPASS:-}" ]] && command -v sshpass >/dev/null 2>&1; then
  SSH_RUN=(sshpass -e ssh "${SSH_OPTS[@]}")
  SCP_RUN=(sshpass -e scp "${SSH_OPTS[@]}")
fi

# Make sure the shared connection is torn down whenever the script ends.
cleanup() { ssh "${SSH_OPTS[@]}" -O exit "${USER}@${BOX}" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "[*] Opening one shared SSH connection to ${USER}@${BOX} (enter password once) ..."
"${SSH_RUN[@]}" -o ConnectTimeout=10 "${USER}@${BOX}" 'true'

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
"${SCP_RUN[@]}" echovault-images.tar "${USER}@${BOX}:/tmp/"

echo "[*] Copying deployment configs to the box's /opt (needs sudo there) ..."
# Stage under /tmp first, then move into /opt on the box (next script).
"${SSH_RUN[@]}" "${USER}@${BOX}" 'mkdir -p /tmp/echovault/{mitmproxy,echo_server,echo_client}'
"${SCP_RUN[@]}" -r ./mitmproxy/docker-compose.yml ./mitmproxy/route.py ./mitmproxy/certs \
      "${USER}@${BOX}:/tmp/echovault/mitmproxy/"
"${SCP_RUN[@]}" ./echo_server/docker-compose.yml "${USER}@${BOX}:/tmp/echovault/echo_server/"
"${SCP_RUN[@]}" ./echo_client/docker-compose.yml "${USER}@${BOX}:/tmp/echovault/echo_client/"
"${SCP_RUN[@]}" ./scripts/03-deploy-on-box.sh    "${USER}@${BOX}:/tmp/echovault/"

echo "[✓] Shipped. Now SSH to the box and run /tmp/echovault/03-deploy-on-box.sh"
