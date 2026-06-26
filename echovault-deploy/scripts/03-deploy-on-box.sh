#!/usr/bin/env bash
# Run on the TEST BOX (10.188.199.221), as a user with sudo + docker access.
# Loads the prebuilt images (no building happens here) and brings up all three
# containers on the shared proxynet network.
set -euo pipefail
# ── Tear down any existing stack and delete old images before loading new ones ─
# Containers must be stopped/removed first, otherwise their images can't be
# deleted ("image is being used by running container"). Guards make this safe on
# a first-ever deploy when nothing exists yet.
echo "[*] Stopping any existing EchoVault stack ..."
for svc in mitmproxy echo_client echo_server; do
  f="/opt/${svc}/docker-compose.yml"
  [[ -f "$f" ]] && docker compose -f "$f" down --remove-orphans 2>/dev/null || true
done

echo "[*] Removing old images so the new tarball fully replaces them ..."
# Our app images share the :1.0 tag, so loading would otherwise leave the old
# build as a dangling layer. Remove them explicitly, then prune dangling layers.
docker rmi -f echo_server:1.0 echo_client:1.0 mitmproxy/mitmproxy:latest 2>/dev/null || true
docker image prune -f >/dev/null 2>&1 || true

echo "[*] Loading images from /tmp/echovault-images.tar ..."
docker load -i /tmp/echovault-images.tar

echo "[*] Installing configs into /opt ..."
sudo mkdir -p /opt/mitmproxy /opt/echo_server /opt/echo_client
sudo cp -r /tmp/echovault/mitmproxy/*    /opt/mitmproxy/
sudo cp    /tmp/echovault/echo_server/*  /opt/echo_server/
sudo cp    /tmp/echovault/echo_client/*  /opt/echo_client/

echo "[*] Deleting old dockers if they exist (idempotent)..."


echo "[*] Creating shared docker network (idempotent)..."
docker network create proxynet 2>/dev/null || true

echo "[*] Starting backends, then the proxy ..."
docker compose -f /opt/echo_server/docker-compose.yml up -d
docker compose -f /opt/echo_client/docker-compose.yml up -d
docker compose -f /opt/mitmproxy/docker-compose.yml   up -d

echo "[✓] Up. Containers:"
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
echo
echo "Next: install /opt/mitmproxy/certs/ca.crt in your browser, add the two"
echo "hostnames to your hosts file (-> 10.188.199.221), then open https://echo.client.test"
