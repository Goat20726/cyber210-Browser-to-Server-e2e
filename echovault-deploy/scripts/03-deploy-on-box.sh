#!/usr/bin/env bash
# Run on the TEST BOX (10.188.199.221), as a user with sudo + docker access.
# Loads the prebuilt images (no building happens here) and brings up all three
# containers on the shared proxynet network.
set -euo pipefail

echo "[*] Loading images from /tmp/echovault-images.tar ..."
docker load -i /tmp/echovault-images.tar

echo "[*] Installing configs into /opt ..."
sudo mkdir -p /opt/mitmproxy /opt/echo_server /opt/echo_client
sudo cp -r /tmp/echovault/mitmproxy/*    /opt/mitmproxy/
sudo cp    /tmp/echovault/echo_server/*  /opt/echo_server/
sudo cp    /tmp/echovault/echo_client/*  /opt/echo_client/

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
