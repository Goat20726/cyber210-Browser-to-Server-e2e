#!/usr/bin/env bash
# Run on your LOCAL machine, from the staging dir that holds echo_server/,
# echo_client/ (with the Next.js source copied in), and mitmproxy/.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[*] Creating shared docker network (idempotent)..."
docker network create proxynet 2>/dev/null || true

echo "[*] Building echo_server:1.0 ..."
docker build -t echo_server:1.0 ./echo_server

echo "[*] Building echo_client:1.0 (WS URL baked to wss://echo.server.test) ..."
docker build -t echo_client:1.0 \
  --build-arg NEXT_PUBLIC_WS_URL=wss://echo.server.test ./echo_client

echo "[*] Pulling mitmproxy base image ..."
docker pull mitmproxy/mitmproxy

echo "[✓] Images ready:"
docker images | grep -E 'echo_server|echo_client|mitmproxy/mitmproxy'
