#!/usr/bin/env bash
# Run on your LOCAL machine, from the staging dir that holds echo_server/,
# echo_client/ (with the Next.js source copied in), and mitmproxy/.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "[*] Creating shared docker network (idempotent)..."
docker network create proxynet 2>/dev/null || true

echo "[*] Building echo_server:1.0 ..."
docker build --no-cache -t echo_server:1.0 ./echo_server

# page.tsx reads NEXT_PUBLIC_API_URL (https://) and derives wss:// from it.
echo "[*] Building echo_client:1.0 (API URL baked to https://echo.server.test) ..."
docker build  --no-cache -t echo_client:1.0 \
  --build-arg NEXT_PUBLIC_API_URL=https://echo.server.test ./echo_client

echo "[*] Pulling mitmproxy base image ..."
docker pull mitmproxy/mitmproxy

echo "[✓] Images ready:"
docker images | grep -E 'echo_server|echo_client|mitmproxy/mitmproxy'
