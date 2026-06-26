# ── EchoVault host-based reverse-proxy router ────────────────────────────────
# mitmproxy runs in reverse mode and terminates TLS on the listen port using our
# custom cert (covers both hostnames via SAN). A single reverse target only
# forwards to ONE backend, so this addon inspects which hostname the browser
# asked for and rewrites the upstream so one proxy fronts BOTH services:
#
#   https://echo.client.test  → client:3000  (Next.js UI)
#   wss://echo.server.test/ws → server:8000  (FastAPI echo / WebSocket)
#
# IMPORTANT — why we route on the TLS SNI, not request.pretty_host:
# In reverse mode mitmproxy normalizes the request host to the configured
# upstream, and (depending on keep_host_header) may rewrite the Host header.
# The one value that is ALWAYS the exact name the browser requested is the TLS
# SNI from the handshake (flow.client_conn.sni). We key on that, and fall back
# to the Host header only if SNI is somehow absent (e.g. plain http).
#
# Setting flow.request.host/port in the request hook is the documented way to
# redirect the upstream per-flow in reverse mode (same mechanism as mitmproxy's
# loadbalancer example). It also covers the WebSocket, since that starts life as
# a normal HTTP upgrade request.

from mitmproxy import http

ROUTES = {
    "echo.client.test": ("client", 3000),
    "echo.server.test": ("server", 8000),
}


def _requested_host(flow: http.HTTPFlow) -> str:
    # 1) TLS SNI — the exact name from the handshake, unaffected by reverse-mode
    #    host rewriting. This is the reliable key.
    sni = getattr(flow.client_conn, "sni", None)
    if sni:
        return sni.split(":")[0].strip().lower()
    # 2) Fallback: the Host header (strip any :port).
    host_hdr = flow.request.host_header or flow.request.pretty_host or ""
    return host_hdr.split(":")[0].strip().lower()


def request(flow: http.HTTPFlow) -> None:
    host = _requested_host(flow)
    target = ROUTES.get(host)
    if target is None:
        # Unknown vhost: refuse rather than leak to the default upstream.
        flow.response = http.Response.make(
            404,
            f"unknown host: {host!r}\n".encode(),
            {"Content-Type": "text/plain"},
        )
        return
    upstream_host, upstream_port = target
    flow.request.host = upstream_host        # redirect the TCP destination...
    flow.request.port = upstream_port        # ...to the matching backend
    flow.request.scheme = "http"             # backends speak plain http/ws
