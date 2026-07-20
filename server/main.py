"""
server/main.py — EchoVault echo server (protocol v1 frozen)

Endpoints:
  GET /api/health   → {"status":"ok"}
  GET /api/status   → {"status":"online","websocket_route":"/ws"}
  GET /pubkey       → {server_x25519, server_ed25519, sig}  (§5.1)
  GET /api/pubkey   → alias (backward compat)
  WS  /ws           → HPKE echo, strict state machine (§5.6)
  WS  /ws/plain     → plaintext echo — demo exhibit (b): E2E OFF, mitmweb sees cleartext
"""

import json

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from hpke_server import (
    ServerKeys, ServerSession, ProtocolError,
    b64url_encode, load_server_keys, build_t_pubkey,
)

load_dotenv()

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"])  # demo only
SERVER_KEYS: ServerKeys = load_server_keys()


# ── HTTP ───────────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def get_health():
    return JSONResponse(status_code=200, content={"status": "ok"})


@app.get("/api/status")
async def get_status():
    return JSONResponse(status_code=200, content={
        "status": "online", "websocket_route": "/ws"
    })


def _pubkey_payload() -> dict:
    """Build /pubkey response with fresh Ed25519 signature (§5.1)."""
    t   = build_t_pubkey(SERVER_KEYS.x25519_pub_bytes, SERVER_KEYS.ed25519_pub_bytes)
    sig = SERVER_KEYS.ed25519_priv.sign(t)
    return {
        "server_x25519":  b64url_encode(SERVER_KEYS.x25519_pub_bytes),
        "server_ed25519": b64url_encode(SERVER_KEYS.ed25519_pub_bytes),
        "sig":            b64url_encode(sig),
    }


@app.get("/pubkey")
async def get_pubkey():
    return JSONResponse(status_code=200, content=_pubkey_payload())


@app.get("/api/pubkey")   # backward compat alias
async def get_pubkey_alias():
    return JSONResponse(status_code=200, content=_pubkey_payload())


# ── WebSocket: strict HPKE protocol (§5.6) ────────────────────────────────────

@app.websocket("/ws")
async def ws_hpke(websocket: WebSocket):
    """
    Strict HPKE echo endpoint.
    Phase machine: AWAIT_HELLO → (hello) → ESTABLISHED → (msg…)
    Any protocol fault → close 4001; no plaintext fallback.
    """
    await websocket.accept()
    session = ServerSession(keys=SERVER_KEYS)

    try:
        while True:
            try:
                frame = json.loads(await websocket.receive_text())
            except Exception as e:
                raise ProtocolError(f"malformed/non-JSON frame: {e}")

            frame_type = frame.get("type")

            if session.phase == "AWAIT_HELLO":
                if frame_type != "hello":
                    raise ProtocolError(f"expected hello in AWAIT_HELLO, got {frame_type!r}")
                server_hello = session.handle_hello(frame)
                await websocket.send_text(json.dumps(server_hello))

            elif session.phase == "ESTABLISHED":
                if frame_type != "msg":
                    raise ProtocolError(f"expected msg in ESTABLISHED, got {frame_type!r}")
                # 'text' vs 'ct' discriminator: the secure channel carries ONLY
                # sealed message blocks. A 'text' (plaintext) frame here means
                # the sender fell out of E2E — kill this session so the client
                # must re-establish a brand-new secure connection (fresh
                # handshake, fresh HPKE contexts). Never echo plaintext on /ws.
                if "text" in frame or "ct" not in frame:
                    raise ProtocolError("plaintext frame on secure channel — new secure connection required")
                plaintext = session.handle_msg(frame)
                reply     = session.seal_reply(b"ECHO: " + plaintext)
                await websocket.send_text(json.dumps(reply))

    except WebSocketDisconnect:
        pass
    except ProtocolError as e:
        print(f"[protocol] {e}")
        try:
            # Surface the fault class in the close reason (≤123 bytes) so the
            # client can auto-re-establish on the plaintext-on-secure case.
            await websocket.close(code=4001, reason=str(e)[:120] or "protocol error")
        except Exception:
            pass
    except Exception as e:
        print(f"[error] {e}")
        try:
            await websocket.close(code=4001, reason="internal error")
        except Exception:
            pass


# ── WebSocket: plaintext echo — demo exhibit (b): E2E OFF ─────────────────────

@app.websocket("/ws/plain")
async def ws_plain(websocket: WebSocket):
    """
    Plaintext echo — no HPKE.
    mitmproxy sees the prompt in cleartext: demonstrates TLS-alone limitation.

    Message blocks mirror the secure channel but use 'text' where /ws uses 'ct':
      client → {"type":"msg", "seq": N, "text": "..."}
      server → {"type":"msg", "seq": N, "text": "ECHO: ...", "plaintext": true}

    Invariants:
      * A frame carrying 'ct' (or missing 'text') is rejected — close 4002.
        Sealed traffic belongs on /ws only; this keeps the two modes disjoint.
      * An echo is emitted ONLY in direct response to a received plaintext
        transmit (transmits_seen gate) — the server never originates a
        plaintext echo the client didn't ask for.
    """
    await websocket.accept()
    transmits_seen = 0
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                frame = json.loads(raw)
            except Exception:
                await websocket.close(code=4002, reason="malformed frame: expected JSON message block")
                return
            if (
                not isinstance(frame, dict)
                or frame.get("type") != "msg"
                or "ct" in frame
                or not isinstance(frame.get("text"), str)
            ):
                await websocket.close(code=4002, reason="plain endpoint accepts only 'text' message blocks")
                return

            transmits_seen += 1
            if transmits_seen < 1:
                # Defensive: no plaintext echo may leave without a transmit first.
                continue
            await websocket.send_text(json.dumps({
                "type": "msg",
                "seq": frame.get("seq", 0),
                "text": f"ECHO: {frame['text']}",
                "plaintext": True,
            }))
    except WebSocketDisconnect:
        pass
