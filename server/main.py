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
from fastapi.responses import JSONResponse
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

from hpke_server import (
    ServerKeys, ServerSession, ProtocolError,
    b64url_encode, load_server_keys, build_t_pubkey,
)

load_dotenv()

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"])
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
                plaintext = session.handle_msg(frame)
                reply     = session.seal_reply(b"ECHO: " + plaintext)
                await websocket.send_text(json.dumps(reply))

    except WebSocketDisconnect:
        pass
    except ProtocolError as e:
        print(f"[protocol] {e}")
        try:
            await websocket.close(code=4001, reason=str(e)[:100])
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
    """
    await websocket.accept()
    try:
        while True:
            text = await websocket.receive_text()
            await websocket.send_text(f"ECHO: {text}")
    except WebSocketDisconnect:
        pass
