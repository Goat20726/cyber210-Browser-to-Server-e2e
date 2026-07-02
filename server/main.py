"""
server/main.py — EchoVault echo server (W3: HPKE on top of W2 baseline)

Wire format — ALL frames both directions are JSON (matching client exactly):
  {
    "type":      "msg" | "init" | "init_ack",
    "seq":       <int>,          # monotonic; replays rejected
    "text":      <str>,          # plaintext (E2E OFF) or ciphertext hex (E2E ON)
    "sender":    "user" | "assistant",
    "timestamp": <iso-str>
  }

E2E ON adds two extra fields on the init frame only:
  "enc":        <hex>    # KEM encapsulated key (one-time, c2s direction)
  "client_pub": <hex>    # client's ephemeral pubkey (server seals s2c to this)

text → ct: when HPKE is active, "text" carries ciphertext hex instead of
plaintext. All other fields stay identical to the W2 baseline. This is the
change described in the W2 server/main.py comment: "text → ct in W4".

Mode detection (per-message, not per-connection):
  type=="init"            → start HPKE channel, open first sealed message
  type=="msg" + channel   → open sealed message on existing channel
  type=="msg" + no channel→ plaintext echo (E2E OFF exhibit state)

SERVER IDENTITY: loaded from .env (SERVER_HPKE_PRIVATE_KEY_HEX).
Run `python3 generate_keys.py` once to generate. See docs/decisions.md D006.
"""

from datetime import datetime, timezone
from itertools import count

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse
from dotenv import load_dotenv

from hpke_server import (
    load_server_keypair_from_env, pubkey_to_hex,
    SecureChannel, make_aad,
)

load_dotenv()

app = FastAPI()

SERVER_KEYPAIR = load_server_keypair_from_env()
SERVER_PUB_HEX = pubkey_to_hex(SERVER_KEYPAIR)


# ── HTTP endpoints ────────────────────────────────────────────────────────────

@app.get("/api/health")
async def get_health():
    return JSONResponse(status_code=200, content={"status": "ok"})


@app.get("/api/status")
async def get_status():
    return JSONResponse(
        status_code=200,
        content={"status": "online", "websocket_route": "/ws"},
    )


@app.get("/api/pubkey")
async def get_pubkey():
    # Delivers the server's static HPKE public key so the browser can seal
    # messages before the WS connection opens. REST delivery assumed --
    # confirm with Fil if a different mechanism is needed (see decisions.md D005).
    return JSONResponse(
        status_code=200,
        content={
            "pubkey_hex": SERVER_PUB_HEX,
            "suite": "DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/ChaCha20-Poly1305",
        },
    )


# ── WebSocket endpoint ────────────────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    # Per-connection seq state (unchanged from W2 baseline).
    s2c_seq = count()       # server's own outgoing counter
    last_c2s = -1           # last accepted client seq (guards replays)

    # Per-connection HPKE state (None until an "init" frame arrives).
    channel: SecureChannel | None = None

    try:
        while True:
            message_data = await websocket.receive_json()

            msg_type  = message_data.get("type")
            seq       = message_data.get("seq")
            text      = message_data.get("text", "")
            timestamp = message_data.get("timestamp")

            # ── seq validation (same guard as W2 baseline) ────────────────
            if not isinstance(seq, int) or isinstance(seq, bool):
                raise ValueError(f"missing or non-integer c2s seq: {seq!r}")
            if seq <= last_c2s:
                raise ValueError(f"replay/reorder: c2s seq {seq} <= last {last_c2s}")
            # Commit only after the checks pass (matches the comment in W2 main.py:
            # "commit -- a trust action, so only after (2)/(3) pass").
            last_c2s = seq
            # ─────────────────────────────────────────────────────────────

            my_seq = next(s2c_seq)
            now = datetime.now(timezone.utc).isoformat()

            if msg_type == "init":
                # ── E2E ON: HPKE handshake ────────────────────────────────
                # "text" carries the first sealed ciphertext (hex).
                # "enc" and "client_pub" carry the KEM material.
                enc_hex        = message_data.get("enc", "")
                client_pub_hex = message_data.get("client_pub", "")

                c2s_aad = make_aad("c2s", seq)
                channel  = SecureChannel(server_keypair=SERVER_KEYPAIR)
                plaintext = channel.handle_init(enc_hex, client_pub_hex, text, c2s_aad)

                s2c_aad  = make_aad("s2c", my_seq)
                reply_ct = channel.seal_reply(b"ECHO: " + plaintext, s2c_aad)
                s2c_enc  = channel.pop_pending_s2c_enc()

                await websocket.send_json({
                    "type":      "init_ack",
                    "seq":       my_seq,
                    "enc":       s2c_enc.hex(),
                    "text":      reply_ct.hex(),
                    "sender":    "assistant",
                    "timestamp": now,
                })

            elif msg_type == "msg" and channel is not None:
                # ── E2E ON: subsequent sealed message ─────────────────────
                # "text" should be ciphertext hex. If it isn't (e.g. the UI
                # toggled E2E off mid-session), fall through to plaintext echo
                # rather than crashing -- belt-and-suspenders for the demo.
                try:
                    c2s_aad   = make_aad("c2s", seq)
                    plaintext = channel.handle_msg(text, c2s_aad)
                    s2c_aad   = make_aad("s2c", my_seq)
                    reply_ct  = channel.seal_reply(b"ECHO: " + plaintext, s2c_aad)
                    await websocket.send_json({
                        "type":      "msg",
                        "seq":       my_seq,
                        "text":      reply_ct.hex(),
                        "sender":    "assistant",
                        "timestamp": now,
                    })
                except Exception:
                    # Not valid ciphertext -- treat as plaintext (E2E OFF fallback)
                    await websocket.send_json({
                        "type":      "msg",
                        "seq":       my_seq,
                        "text":      f"{text} (Echo)",
                        "sender":    "assistant",
                        "timestamp": now,
                    })

            else:
                # ── E2E OFF: plaintext echo (W2 baseline behaviour) ───────
                await websocket.send_json({
                    "type":      "msg",
                    "seq":       my_seq,
                    "text":      f"{text} (Echo)",
                    "sender":    "assistant",
                    "timestamp": now,
                })

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"An error occurred: {e}")
        try:
            await websocket.close(code=4001, reason=f"error: {type(e).__name__}")
        except Exception:
            pass
