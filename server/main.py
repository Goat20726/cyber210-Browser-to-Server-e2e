from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse # <-- Imported here
import json
from itertools import count

app = FastAPI()


# Example 1: Standard HTTP GET route using JSONResponse
@app.get("/api/status")
async def get_status():
    # Useful for manually setting status codes or custom headers
    return JSONResponse(
        status_code=200,
        content={"status": "online", "websocket_route": "/ws"}
    )
@app.get("/api/health")
async def get_health():
    # Useful for manually setting status codes or custom headers
    return JSONResponse(
        status_code=200,
        content={"status": "ok"}
    )

# Your existing WebSocket code stays exactly the same
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("Client connected")
     # --- per-connection sequence state ---------------------------------
    # OUTGOING (s2c): our own monotonic counter. The first echo we send
    #   carries seq=0, then 1, 2, ...  The client validates THIS using the
    #   s2c-receive table you pasted (reject if seq <= lastS2C).
    s2c_seq = count()  # 0, 1, 2, ...  -> next(s2c_seq)
    # INCOMING (c2s): receive guard. Init to firstValidSeq - 1 so the first
    #   legit client frame (seq=0) passes `seq > last_c2s`.  (table step 0)
    last_c2s = -1
    # -------------------------------------------------------------------
    try:
        while True:
            message_data = await websocket.receive_json()

            # (1) read seq from the UNTRUSTED frame -- just parsing
            seq = message_data.get("seq")
            if not isinstance(seq, int) or isinstance(seq, bool):
                # malformed / missing seq -> fail closed
                raise ValueError(f"missing or non-integer c2s seq: {seq!r}")

            # (2) reject if seq <= last_c2s.  Safe to reject on raw bytes
            #     (fails closed); cheap guard before any trust action.
            if seq <= last_c2s:
                raise ValueError(f"replay/reorder: c2s seq {seq} <= last {last_c2s}")

            # (3) AUTHENTICATE HERE.  In your table this is open(ct, aad) with
            #     aad = "echovault/v3" + "c2s" + seq(8B BE), which proves the
            #     seq+ciphertext are authentic before we trust them.
            #     This plaintext code has no AEAD layer, so step 3 is a no-op.
            #     >>> Until you add it, step 4 commits an UNAUTHENTICATED seq. <<<

            # (4) commit -- a trust action, so only after (2)/(3) pass
            last_c2s = seq

            # --- build + send the echo, stamped with OUR outgoing counter ---
            echo_data = {
                "seq": next(s2c_seq),  # server-controlled s2c seq, NOT the client's
                "text": f"{message_data.get('text')} (Echo)",
                "sender": "assistant",
                "type": "msg",
                "timestamp": message_data.get("timestamp"),
            }
            await websocket.send_json(echo_data)
    except WebSocketDisconnect:
        print("Client disconnected gracefully")
    except Exception as e:
        print(f"An error occurred: {e}")
