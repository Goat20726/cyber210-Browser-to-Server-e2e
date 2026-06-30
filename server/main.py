# ─────────────────────────────────────────────────────────────────────────────
# IMPORTS
# In Python, "import" brings in code that other people have written so we can
# reuse it instead of writing everything from scratch.
# ─────────────────────────────────────────────────────────────────────────────

# FastAPI is the web framework we're using. A "framework" is a toolkit that
# handles the boring plumbing of running a web server so we can focus on logic.
#   - FastAPI: the main application object/class.
#   - WebSocket: a special kind of network connection that stays OPEN so the
#       server and client (e.g. a browser) can send messages back and forth
#       in real time. A normal web request is "ask once, get one answer";
#       a WebSocket is more like a phone call that stays connected.
#   - WebSocketDisconnect: an "error signal" FastAPI raises when the client
#       hangs up the WebSocket connection.
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

# JSONResponse lets us send back data in JSON format (a common text format for
# data, e.g. {"status": "online"}) while ALSO controlling extra details like
# the HTTP status code (200 = OK, 404 = not found, etc.).
from fastapi.responses import JSONResponse  # <-- Imported here

# Built-in Python tools:
import json                  # Helps convert between JSON text and Python data.
from itertools import count  # A handy counter generator (explained where used).

# Create the actual application. Think of `app` as the central object that all
# our web routes get attached to. The web server runs THIS.
app = FastAPI()


# ─────────────────────────────────────────────────────────────────────────────
# HTTP ROUTES (normal "ask once, get one answer" web requests)
#
# The "@app.get(...)" line above a function is called a DECORATOR. It tells
# FastAPI: "when someone visits this URL with an HTTP GET request, run the
# function right below me." GET is the request type browsers use to fetch a page.
# ─────────────────────────────────────────────────────────────────────────────

# Example 1: Standard HTTP GET route using JSONResponse
@app.get("/api/status")
# "async def" defines an ASYNCHRONOUS function. In simple terms, async lets the
# server handle many users at once without getting stuck waiting on slow things
# (like network or disk). For now you can read it like a normal function.
async def get_status():
    # Useful for manually setting status codes or custom headers
    # We return a JSON response with an explicit "200 OK" status and a body
    # that tells the caller the service is online and where the WebSocket lives.
    return JSONResponse(
        status_code=200,
        content={"status": "online", "websocket_route": "/ws"}
    )


@app.get("/api/health")
async def get_health():
    # Useful for manually setting status codes or custom headers
    # A "health check" endpoint. Monitoring tools hit this URL periodically;
    # if it answers "ok", they know the server is alive.
    return JSONResponse(
        status_code=200,
        content={"status": "ok"}
    )


# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET ROUTE (the always-open, two-way connection)
#
# This endpoint "echoes" messages: whatever text the client sends, the server
# sends it back with " (Echo)" added. It also tracks message ORDER using
# sequence numbers to detect duplicated or out-of-order messages.
# ─────────────────────────────────────────────────────────────────────────────

# Your existing WebSocket code stays exactly the same
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    # A WebSocket connection must be explicitly accepted before use, like
    # picking up the phone when it rings. "await" means "wait for this slow
    # network step to finish before continuing" (that's the async part).
    await websocket.accept()
    print("Client connected")  # Prints to the server's log/console.

    # --- per-connection sequence state ---------------------------------
    # Each open connection gets its OWN copy of the variables below. They help
    # us number outgoing messages and validate incoming ones.

    # OUTGOING (s2c = "server to client"): our own monotonic counter. The first
    #   echo we send carries seq=0, then 1, 2, ...  The client validates THIS
    #   using the s2c-receive table you pasted (reject if seq <= lastS2C).
    #
    # count() is a generator that produces 0, 1, 2, 3, ... forever. Each time we
    # call next(s2c_seq) we get the next number in that sequence. "Monotonic"
    # just means it only ever goes up, never repeats.
    s2c_seq = count()  # 0, 1, 2, ...  -> next(s2c_seq)

    # INCOMING (c2s = "client to server"): receive guard. We remember the last
    #   sequence number we accepted from the client. We start at -1 so that the
    #   client's first legitimate message (seq=0) passes the check `seq > -1`.
    last_c2s = -1
    # -------------------------------------------------------------------

    # "try / except" is Python's error handling. We TRY to run the code; if
    # something goes wrong, an EXCEPT block below catches it instead of crashing.
    try:
        # Loop forever, processing one incoming message per pass, until the
        # client disconnects or an error breaks us out of the loop.
        while True:
            # Wait for the next message from the client and parse it as JSON
            # into a Python dictionary (a set of key/value pairs).
            message_data = await websocket.receive_json()

            # (1) read seq from the UNTRUSTED frame -- just parsing
            # ".get('seq')" safely reads the "seq" value; it returns None
            # (Python's "nothing here") if the key is missing, instead of crashing.
            seq = message_data.get("seq")

            # Make sure seq is actually a whole number and NOT a True/False value.
            # (In Python, True/False technically count as 1/0, so we exclude them
            # explicitly.) If the data is malformed, we "fail closed" — i.e.
            # reject it rather than risk trusting bad input.
            if not isinstance(seq, int) or isinstance(seq, bool):
                # "raise" throws an error, which jumps down to the except blocks.
                # The f"..." string lets us insert variables inside the text;
                # {seq!r} prints seq in a debug-friendly, quoted form.
                raise ValueError(f"missing or non-integer c2s seq: {seq!r}")

            # (2) reject if seq <= last_c2s.  Safe to reject on raw bytes
            #     (fails closed); cheap guard before any trust action.
            # If this message's number isn't HIGHER than the last one we accepted,
            # it's either a duplicate (replay) or arrived out of order — reject it.
            if seq <= last_c2s:
                raise ValueError(f"replay/reorder: c2s seq {seq} <= last {last_c2s}")

            # (3) AUTHENTICATE HERE.  In your table this is open(ct, aad) with
            #     aad = "echovault/v3" + "c2s" + seq(8B BE), which proves the
            #     seq+ciphertext are authentic before we trust them.
            #     This plaintext code has no AEAD layer, so step 3 is a no-op.
            #     >>> Until you add it, step 4 commits an UNAUTHENTICATED seq. <<<
            # (NOTE for the reader: this step is intentionally empty for now. The
            #  comment is a reminder that, in the secure version, we'd verify the
            #  message is genuine/untampered here BEFORE trusting its seq number.)

            # (4) commit -- a trust action, so only after (2)/(3) pass
            # Remember this seq as the newest one we've accepted, so future
            # messages must have an even higher number to be allowed through.
            last_c2s = seq

            # --- build + send the echo, stamped with OUR outgoing counter ---
            # Build the reply as a dictionary. Note the seq here is OUR OWN
            # server counter (next number from s2c_seq), not the client's number.
            echo_data = {
                "seq": next(s2c_seq),  # server-controlled s2c seq, NOT the client's
                # Take the client's "text", append " (Echo)" to it, and send back.
                "text": f"{message_data.get('text')} (Echo)",
                "sender": "assistant",
                "type": "msg",
                # Pass the original timestamp straight back to the client.
                "timestamp": message_data.get("timestamp"),
            }
            # Send our reply dictionary back to the client as JSON.
            await websocket.send_json(echo_data)

    # If the client closed the connection normally, FastAPI raises
    # WebSocketDisconnect. We catch it here so it's treated as expected, not a crash.
    except WebSocketDisconnect:
        print("Client disconnected gracefully")

    # Catch ANY other error (e.g. the ValueErrors we raised above, or unexpected
    # problems). "as e" gives us the error object so we can print its message.
    # This keeps one bad connection from taking down the whole server.
    except Exception as e:
        print(f"An error occurred: {e}")