"""
Demonstrates the core exhibit: mitmproxy sees CLEARTEXT when E2E is OFF,
and only {enc, text=ciphertext} when E2E is ON.

In real usage each session is either E2E OFF or ON -- not toggled mid-stream.
This test simulates both modes on separate connections, the same way the
live mitmweb demo would show them.
"""
import asyncio, json, os
from datetime import datetime, timezone
import websockets, httpx
from hpke_server import SUITE, PROTO_INFO, make_aad, pubkey_to_hex, hex_to_pubkey

async def main():
    now = lambda: datetime.now(timezone.utc).isoformat()

    # ── Session 1: E2E OFF ────────────────────────────────────────────────
    # mitmproxy sees: {"type":"msg","seq":0,"text":"hello world",...}
    print("=== Session 1: E2E OFF (mitmproxy sees cleartext) ===")
    async with websockets.connect("ws://localhost:8000/ws") as ws:
        for i, text in enumerate(["hello world", "sensitive prompt here"]):
            await ws.send(json.dumps({"type": "msg", "seq": i, "text": text,
                                      "sender": "user", "timestamp": now()}))
            reply = json.loads(await ws.recv())
            print(f"  [cleartext in mitmweb] -> {reply['text']!r}")
            assert reply["text"] == f"{text} (Echo)"
    print()

    # ── Session 2: E2E ON ────────────────────────────────────────────────
    # mitmproxy sees: {"type":"init","enc":"...","text":"<ciphertext>","client_pub":"...",...}
    print("=== Session 2: E2E ON (mitmproxy sees only ciphertext) ===")
    async with httpx.AsyncClient() as http:
        resp = await http.get("http://localhost:8000/api/pubkey")
        server_pub_hex = resp.json()["pubkey_hex"]
    server_pub     = hex_to_pubkey(server_pub_hex)
    client_keypair = SUITE.kem.derive_key_pair(os.urandom(32))

    async with websockets.connect("ws://localhost:8000/ws") as ws:
        enc, sender_ctx_c2s = SUITE.create_sender_context(pkr=server_pub, info=PROTO_INFO)
        ct = sender_ctx_c2s.seal(b"hello world", aad=make_aad("c2s", 0))
        print(f"  [wire payload text field] -> '{ct.hex()[:32]}...' (ciphertext only)")
        await ws.send(json.dumps({
            "type": "init", "seq": 0,
            "enc": enc.hex(), "client_pub": pubkey_to_hex(client_keypair),
            "text": ct.hex(), "sender": "user", "timestamp": now(),
        }))
        ack = json.loads(await ws.recv())
        recipient_ctx_s2c = SUITE.create_recipient_context(
            enc=bytes.fromhex(ack["enc"]), skr=client_keypair.private_key, info=PROTO_INFO
        )
        opened = recipient_ctx_s2c.open(bytes.fromhex(ack["text"]), aad=make_aad("s2c", ack["seq"]))
        print(f"  [client decrypted reply ] -> {opened!r}")
        assert opened == b"ECHO: hello world"

    print()
    print("✅ Exhibit demonstrated: E2E OFF = cleartext in mitmweb, E2E ON = ciphertext only.")

if __name__ == "__main__":
    asyncio.run(main())
