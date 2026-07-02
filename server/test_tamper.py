"""Tamper test: bit-flipped ciphertext must be rejected, not echoed."""
import asyncio, json, os
from datetime import datetime, timezone
import websockets, httpx
from hpke_server import SUITE, PROTO_INFO, make_aad, pubkey_to_hex, hex_to_pubkey

async def main():
    async with httpx.AsyncClient() as http:
        resp = await http.get("http://localhost:8000/api/pubkey")
        server_pub_hex = resp.json()["pubkey_hex"]
    server_pub     = hex_to_pubkey(server_pub_hex)
    client_keypair = SUITE.kem.derive_key_pair(os.urandom(32))

    async with websockets.connect("ws://localhost:8000/ws") as ws:
        enc, sender_ctx_c2s = SUITE.create_sender_context(pkr=server_pub, info=PROTO_INFO)
        ct = sender_ctx_c2s.seal(b"legit first message", aad=make_aad("c2s", 0))
        tampered = bytearray(ct); tampered[-1] ^= 0xFF

        await ws.send(json.dumps({
            "type": "init", "seq": 0,
            "enc": enc.hex(), "client_pub": pubkey_to_hex(client_keypair),
            "text": bytes(tampered).hex(),
            "sender": "user", "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
        try:
            reply = await ws.recv()
            print(f"❌ Server replied to tampered ciphertext: {reply!r} -- BAD")
        except websockets.exceptions.ConnectionClosed as e:
            print(f"✅ Tampered ciphertext correctly rejected (code={e.code})")

if __name__ == "__main__":
    asyncio.run(main())
