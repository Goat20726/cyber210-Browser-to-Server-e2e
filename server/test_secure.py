"""Tests E2E ON path: HPKE handshake + ongoing messages in the JSON wire format."""
import asyncio, json, os
from datetime import datetime, timezone
import websockets, httpx
from hpke_server import SUITE, PROTO_INFO, make_aad, pubkey_to_hex, hex_to_pubkey

async def main():
    async with httpx.AsyncClient() as http:
        resp = await http.get("http://localhost:8000/api/pubkey")
        server_pub_hex = resp.json()["pubkey_hex"]
        print("fetched server pubkey:", server_pub_hex[:24] + "...")

    server_pub     = hex_to_pubkey(server_pub_hex)
    client_keypair = SUITE.kem.derive_key_pair(os.urandom(32))

    async with websockets.connect("ws://localhost:8000/ws") as ws:
        # ── init ─────────────────────────────────────────────────────────
        c2s_seq = 0
        enc, sender_ctx_c2s = SUITE.create_sender_context(pkr=server_pub, info=PROTO_INFO)
        first_msg = b"hello from a real websocket test client"
        ct = sender_ctx_c2s.seal(first_msg, aad=make_aad("c2s", c2s_seq))

        now = datetime.now(timezone.utc).isoformat()
        await ws.send(json.dumps({
            "type": "init", "seq": c2s_seq,
            "enc": enc.hex(), "client_pub": pubkey_to_hex(client_keypair),
            "text": ct.hex(), "sender": "user", "timestamp": now,
        }))

        init_ack = json.loads(await ws.recv())
        assert init_ack["type"] == "init_ack"
        s2c_seq_client = init_ack["seq"]
        recipient_ctx_s2c = SUITE.create_recipient_context(
            enc=bytes.fromhex(init_ack["enc"]),
            skr=client_keypair.private_key, info=PROTO_INFO,
        )
        opened = recipient_ctx_s2c.open(
            bytes.fromhex(init_ack["text"]), aad=make_aad("s2c", s2c_seq_client)
        )
        print(f"handshake reply decrypted: {opened!r}")
        assert opened == b"ECHO: " + first_msg

        # ── subsequent messages ───────────────────────────────────────────
        for i, msg in enumerate([b"second real message", b"sensitive prompt text", b"final test message"], start=1):
            c2s_seq += 1
            ct = sender_ctx_c2s.seal(msg, aad=make_aad("c2s", c2s_seq))
            await ws.send(json.dumps({
                "type": "msg", "seq": c2s_seq, "text": ct.hex(),
                "sender": "user", "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            frame = json.loads(await ws.recv())
            s2c_seq_client = frame["seq"]
            opened = recipient_ctx_s2c.open(
                bytes.fromhex(frame["text"]), aad=make_aad("s2c", s2c_seq_client)
            )
            print(f"round trip ok: {msg!r} -> {opened!r}")
            assert opened == b"ECHO: " + msg

    print("\n✅ Full HPKE-encrypted (E2E ON) round trip succeeded on /ws.")

if __name__ == "__main__":
    asyncio.run(main())
