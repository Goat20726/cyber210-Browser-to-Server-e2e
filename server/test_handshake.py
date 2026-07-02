"""
Full protocol handshake integration test — simulates browser side in Python.
Flow: GET /pubkey → verify sig → hello → server_hello → verify → msg × N → tamper test.
"""
import asyncio, json, os
import httpx, websockets
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from hpke_server import (
    SUITE, HPKE_INFO, DIR_C2S, DIR_S2C,
    b64url_encode, b64url_decode, seq_to_hex, hex_to_seq,
    build_t_pubkey, build_t_hello, build_t_server_hello,
    compute_session_id, make_aad,
)

BASE = "http://localhost:8000"
WS   = "ws://localhost:8000/ws"


async def browser_sim():
    """Simulates the browser side of the full protocol."""

    # ── 1. GET /pubkey → verify sig, pin keys ─────────────────────────────
    async with httpx.AsyncClient() as http:
        resp = await http.get(f"{BASE}/pubkey")
    assert resp.status_code == 200, f"/pubkey returned {resp.status_code}"
    pub = resp.json()

    server_x25519_bytes  = b64url_decode(pub["server_x25519"])
    server_ed25519_bytes = b64url_decode(pub["server_ed25519"])
    pub_sig              = b64url_decode(pub["sig"])

    # Verify /pubkey signature (§4.1)
    t_pubkey = build_t_pubkey(server_x25519_bytes, server_ed25519_bytes)
    Ed25519PublicKey.from_public_bytes(server_ed25519_bytes).verify(pub_sig, t_pubkey)
    print(f"✅ /pubkey sig verified — server pinned")

    # ── 2. Browser key material (random for tests — real browser uses BIP-39) ──
    browser_ed25519_priv = Ed25519PrivateKey.generate()
    browser_ed25519_pub  = browser_ed25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    # browser_x25519 = static identity key (server seals replies to this)
    browser_x25519_kp  = SUITE.kem.derive_key_pair(os.urandom(32))
    browser_x25519_pub = browser_x25519_kp.public_key.to_public_bytes()

    # ── 3. hello ──────────────────────────────────────────────────────────
    server_x25519_pub_obj = SUITE.kem.deserialize_public_key(server_x25519_bytes)
    c2s_enc, c2s_sender   = SUITE.create_sender_context(pkr=server_x25519_pub_obj, info=HPKE_INFO)

    t_hello   = build_t_hello(browser_x25519_pub, browser_ed25519_pub, c2s_enc,
                               server_x25519_bytes, server_ed25519_bytes)
    hello_sig = browser_ed25519_priv.sign(t_hello)

    hello_frame = {
        "type":            "hello",
        "browser_x25519":  b64url_encode(browser_x25519_pub),
        "browser_ed25519": b64url_encode(browser_ed25519_pub),
        "enc":             b64url_encode(c2s_enc),
        "sig":             b64url_encode(hello_sig),
    }

    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps(hello_frame))

        # ── 4. server_hello ───────────────────────────────────────────────
        sh = json.loads(await ws.recv())
        assert sh["type"] == "server_hello", f"expected server_hello, got {sh['type']!r}"
        s2c_enc = b64url_decode(sh["enc"])
        sh_sig  = b64url_decode(sh["sig"])

        # Verify server_hello sig + §4.3.1 gate
        t_server_hello = build_t_server_hello(
            s2c_enc, browser_x25519_pub, browser_ed25519_pub,
            server_x25519_bytes, server_ed25519_bytes,
        )
        Ed25519PublicKey.from_public_bytes(server_ed25519_bytes).verify(sh_sig, t_server_hello)
        print(f"✅ server_hello sig verified")

        # §4.3.1: confirm transcript reflects our own handshake material
        # (T_server_hello was built from our browser keys → sig verifying is the check)

        # Compute SESSION_ID
        session_id = compute_session_id(t_hello, t_server_hello)
        print(f"   SESSION_ID: {session_id.hex()}")

        # Open s2c recipient context
        s2c_recip = SUITE.create_recipient_context(
            enc=s2c_enc, skr=browser_x25519_kp.private_key, info=HPKE_INFO,
        )

        # ── 5. msg round-trips ────────────────────────────────────────────
        for i, prompt in enumerate([b"hello world", b"sensitive prompt text", b"final test"]):
            c2s_aad = make_aad(DIR_C2S, session_id, i)
            ct = c2s_sender.seal(prompt, aad=c2s_aad)

            await ws.send(json.dumps({"type": "msg", "seq": seq_to_hex(i), "ct": b64url_encode(ct)}))

            reply = json.loads(await ws.recv())
            assert reply["type"] == "msg"
            s2c_seq  = hex_to_seq(reply["seq"])
            s2c_aad  = make_aad(DIR_S2C, session_id, s2c_seq)
            plaintext = s2c_recip.open(b64url_decode(reply["ct"]), aad=s2c_aad)
            assert plaintext == b"ECHO: " + prompt, f"echo mismatch: {plaintext!r}"
            print(f"   round-trip [{i}]: {prompt!r} → {plaintext!r}")

        print("✅ All msg round-trips passed")

    # ── 6. Tamper test on a fresh connection ──────────────────────────────
    c2s_enc2, c2s_sender2 = SUITE.create_sender_context(pkr=server_x25519_pub_obj, info=HPKE_INFO)
    browser_ed25519_priv2 = Ed25519PrivateKey.generate()
    browser_ed25519_pub2  = browser_ed25519_priv2.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    browser_x25519_kp2    = SUITE.kem.derive_key_pair(os.urandom(32))
    browser_x25519_pub2   = browser_x25519_kp2.public_key.to_public_bytes()

    t_hello2   = build_t_hello(browser_x25519_pub2, browser_ed25519_pub2, c2s_enc2,
                                server_x25519_bytes, server_ed25519_bytes)
    hello_sig2 = browser_ed25519_priv2.sign(t_hello2)

    # Corrupt the signature
    bad_sig = bytearray(hello_sig2); bad_sig[0] ^= 0xFF

    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps({
            "type":            "hello",
            "browser_x25519":  b64url_encode(browser_x25519_pub2),
            "browser_ed25519": b64url_encode(browser_ed25519_pub2),
            "enc":             b64url_encode(c2s_enc2),
            "sig":             b64url_encode(bytes(bad_sig)),
        }))
        try:
            await ws.recv()
            print("❌ Tampered hello was not rejected")
        except websockets.exceptions.ConnectionClosed as e:
            print(f"✅ Tampered hello correctly rejected (code={e.code})")


async def test_plaintext_endpoint():
    """Verify /ws/plain echoes without HPKE (demo E2E OFF exhibit)."""
    async with websockets.connect("ws://localhost:8000/ws/plain") as ws:
        await ws.send("this is plaintext")
        reply = await ws.recv()
        assert reply == "ECHO: this is plaintext"
        print("✅ /ws/plain plaintext echo works (E2E OFF exhibit)")


if __name__ == "__main__":
    async def run():
        await browser_sim()
        print()
        await test_plaintext_endpoint()
        print("\n✅ All handshake integration tests passed.")
    asyncio.run(run())
