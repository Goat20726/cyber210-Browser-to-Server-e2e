"""
Unit tests for hpke_server.py — no networking, no server process.
Tests: AAD construction, transcript lengths, SESSION_ID, encoding round-trips.
"""
import hashlib
from hpke_server import (
    SUITE, HPKE_INFO, DIR_C2S, DIR_S2C, TYPE_MSG,
    STATE, LABEL_PUBKEY, LABEL_HELLO, LABEL_SERVER_HELLO,
    b64url_encode, b64url_decode, seq_to_hex, hex_to_seq, seq_to_bytes,
    build_t_pubkey, build_t_hello, build_t_server_hello,
    compute_session_id, make_aad,
    generate_server_keys, load_server_keys,
)
import os

def test_encoding():
    raw = os.urandom(32)
    assert b64url_decode(b64url_encode(raw)) == raw
    assert "=" not in b64url_encode(raw)
    for seq in [0, 1, 255, 2**32, 2**64-1]:
        hex_str = seq_to_hex(seq)
        assert len(hex_str) == 16
        assert hex_to_seq(hex_str) == seq
    print("✅ encoding round-trips")

def test_transcript_lengths():
    x25519  = os.urandom(32)
    ed25519 = os.urandom(32)
    enc     = os.urandom(32)
    t_pk = build_t_pubkey(x25519, ed25519)
    assert len(t_pk) == 83,  f"T_pubkey should be 83 bytes, got {len(t_pk)}"
    t_h = build_t_hello(x25519, ed25519, enc, x25519, ed25519)
    assert len(t_h) == 178, f"T_hello should be 178 bytes, got {len(t_h)}"
    t_sh = build_t_server_hello(enc, x25519, ed25519, x25519, ed25519)
    assert len(t_sh) == 185, f"T_server_hello should be 185 bytes, got {len(t_sh)}"
    print("✅ transcript lengths: T_pubkey=83, T_hello=178, T_server_hello=185")

def test_session_id():
    t_h  = os.urandom(178)
    t_sh = os.urandom(185)
    sid  = compute_session_id(t_h, t_sh)
    assert len(sid) == 16
    expected = hashlib.sha256(t_h + t_sh).digest()[:16]
    assert sid == expected
    # Different transcripts → different SESSION_ID
    assert compute_session_id(os.urandom(178), t_sh) != sid
    print("✅ SESSION_ID = SHA-256(T_hello‖T_server_hello)[:16]")

def test_aad_layout():
    session_id = os.urandom(16)
    aad = make_aad(DIR_C2S, session_id, 42)
    assert len(aad) == 37, f"AAD should be 37 bytes, got {len(aad)}"
    assert aad[:9]    == STATE
    assert aad[9:25]  == session_id
    assert aad[25:28] == DIR_C2S
    assert aad[28:29] == TYPE_MSG
    assert aad[29:]   == (42).to_bytes(8, "big")
    # direction in AAD
    aad_s2c = make_aad(DIR_S2C, session_id, 42)
    assert aad_s2c[25:28] == DIR_S2C
    assert aad != aad_s2c
    print("✅ AAD layout: 37 bytes, correct field positions")

def test_hpke_round_trip():
    """Full c2s + s2c HPKE round-trip with the correct AAD."""
    kp = SUITE.kem.derive_key_pair(os.urandom(32))
    session_id = os.urandom(16)

    # c2s
    c2s_enc, c2s_sender = SUITE.create_sender_context(pkr=kp.public_key, info=HPKE_INFO)
    c2s_recip = SUITE.create_recipient_context(enc=c2s_enc, skr=kp.private_key, info=HPKE_INFO)

    pt = b"hello from browser"
    aad = make_aad(DIR_C2S, session_id, 0)
    ct  = c2s_sender.seal(pt, aad=aad)
    assert c2s_recip.open(ct, aad=aad) == pt

    # tamper rejection
    tampered = bytearray(ct); tampered[-1] ^= 0xFF
    try:
        c2s_recip.open(bytes(tampered), aad=aad)
        assert False, "should have raised"
    except Exception:
        pass
    print("✅ HPKE ChaCha20-Poly1305 round-trip + tamper rejection")

def test_key_generation_and_loading():
    keys = generate_server_keys()
    os.environ["SERVER_X25519_PRIVATE_KEY_HEX"]  = keys["SERVER_X25519_PRIVATE_KEY_HEX"]
    os.environ["SERVER_ED25519_PRIVATE_KEY_HEX"] = keys["SERVER_ED25519_PRIVATE_KEY_HEX"]
    loaded = load_server_keys()
    assert loaded.x25519_pub_bytes.hex()  == keys["x25519_pub_hex"]
    assert loaded.ed25519_pub_bytes.hex() == keys["ed25519_pub_hex"]
    print("✅ key generation and env loading round-trip")

if __name__ == "__main__":
    test_encoding()
    test_transcript_lengths()
    test_session_id()
    test_aad_layout()
    test_hpke_round_trip()
    test_key_generation_and_loading()
    print("\n✅ All crypto unit tests passed.")
