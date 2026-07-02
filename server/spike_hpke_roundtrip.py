"""
WebServer role - Spike #1
Goal: round-trip a pyhpke seal/open in isolation (no networking yet).

This proves the crypto primitive works on our side before we wire it
into the WebSocket. Suite chosen: DHKEM-X25519-HKDF-SHA256 / HKDF-SHA256 /
AES-128-GCM -- this is RFC 9180's mandatory "base" suite and is also the
default lightweight build of hpke-js on the browser side, so it's the
most likely thing Fil's client will speak without extra config.

NOTE: this must be confirmed with Fil before W3 -- if hpke-js on his end
is configured with a different KEM/KDF/AEAD, seal() on one side and
open() on the other will simply fail (they're not friendly enough to
"degrade" -- it's a hard mismatch). Log the agreed suite in
docs/decisions.md once confirmed.
"""

import os
from pyhpke import CipherSuite, KEMId, KDFId, AEADId

SUITE = CipherSuite.new(
    kem_id=KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id=KDFId.HKDF_SHA256,
    aead_id=AEADId.AES128_GCM,
)


def roundtrip_demo():
    # --- "Server" side: generate a long-lived recipient keypair ---
    # In the real project this keypair is generated once when the server
    # boots, and the public key is handed to the browser somehow (W3 design
    # question -- see README) so the browser can encrypt *to* the server.
    # pyhpke has no "just generate a random keypair" call -- it implements
    # RFC 9180's DeriveKeyPair(ikm), so we feed it our own random seed
    # (32 random bytes is plenty of entropy for X25519).
    recipient_keypair = SUITE.kem.derive_key_pair(os.urandom(32))
    recipient_pub = recipient_keypair.public_key
    recipient_priv = recipient_keypair.private_key

    # --- "Browser" side (simulated here): seal a message to the server's pubkey ---
    plaintext = b"hello from a simulated browser client"
    aad = b"ws-msg"  # associated data -- bound to the ciphertext, not encrypted.
    # AAD use here: tags which logical channel/message-type this seal belongs
    # to, so a ciphertext can't be silently replayed into a different context.

    sender_enc, sender = SUITE.create_sender_context(pkr=recipient_pub)
    ciphertext = sender.seal(plaintext, aad=aad)
    enc = sender_enc  # the encapsulated key -- must travel WITH the ciphertext

    print(f"[sender]   plaintext : {plaintext!r}")
    print(f"[sender]   enc (KEM) : {enc.hex()[:32]}... ({len(enc)} bytes)")
    print(f"[sender]   ciphertext: {ciphertext.hex()[:32]}... ({len(ciphertext)} bytes)")

    # --- "Server" side: open it ---
    recipient = SUITE.create_recipient_context(enc=enc, skr=recipient_priv)
    opened = recipient.open(ciphertext, aad=aad)

    print(f"[recipient] opened    : {opened!r}")
    assert opened == plaintext, "Round trip FAILED -- opened plaintext doesn't match"
    print("\n✅ Round trip succeeded: seal() -> open() recovered the original message.")

    # --- Negative test: tampered ciphertext must fail to open ---
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0xFF
    try:
        SUITE.create_recipient_context(enc=enc, skr=recipient_priv).open(bytes(tampered), aad=aad)
        print("❌ Tampered ciphertext opened successfully -- THIS IS BAD, AEAD is broken")
    except Exception as e:
        print(f"✅ Tampered ciphertext correctly rejected ({type(e).__name__})")

    # --- Negative test: wrong AAD must fail to open ---
    try:
        SUITE.create_recipient_context(enc=enc, skr=recipient_priv).open(ciphertext, aad=b"wrong-aad")
        print("❌ Wrong AAD opened successfully -- THIS IS BAD")
    except Exception as e:
        print(f"✅ Mismatched AAD correctly rejected ({type(e).__name__})")


if __name__ == "__main__":
    roundtrip_demo()
