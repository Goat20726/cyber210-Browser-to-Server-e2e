"""
hpke_server.py — HPKE crypto core for EchoVault echo server (W3)

Why two one-directional contexts instead of one shared context:
  HPKE base mode gives ONE asymmetric encapsulation. Reusing one context
  for both directions risks nonce reuse under AES-GCM (catastrophic: can
  leak the key). Two separate contexts let pyhpke manage nonce sequencing
  internally with zero custom nonce code; the direction binding in both
  `info` (key schedule) and `aad` (per-message) defeats reflection attacks
  where a captured c2s frame is replayed as a server reply.

AAD design (matches protocol.md: "echovault/v3" + direction + seq 8B BE):
  Every seal/open call binds the protocol version, direction, AND the
  application-layer seq number from the JSON frame. This means a ciphertext
  is bound to its exact position in the stream — replaying it at a different
  seq fails the AAD check before HPKE's internal counter even gets a chance
  to reject it. Belt-and-suspenders: two independent replay guards.

Suite: DHKEM-X25519-HKDF-SHA256 / HKDF-SHA256 / ChaCha20-Poly1305
  Per D003: ChaCha20-Poly1305 chosen over AES-128-GCM for software
  performance and broad support without requiring hardware acceleration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pyhpke import CipherSuite, KEMId, KDFId, AEADId, KEMKeyPair
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SUITE = CipherSuite.new(
    kem_id=KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id=KDFId.HKDF_SHA256,
    aead_id=AEADId.CHACHA20_POLY1305,
)

# Protocol identifier bound into the HPKE key schedule via `info`.
# Direction is kept out of info (it goes into aad instead) so both
# contexts can share the same protocol label without ambiguity.
PROTO_INFO = b"echovault/v3"

# Direction tags for aad construction.
C2S = b"c2s"
S2C = b"s2c"


def make_aad(direction: str, seq: int) -> bytes:
    """
    Build the per-message AAD: protocol label + direction + seq (8-byte BE).
    Matches the protocol.md spec: aad = "echovault/v3" + "c2s"|"s2c" + seq(8B BE).
    Binding seq into the AAD means the ciphertext is tied to its exact
    position in the stream -- replaying it at a different seq number fails
    even before HPKE's internal counter rejects it.
    """
    direction_bytes = C2S if direction == "c2s" else S2C
    return PROTO_INFO + direction_bytes + seq.to_bytes(8, "big")


def generate_server_keypair() -> KEMKeyPair:
    """Fresh random keypair -- used ONLY by generate_keys.py (one-time setup).
    Running server loads from env via load_server_keypair_from_env()."""
    return SUITE.kem.derive_key_pair(os.urandom(32))


def private_key_to_hex(keypair: KEMKeyPair) -> str:
    return keypair.private_key.to_private_bytes().hex()


def pubkey_to_hex(keypair: KEMKeyPair) -> str:
    return keypair.public_key.to_public_bytes().hex()


def hex_to_pubkey(hex_str: str):
    return SUITE.kem.deserialize_public_key(bytes.fromhex(hex_str))


def load_server_keypair_from_env(env_var: str = "SERVER_HPKE_PRIVATE_KEY_HEX") -> KEMKeyPair:
    """
    Load the server's persistent HPKE keypair from an env var (hex private key).
    Public key is derived mathematically -- no need to store it separately.
    Raises clearly if the var is missing; no silent random-keypair fallback.
    """
    priv_hex = os.environ.get(env_var)
    if not priv_hex:
        raise RuntimeError(
            f"{env_var} is not set. Run `python3 generate_keys.py` once, "
            f"put the output in .env (see .env.example), and load it before "
            f"starting the server."
        )
    private_key = SUITE.kem.deserialize_private_key(bytes.fromhex(priv_hex))
    raw_pub = private_key.raw.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    public_key = SUITE.kem.deserialize_public_key(raw_pub)
    return KEMKeyPair(sk=private_key, pk=public_key)


@dataclass
class SecureChannel:
    """
    Per-connection HPKE state. One instance per WebSocket connection --
    never reuse across connections.
    """
    server_keypair: KEMKeyPair
    recipient_ctx_c2s = None
    sender_ctx_s2c = None
    _pending_s2c_enc = None

    def handle_init(self, enc_hex: str, client_pub_hex: str,
                    text_hex: str, aad: bytes) -> bytes:
        """
        Process the client's init frame:
          1. Open the first ciphertext (text field, hex) using the client's
             KEM encapsulation (enc field) and our static private key.
          2. Set up the s2c sender context against the client's ephemeral
             pubkey so we can seal replies for the rest of the session.
        text_hex: the 'text' field from the JSON frame (ciphertext hex).
        aad: make_aad("c2s", seq) -- caller computes this so the seq is bound.
        """
        enc = bytes.fromhex(enc_hex)
        ct = bytes.fromhex(text_hex)
        client_pub = hex_to_pubkey(client_pub_hex)

        self.recipient_ctx_c2s = SUITE.create_recipient_context(
            enc=enc, skr=self.server_keypair.private_key, info=PROTO_INFO
        )
        plaintext = self.recipient_ctx_c2s.open(ct, aad=aad)

        s2c_enc, self.sender_ctx_s2c = SUITE.create_sender_context(
            pkr=client_pub, info=PROTO_INFO
        )
        self._pending_s2c_enc = s2c_enc
        return plaintext

    def handle_msg(self, text_hex: str, aad: bytes) -> bytes:
        """Open a post-handshake c2s message. text_hex is the 'text' JSON field."""
        if self.recipient_ctx_c2s is None:
            raise RuntimeError("handle_init must be called before handle_msg")
        return self.recipient_ctx_c2s.open(bytes.fromhex(text_hex), aad=aad)

    def seal_reply(self, plaintext: bytes, aad: bytes) -> bytes:
        """Seal an s2c reply. Returns raw ciphertext bytes (caller hex-encodes)."""
        if self.sender_ctx_s2c is None:
            raise RuntimeError("handle_init must be called before seal_reply")
        return self.sender_ctx_s2c.seal(plaintext, aad=aad)

    def pop_pending_s2c_enc(self) -> bytes:
        """Returns the s2c KEM encapsulation -- sent once in init_ack, then gone."""
        enc = self._pending_s2c_enc
        self._pending_s2c_enc = None
        return enc
