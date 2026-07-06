"""
hpke_server.py — HPKE + Ed25519 crypto core for EchoVault (protocol v1, frozen)

Protocol: docs/protocol.md
Suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305

Key decisions:
  D003 — ChaCha20-Poly1305
  D013 — frozen protocol constants (HPKE info, transcript labels, direction tokens)
  D014 — HPKE owns nonce/counter; no manual nonce handling
  D019 — seq gate: expected_next_seq tracked per direction; teardown on any fault
  D020 — TYPE byte (0x01) bound into AAD; strict state machine (§5.6)
"""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat, PrivateFormat, NoEncryption,
)
from pyhpke import CipherSuite, KEMId, KDFId, AEADId, KEMKeyPair

# ── Suite ─────────────────────────────────────────────────────────────────────

SUITE = CipherSuite.new(
    kem_id=KEMId.DHKEM_X25519_HKDF_SHA256,
    kdf_id=KDFId.HKDF_SHA256,
    aead_id=AEADId.CHACHA20_POLY1305,
)

# ── Frozen protocol constants (§0, §3, §4) ────────────────────────────────────

HPKE_INFO          = b"echovault/hpke/v1"           # §0 item 5, §7.1
STATE              = b"echovault"                    # §3.1
DIR_C2S            = b"c2s"                          # §0 item 4
DIR_S2C            = b"s2c"                          # §0 item 4
TYPE_MSG           = b"\x01"                         # §3.0.1

LABEL_PUBKEY       = b"echovault/pubkey/v1"          # §4.1 — 19 bytes
LABEL_HELLO        = b"echovault/hello/v1"           # §4.2 — 18 bytes
LABEL_SERVER_HELLO = b"echovault/server_hello/v1"    # §4.3 — 25 bytes


# ── Encoding helpers (§6) ─────────────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    """base64url, no padding (§6)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    """base64url decode; re-pad missing = (§6)."""
    s = str(s)
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.urlsafe_b64decode(s)


def seq_to_hex(seq: int) -> str:
    """8-byte big-endian uint64 → 16-char lowercase hex (§5.4)."""
    return f"{seq:016x}"


def hex_to_seq(hex_str: str) -> int:
    return int(hex_str, 16)


def seq_to_bytes(seq: int) -> bytes:
    """I2OSP(seq, 8) for AAD (§3.1)."""
    return seq.to_bytes(8, "big")


# ── Transcript builders (§4) ──────────────────────────────────────────────────

def build_t_pubkey(server_x25519: bytes, server_ed25519: bytes) -> bytes:
    """T_pubkey = label(19) + server_x25519(32) + server_ed25519(32) = 83 bytes (§4.1)."""
    return LABEL_PUBKEY + server_x25519 + server_ed25519


def build_t_hello(
    browser_x25519: bytes, browser_ed25519: bytes,
    enc: bytes,
    server_x25519: bytes, server_ed25519: bytes,
) -> bytes:
    """T_hello = label(18)+bx25519(32)+bed25519(32)+enc(32)+sx25519(32)+sed25519(32)=178 bytes (§4.2)."""
    return LABEL_HELLO + browser_x25519 + browser_ed25519 + enc + server_x25519 + server_ed25519


def build_t_server_hello(
    s2c_enc: bytes,
    browser_x25519: bytes, browser_ed25519: bytes,
    server_x25519: bytes, server_ed25519: bytes,
) -> bytes:
    """T_server_hello = label(25)+enc(32)+bx25519(32)+bed25519(32)+sx25519(32)+sed25519(32)=185 bytes (§4.3)."""
    return LABEL_SERVER_HELLO + s2c_enc + browser_x25519 + browser_ed25519 + server_x25519 + server_ed25519


def compute_session_id(t_hello: bytes, t_server_hello: bytes) -> bytes:
    """SESSION_ID = SHA-256(T_hello ‖ T_server_hello)[:16] (§3.0)."""
    return hashlib.sha256(t_hello + t_server_hello).digest()[:16]


# ── AAD construction (§3) ─────────────────────────────────────────────────────

def make_aad(direction: bytes, session_id: bytes, seq: int) -> bytes:
    """
    AAD = STATE(9) ‖ SESSION_ID(16) ‖ DIRECTION(3) ‖ TYPE(1) ‖ SEQ8(8) = 37 bytes (§3.1)
    Never transmitted — both sides reconstruct independently.
    """
    assert len(session_id) == 16, f"SESSION_ID must be 16 bytes, got {len(session_id)}"
    return STATE + session_id + direction + TYPE_MSG + seq_to_bytes(seq)


# ── Server key management ─────────────────────────────────────────────────────

@dataclass
class ServerKeys:
    """Both server keypairs — loaded once at process startup."""
    x25519_kp:          KEMKeyPair
    ed25519_priv:       Ed25519PrivateKey
    x25519_pub_bytes:   bytes   # 32 raw bytes
    ed25519_pub_bytes:  bytes   # 32 raw bytes


def generate_server_keys() -> dict:
    """
    Generate fresh server keypairs (X25519 + Ed25519).
    Call only from generate_keys.py; never at server startup.
    """
    x25519_kp    = SUITE.kem.derive_key_pair(os.urandom(32))
    ed25519_priv = Ed25519PrivateKey.generate()

    x25519_priv_hex  = x25519_kp.private_key.to_private_bytes().hex()
    ed25519_seed     = ed25519_priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ed25519_seed_hex = ed25519_seed.hex()
    x25519_pub_hex   = x25519_kp.public_key.to_public_bytes().hex()
    ed25519_pub_hex  = ed25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    return {
        "SERVER_X25519_PRIVATE_KEY_HEX":  x25519_priv_hex,
        "SERVER_ED25519_PRIVATE_KEY_HEX": ed25519_seed_hex,
        "x25519_pub_hex":  x25519_pub_hex,
        "ed25519_pub_hex": ed25519_pub_hex,
    }


def load_server_keys() -> ServerKeys:
    """
    Load both server keypairs from env vars. Raises clearly if missing.
      SERVER_X25519_PRIVATE_KEY_HEX  — 64 hex chars
      SERVER_ED25519_PRIVATE_KEY_HEX — 64 hex chars (Ed25519 seed)
    """
    x25519_hex  = os.environ.get("SERVER_X25519_PRIVATE_KEY_HEX",  "").strip().strip('"').strip("'")
    ed25519_hex = os.environ.get("SERVER_ED25519_PRIVATE_KEY_HEX", "").strip().strip('"').strip("'")

    if not x25519_hex:
        raise RuntimeError("SERVER_X25519_PRIVATE_KEY_HEX not set. Run generate_keys.py.")
    if not ed25519_hex:
        raise RuntimeError("SERVER_ED25519_PRIVATE_KEY_HEX not set. Run generate_keys.py.")

    # X25519
    x25519_priv      = SUITE.kem.deserialize_private_key(bytes.fromhex(x25519_hex))
    x25519_pub_bytes = x25519_priv.raw.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    x25519_pub       = SUITE.kem.deserialize_public_key(x25519_pub_bytes)
    x25519_kp        = KEMKeyPair(sk=x25519_priv, pk=x25519_pub)

    # Ed25519
    ed25519_priv      = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(ed25519_hex))
    ed25519_pub_bytes = ed25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    return ServerKeys(
        x25519_kp=x25519_kp,
        ed25519_priv=ed25519_priv,
        x25519_pub_bytes=x25519_pub_bytes,
        ed25519_pub_bytes=ed25519_pub_bytes,
    )


# ── Per-connection state machine (§5.6) ───────────────────────────────────────

class ProtocolError(Exception):
    """Any protocol violation — caller MUST tear down the connection."""


@dataclass
class ServerSession:
    """
    Per-WebSocket state machine.
      AWAIT_HELLO  → accepts only hello
      ESTABLISHED  → accepts only msg
    Any wrong frame type or auth/ordering fault → raises ProtocolError.
    Never reuse across connections.
    """
    keys: ServerKeys
    phase: str = "AWAIT_HELLO"

    _recipient_ctx_c2s: object = field(default=None, repr=False)
    _sender_ctx_s2c:    object = field(default=None, repr=False)
    _session_id:        bytes  = field(default=None, repr=False)
    _expected_c2s:      int    = 0
    _expected_s2c:      int    = 0

    def handle_hello(self, frame: dict) -> dict:
        """
        Process hello frame (§5.2).
        1. Verify browser Ed25519 sig over T_hello.
        2. Confirm T_hello binds to our server identity (§4.3 server gate).
        3. Set up both HPKE contexts.
        4. Sign and return server_hello frame dict (§5.3).
        Raises ProtocolError on any failure.
        """
        if self.phase != "AWAIT_HELLO":
            raise ProtocolError(f"hello received in wrong phase: {self.phase}")

        try:
            browser_x25519  = b64url_decode(frame["browser_x25519"])
            browser_ed25519 = b64url_decode(frame["browser_ed25519"])
            c2s_enc         = b64url_decode(frame["enc"])
            sig             = b64url_decode(frame["sig"])
        except (KeyError, Exception) as e:
            raise ProtocolError(f"malformed hello frame: {e}") from e

        # Reconstruct T_hello using OUR server keys (§4.3 server gate)
        t_hello = build_t_hello(
            browser_x25519, browser_ed25519, c2s_enc,
            self.keys.x25519_pub_bytes, self.keys.ed25519_pub_bytes,
        )

        # Verify browser signature — also implicitly confirms browser sealed to us
        try:
            Ed25519PublicKey.from_public_bytes(browser_ed25519).verify(sig, t_hello)
        except Exception as e:
            raise ProtocolError(f"hello sig verification failed: {e}") from e

        # Set up c2s recipient context (browser→server)
        self._recipient_ctx_c2s = SUITE.create_recipient_context(
            enc=c2s_enc, skr=self.keys.x25519_kp.private_key, info=HPKE_INFO,
        )

        # Set up s2c sender context (server→browser)
        s2c_enc, self._sender_ctx_s2c = SUITE.create_sender_context(
            pkr=SUITE.kem.deserialize_public_key(browser_x25519), info=HPKE_INFO,
        )

        # Build and sign T_server_hello
        t_server_hello = build_t_server_hello(
            s2c_enc, browser_x25519, browser_ed25519,
            self.keys.x25519_pub_bytes, self.keys.ed25519_pub_bytes,
        )
        sh_sig = self.keys.ed25519_priv.sign(t_server_hello)

        # Compute SESSION_ID — both transcripts now known
        self._session_id = compute_session_id(t_hello, t_server_hello)
        self.phase = "ESTABLISHED"

        return {
            "type": "server_hello",
            "enc":  b64url_encode(s2c_enc),
            "sig":  b64url_encode(sh_sig),
        }

    def handle_msg(self, frame: dict) -> bytes:
        """
        Open incoming msg (§5.4, §7.2).
        seq gate enforced before open() — D019/§7.3.
        Raises ProtocolError on any fault; caller MUST tear down.
        """
        if self.phase != "ESTABLISHED":
            raise ProtocolError(f"msg received in wrong phase: {self.phase}")

        try:
            seq = hex_to_seq(frame["seq"])
            ct  = b64url_decode(frame["ct"])
        except Exception as e:
            raise ProtocolError(f"malformed msg frame: {e}") from e

        # seq gate (D019): reject duplicate/rollback/gap
        if seq != self._expected_c2s:
            raise ProtocolError(
                f"seq gate: expected {self._expected_c2s:#018x}, got {seq:#018x}"
            )

        aad       = make_aad(DIR_C2S, self._session_id, seq)
        plaintext = self._recipient_ctx_c2s.open(ct, aad=aad)
        self._expected_c2s += 1
        return plaintext

    def seal_reply(self, plaintext: bytes) -> dict:
        """Seal a server→browser reply (§5.4, §7.2). Returns ready-to-send frame dict."""
        if self.phase != "ESTABLISHED":
            raise ProtocolError("seal_reply called outside ESTABLISHED phase")

        seq = self._expected_s2c
        aad = make_aad(DIR_S2C, self._session_id, seq)
        ct  = self._sender_ctx_s2c.seal(plaintext, aad=aad)
        self._expected_s2c += 1

        return {
            "type": "msg",
            "seq":  seq_to_hex(seq),
            "ct":   b64url_encode(ct),
        }
