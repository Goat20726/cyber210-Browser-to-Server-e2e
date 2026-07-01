# EchoVault - Protocol Specification

*HPKE suite:** `DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305`
(RFC 9180 HPKE, base mode).

This document is the single source of truth for byte layouts, encodings, and
key derivation so two independent implementations (browser + server); both were run 
end-to-end and a **Python-sealed message opens in Node with byte-identical derived identities**.

Architecture context (KB `threat-model.md`): L4 is "RFC 9180 HPKE using X25519,
HKDF-SHA-256, and ChaCha20-Poly1305"; the handshake "binds key material to a
signed transcript"; "monotonic sequence numbers [are] bound into AAD"; and
"direction and session context [are] bound into AAD."

---

## 0. EchoVault Static Values - Frozen via D011
The following are frozen decisions you must paste in verbatim.


| # | Item | Placeholder used here | Source |
|---|------|-----------------------|--------|
| 1 | Full 32-byte HKDF salt | `65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95` | D011 |
| 2 | X25519 `info` string | `"echovault-x25519-encryption"` | D011 |
| 3 | Ed25519 `info` string | `"echovault-ed25519-signing"` | D011 |
| 4 | Direction tokens | `"c2s"` / `"s2c"` | D013/handshake |

---

## 1. Suite identifier & fixed constants

| Role | Choice | RFC 9180 ID |
|------|--------|-------------|
| KEM  | DHKEM(X25519, HKDF-SHA256) | `0x0020` |
| KDF  | HKDF-SHA256                 | `0x0001` |
| AEAD | ChaCha20-Poly1305           | `0x0003` |
| Mode | `mode_base`                 | `0x00`   |

Derived lengths used throughout:

| Symbol | Meaning | Bytes |
|--------|---------|-------|
| `Nsecret` / scalar | X25519 private scalar | 32 |
| `Npk` | X25519 public key | 32 |
| `Nenc` | HPKE encapsulated key (`enc`) | 32 |
| `Nk` | ChaCha20-Poly1305 key | 32 |
| `Nn` | Base nonce / AEAD nonce | 12 |
| `Nt` | Poly1305 tag (appended to ciphertext) | 16 |
| — | Ed25519 public key | 32 |
| — | Ed25519 signature | 64 |

---

## 2. Identity derivation (D010 / D011)

One BIP-39 phrase deterministically produces **two unrelated key pairs**: an
X25519 encryption pair and an Ed25519 signing pair. Domain separation comes from
two distinct HKDF `info` strings.

### 2.1 Pipeline

```
BIP-39 mnemonic
   │  PBKDF2-HMAC-SHA512(password = NFKD(mnemonic),
   │                     salt = "mnemonic" ‖ passphrase,   passphrase = "" for demo
   │                     iterations = 2048, dkLen = 64)
   ▼
seed  (64 bytes)
   │  PRK = HKDF-Extract(salt = HKDF_SALT, IKM = seed)          ← HMAC-SHA256
   ▼
PRK   (32 bytes)
   ├─ HKDF-Expand(PRK, info = INFO_X25519,  L = 32) ─▶ x25519_scalar (32 bytes)
   └─ HKDF-Expand(PRK, info = INFO_ED25519, L = 32) ─▶ ed25519_seed  (32 bytes)
```

---

### 2.2 Frozen inputs

| Name | Value | Encoding |
|------|-------|----------|
| `HKDF_SALT` | `65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95` — **32 bytes**, see §0 item 1 | raw bytes (given as lowercase hex) |
| `INFO_X25519` | `"echovault-x25519-encryption""` — **confirm (§0)** | ASCII/UTF-8 bytes, verbatim, no base64 |
| `INFO_ED25519` | `"echovault-ed25519-signing"` — **confirm (§0)** | ASCII/UTF-8 bytes, verbatim, no base64 |

The `info` strings are the exact byte strings, used as-is. They are **never**
base64-encoded before going into HKDF-Expand.

### 2.3 X25519 conversion method — **RAW SCALAR** 

> The 32 bytes from `HKDF-Expand(PRK, INFO_X25519, 32)` **are** the X25519 private key, used directly.

- **DO** import those 32 bytes as the raw X25519 private scalar
  (`X25519PrivateKey.from_private_bytes(...)` / PKCS#8-wrapped raw key).
  X25519 performs its required bit-clamping internally at multiply time, so the
  raw HKDF output is exactly the private scalar.
- **DO NOT** derive X25519 by converting the Ed25519 key (no
  Ed25519→Montgomery birational map). The two keys come from two independent
  HKDF-Expand calls. (**D011**)

The Ed25519 key pair is built from `ed25519_seed` the normal way (`Ed25519PrivateKey.from_private_bytes(ed25519_seed)`).

---

## 3. AAD construction

The AAD ("additional authenticated data") is a fixed label that the AEAD
authenticates but does **not** encrypt. It binds every message to the app, the
direction, and its position in the stream.

### 3.1 Layout — fixed order, no separators

```
AAD = STATE  ‖  DIRECTION  ‖  SEQ8
        │          │          └── seq as 8-byte big-endian unsigned (uint64)
        │          └───────────── direction token, ASCII bytes (§0 item 4)
        └──────────────────────── the constant ASCII bytes "echovault"
```

| Segment | Value | Encoding | Length |
|---------|-------|----------|--------|
| `STATE` | `"echovault"` | ASCII bytes `65 63 68 6f 76 61 75 6c 74` | 9 |
| `DIRECTION` | `"c2s"` (browser→server) or `"s2c"` (server→browser) — **confirm (§0)** | ASCII bytes | 3 (as chosen) |
| `SEQ8` | message counter | 8-byte **big-endian** unsigned | 8 |

- **No separator bytes, no length prefixes.** Every segment is fixed-length, so
  the concatenation is unambiguous. Concatenation order is exactly
  `STATE → DIRECTION → SEQ8`.
- With the placeholder tokens the AAD is a fixed **20 bytes**.
- Example (`seq = 0`, browser→server): `65 63 68 6f 76 61 75 6c 74` ‖ `63 32 73` ‖ `00 00 00 00 00 00 00 00`.

### 3.2 The AAD is NEVER on the wire

The AAD is passed only as the `aad` argument to seal/open. It is **not** a JSON
field and appears in **no** frame. Both sides reconstruct it independently from
values they already hold (`STATE` is constant, `DIRECTION` is known per link,
`SEQ8` comes from the `msg.seq` field). If the receiver's rebuilt AAD differs by
one byte, `open()` fails — that is exactly how reflection/replay/direction-swap
are rejected (KB: "Reflected message should fail authentication").

---

## 4. Transcript layout (Ed25519-signed)

Signatures cover **raw bytes** in a fixed order. base64url appears **only** at
the JSON boundary (§6), never inside signed bytes. To verify: base64url-decode
each frame field back to raw, re-assemble the transcript in the order below, then
`Ed25519_Verify`.

All fields are raw, fixed-length, concatenated with **no separators**. Each
transcript begins with a distinct ASCII **domain-separation label** so a signature
for one message type can never be replayed as another.

### 4.1 `GET /pubkey` — signed by the **server** Ed25519 key

```
T_pubkey = "echovault/pubkey/v1"   (19 ASCII bytes)
         ‖ server_x25519           (32 raw)
         ‖ server_ed25519          (32 raw)                         total = 83 bytes
sig = Ed25519_Sign(server_ed25519_priv, T_pubkey)
```

| Order | Field | Encoding in transcript | Bytes |
|------:|-------|------------------------|------:|
| 1 | label `"echovault/pubkey/v1"` | ASCII | 19 |
| 2 | `server_x25519` (public) | raw | 32 |
| 3 | `server_ed25519` (public) | raw | 32 |

### 4.2 `hello` — signed by the **browser** Ed25519 key

Binds the browser's ephemeral material **to the specific server key it sealed to**
(anti key-substitution").

```
T_hello = "echovault/hello/v1"     (18 ASCII bytes)
        ‖ browser_x25519           (32 raw)
        ‖ browser_ed25519          (32 raw)
        ‖ enc                      (32 raw)   ← browser→server HPKE encapsulated key
        ‖ nonce                    (12 raw)   ← base nonce for the browser→server link
        ‖ server_x25519            (32 raw)   ← pins which server padlock was used
        ‖ server_ed25519           (32 raw)   ← pins the server identity
                                                              total = 190 bytes
sig = Ed25519_Sign(browser_ed25519_priv, T_hello)
```

### 4.3 `server_hello` — signed by the **server** Ed25519 key

Binds the server's reply material back to the browser's `hello` (both directions
are covered).

```
T_server_hello = "echovault/server_hello/v1"  (25 ASCII bytes)
               ‖ enc                (32 raw)   ← server→browser HPKE encapsulated key
               ‖ nonce              (12 raw)   ← base nonce for the server→browser link
               ‖ browser_x25519     (32 raw)   ← from hello
               ‖ browser_ed25519    (32 raw)   ← from hello
               ‖ server_x25519      (32 raw)
               ‖ server_ed25519     (32 raw)
                                                              total = 197 bytes
sig = Ed25519_Sign(server_ed25519_priv, T_server_hello)
```

**Rule:** every field inside a transcript is **raw** (never base64). Labels are
ASCII. The order above is normative.

---

## 5. Frame shapes (on the wire)

JSON objects. Every binary value is a string (base64url, no padding — §6). The
one exception is `seq`, which is hex. **There is no `iv` field in any frame,
anywhere in EchoVault.**

### 5.1 `GET /pubkey` → response

```json
{
  "server_x25519":  "…",   // base64url · 32-byte raw X25519 public key
  "server_ed25519": "…",   // base64url · 32-byte raw Ed25519 public key
  "sig":            "…"    // base64url · 64-byte Ed25519 signature over T_pubkey (§4.1)
}
```

### 5.2 `hello`  (browser → server)

```json
{
  "browser_x25519":  "…",  // base64url · 32-byte raw X25519 public key
  "browser_ed25519": "…",  // base64url · 32-byte raw Ed25519 public key
  "enc":             "…",  // base64url · 32-byte HPKE encapsulated key (browser→server)
  "nonce":           "…",  // base64url · 12-byte base nonce (NOT an iv — see §5.5)
  "sig":             "…"   // base64url · 64-byte Ed25519 signature over T_hello (§4.2)
}
```

### 5.3 `server_hello`  (server → browser)

```json
{
  "enc":   "…",            // base64url · 32-byte HPKE encapsulated key (server→browser)
  "nonce": "…",            // base64url · 12-byte base nonce (NOT an iv — see §5.5)
  "sig":   "…"            // base64url · 64-byte Ed25519 signature over T_server_hello (§4.3)
}
```

### 5.4 `msg`  (either direction, one per note)

```json
{
  "seq": "0000000000000007",  // HEX · 16 chars · 8-byte big-endian uint64 counter
  "ct":  "…"                 // base64url · ChaCha20-Poly1305 output = ciphertext ‖ 16-byte tag  **THIS IS THE LLM PROMPT**
}
```

- `ct` already includes the 16-byte Poly1305 tag appended at the end. There is
  **no** separate `tag` field and **no** `iv` field.
- `seq` is **hex**, not base64 — it is a human-readable counter and a uint64
  exceeds JavaScript's safe-integer range, so it must not be a JSON number.

### 5.5 No `iv` field — anywhere

**EchoVault has no `iv` field in any frame.** Per-message nonces are *derived*,
not transmitted as random IVs:

- The `nonce` in `hello`/`server_hello` is the HPKE-exported **base nonce** for
  that link (see §7), transmitted once and authenticated by the transcript
  signature. It is deterministic, not a random IV.
- The actual AEAD nonce for message `N` is `base_nonce XOR seq` (§7.2). It is
  never sent; the receiver recomputes it from `msg.seq`.

---

## 6. Encoding conventions (every binary field)

**Wire binary → base64url, no padding.** All binary blobs use RFC 4648 §5
base64url (`-` and `_`, never `+`/`/`) with trailing `=` padding **stripped**.
Decoders MUST accept and re-pad missing `=`. Standard base64 (`+`/`/`, padded)
MUST NOT appear on the wire.

| Field | Where | Encoding |
|-------|-------|----------|
| `server_x25519`, `browser_x25519` | pubkey, hello | base64url, no pad |
| `server_ed25519`, `browser_ed25519` | pubkey, hello | base64url, no pad |
| `enc` | hello, server_hello | base64url, no pad |
| `nonce` (base nonce) | hello, server_hello | base64url, no pad |
| `sig` | pubkey, hello, server_hello | base64url, no pad |
| `ct` (ciphertext ‖ tag) | msg | base64url, no pad |
| `seq` | msg | **lowercase hex**, 16 chars, zero-padded, big-endian |
| `HKDF_SALT` | config / this doc | lowercase hex |
| `INFO_X25519`, `INFO_ED25519` | key derivation | ASCII/UTF-8 bytes, verbatim (no base64) |
| `STATE` (`"echovault"`), `DIRECTION` | inside AAD | ASCII bytes, verbatim (no base64) |
| transcript labels (`"echovault/hello/v1"`, …) | inside signed bytes | ASCII bytes, verbatim |

Rationale for the split: base64url is JSON/URL/header-safe; dropping padding
removes the single most common cross-stack mismatch (one side pads, the other
rejects `=`). `seq` is hex because it is an eyeball-in-logs counter and a padded
base64 of 8 bytes buys nothing.

---

## 7. Per-message crypto (how a `msg` is built)

Each direction runs HPKE **once** to establish a link, then encrypts many `msg`
frames under a derived key with a counter-based nonce.

### 7.1 Link setup (once per direction)

```
sender:     enc, ctx_S = SetupBaseS(pkR, info = "echovault/hpke/v1")
recipient:  ctx_R      = SetupBaseR(enc, skR, info = "echovault/hpke/v1")

key        = ctx.Export("echovault chacha key", 32)   # 32-byte ChaCha20-Poly1305 key
base_nonce = ctx.Export("echovault base nonce", 12)   # the wire `nonce`
```

`info = "echovault/hpke/v1"` and both export labels are ASCII bytes (freeze these
as v1). Sender and recipient derive **identical** `key` and `base_nonce`.

### 7.2 Sealing / opening message `seq`

```
msg_nonce = base_nonce XOR I2OSP(seq, 12)      # seq as 12-byte big-endian, XORed in
aad       = STATE ‖ DIRECTION ‖ I2OSP(seq, 8)  # §3
ct        = ChaCha20Poly1305_Seal(key, msg_nonce, aad, plaintext)   # tag appended
wire      = { "seq": hex(I2OSP(seq, 8)), "ct": base64url(ct) }
```

`seq` is one logical uint64. It appears **12-byte** big-endian when XORed into the
nonce (HPKE convention; the top 4 bytes are zero) and **8-byte** big-endian inside
the AAD — same number, different fixed widths. `seq` starts at 0 and increments by
1 per message per direction. Because key + counter fix the nonce, the sender never
generates a random IV.

### 7.3 Replay / reordering

Binding `seq` into the AAD lets the receiver detect replays and reorders, but (KB
`threat-model.md`) protection is only complete if the **receiver tracks accepted
`seq` values per link** and rejects duplicates/rollbacks. Sequence tracking is a
receiver responsibility; 

---

## 8. What is and isn't protected (from `threat-model.md`)

- "End-to-end" here means **browser → intended echo-server process**. The echo
  server decrypts by design; this is not messaging-app E2E where only two humans
  can read.
- HPKE-inside-TLS reduces plaintext exposure at TLS-terminating intermediaries
  that are not the intended reader.
- Key pinning (the signed transcripts of §4) is a **demo trust assumption**: it
  only helps if the browser already holds the expected server identity via a
  trusted path. If the frontend JS that carries the pin is compromised, the
  attacker can swap both the key and the check.


## Plaintext Server End Points
/api/health
/api/status
/pubkey/v1

