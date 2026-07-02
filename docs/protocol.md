# EchoVault - Protocol Specification

*HPKE suite:* `DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20-Poly1305`
(RFC 9180 HPKE, base mode).

This document is the single source of truth for byte layouts, encoding, and
key derivation for two independent implementations (browser + server); designed so 
that a Node-sealed message opens in python and vice versa.

Architecture context (KB `threat-model.md`): L4 is "RFC 9180 HPKE using X25519,
HKDF-SHA-256, and ChaCha20-Poly1305"; the handshake "binds key material to a
signed transcript"; "monotonic sequence numbers [are] bound into AAD"; and
"direction [is] bound into AAD", with **session context bound via a per-session
`SESSION_ID` derived from the handshake transcripts (§3.0)** so a sealed message
cannot be reflected into a different session.

---

## 0. EchoVault Static Values - Frozen via D011
The following are frozen decisions you must paste in verbatim.


| # | Item | Placeholder used here | Source |
|---|------|-----------------------|--------|
| 1 | Full 32-byte HKDF salt | `65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95` | D011 |
| 2 | X25519 `info` string | `"echovault-x25519-encryption"` | D011 |
| 3 | Ed25519 `info` string | `"echovault-ed25519-signing"` | D011 |
| 4 | Direction tokens | `"c2s"` / `"s2c"` | D013/handshake |
| 5 | HPKE Info | `info = "echovault/hpke/v1"` | D013 |
| 6 | Transcript layout pubkey | `"echovault/pubkey/v1"` | D013 |
| 7 | Transcript layout hello | `"echovault/hello/v1"` | D013 |
| 8 | Transcript layout server_hello | `"echovault/server_hello/v1"` | D013 |
| 9 | `SESSION_ID` derivation | `SHA-256(T_hello ‖ T_server_hello)[:16]` — 16 bytes (§3.0) | D013 |

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
| — | `SESSION_ID` (SHA-256 truncated) | 16 |

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
> **D010 note (standard params + demo limitation).** These PBKDF2 parameters
> (HMAC-SHA512, 2048 iterations, salt `"mnemonic"‖passphrase`) are the *unmodified*
> BIP-39 standard, chosen so the same 24 words reproduce the same seed on any
> compliant implementation — not customized. The low 2048-iteration count is safe
> only because the security lives in the ~256-bit mnemonic entropy, not in a weak
> password. `passphrase = ""` drops BIP-39's optional 25th-word second factor, so the
> 24 words are the sole secret: this is a **demo simplification, not a production
> recommendation** (production should take a user passphrase).

---

### 2.2 Frozen inputs

| Name | Value | Encoding |
|------|-------|----------|
| `HKDF_SALT` | `65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95` — **32 bytes**, see §0 item 1 | raw bytes (given as lowercase hex) |
| `INFO_X25519` | `"echovault-x25519-encryption"` (frozen, §0 item 2) | ASCII/UTF-8 bytes, verbatim, no base64 |
| `INFO_ED25519` | `"echovault-ed25519-signing"` (frozen, §0 item 3) | ASCII/UTF-8 bytes, verbatim, no base64 |
| HPKE `info` | `"echovault/hpke/v1"` (frozen, §0 item 5) | ASCII/UTF-8 bytes, verbatim, no base64 |


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

> **D012 interop gate (do not skip).** Raw-scalar vs. clamped handling and public-key
> encoding can diverge across libraries. Treat this section as unverified until a small
> **JS↔Python interop test confirms both sides derive byte-identical
> `browser_x25519` / `server_x25519` (and matching shared secrets) from the same
> mnemonic.** The demo depends on this being byte-for-byte identical between hpke-js and
> pyhpke; verify it before wiring the live handshake.

The Ed25519 key pair is built from `ed25519_seed` the normal way (`Ed25519PrivateKey.from_private_bytes(ed25519_seed)`).

---

## 3. AAD construction

The AAD ("additional authenticated data") is a fixed label that the AEAD
authenticates but does **not** encrypt. It binds every message to the app, the
**session**, the direction, and its position in the stream.

### 3.0 Session identifier (`SESSION_ID`) — NEW (Step-1 F2 fix)

`SESSION_ID` binds every sealed message to the *specific handshake instance* that
established the keys, so a ciphertext captured in one session cannot be replayed
("reflected") into a different session even if the app label, direction, and `seq`
happen to line up.

```
SESSION_ID = SHA-256( T_hello ‖ T_server_hello )   [first 16 bytes]
```

- `T_hello` (178 raw bytes, §4.2) and `T_server_hello` (185 raw bytes, §4.3) are the
  exact signed transcripts both parties already hold **after** the handshake
  completes. Concatenate raw bytes in that order, SHA-256, and take the **first 16
  bytes**.
- Because both transcripts contain both `enc` values and both parties' static keys,
  `SESSION_ID` is a 128-bit fingerprint of the whole handshake. Two different
  sessions (different ephemerals) produce different `SESSION_ID`s with overwhelming
  probability.
- `SESSION_ID` is **derived, never transmitted.** Both sides recompute it locally,
  exactly like the rest of the AAD (§3.2). It MUST be identical byte-for-byte across
  the JS and Python sides — add it to the D012 interop test.
- It is fixed for the lifetime of a link and identical for both directions of that
  link. On epoch/link rotation (§7.3) a fresh handshake yields a fresh `SESSION_ID`.

### 3.1 Layout — fixed order, no separators

```
AAD = STATE ‖ SESSION_ID ‖ DIRECTION ‖ SEQ8
        │         │            │          └── seq as 8-byte big-endian unsigned (uint64)
        │         │            └───────────── direction token, ASCII bytes (§0 item 4)
        │         └────────────────────────── SHA-256(T_hello ‖ T_server_hello)[:16] (§3.0)
        └──────────────────────────────────── the constant ASCII bytes "echovault"
```

| Segment | Value | Encoding | Length |
|---------|-------|----------|--------|
| `STATE` | `"echovault"` | ASCII bytes `65 63 68 6F 76 61 75 6C 74` | 9 |
| `SESSION_ID` | `SHA-256(T_hello ‖ T_server_hello)[:16]` (§3.0) | raw bytes | 16 |
| `DIRECTION` | `"c2s"` (browser→server) or `"s2c"` (server→browser) | ASCII bytes | 3 |
| `SEQ8` | message counter | 8-byte **big-endian** unsigned | 8 |

- **No separator bytes, no length prefixes.** Every segment is fixed-length, so
  the concatenation is unambiguous. Concatenation order is exactly
  `STATE → SESSION_ID → DIRECTION → SEQ8`.
- With the placeholder tokens the AAD is a fixed **36 bytes** (9 + 16 + 3 + 8).
- Example (`seq = 0`, browser→server), with `SESSION_ID` shown as `SS…SS`:
  `65 63 68 6f 76 61 75 6c 74` ‖ `SS…SS (16 bytes)` ‖ `63 32 73` ‖ `00 00 00 00 00 00 00 00`.

### 3.2 The AAD is NEVER on the wire

The AAD is passed only as the `aad` argument to seal/open. It is **not** a JSON
field and appears in **no** frame. Both sides reconstruct it independently from
values they already hold (`STATE` is constant, `SESSION_ID` is computed from the
handshake transcripts (§3.0), `DIRECTION` is known per link, `SEQ8` comes from the
`msg.seq` field). If the receiver rebuilds AAD with a different session, direction,
or sequence value, `open()` fails — this rejects cross-session reflection,
direction-swap, and reflection mistakes, and supports replay/reorder detection.

**Replay protection is partial by default (F3 clarification).** An exact replay of an
*already-consumed* frame fails to `open()` because the stateful HPKE context has
already advanced past that message — but this is a **fail-closed side effect that
also desynchronizes the stream, not a clean replay check**. Complete replay/reorder
handling requires the receiver to track the expected next `seq` per direction and
reject duplicates/rollbacks *before* calling `open()` (§7.3). Until that tracking is
implemented, document replay protection as **partial** (see `threat-model.md`,
"Replay and Sequence Number Limits").
---

## 4. Transcript layout (Ed25519-signed)

Signatures cover **raw bytes** in a fixed order. base64url appears **only** at
the JSON boundary (§6), never inside signed bytes. To verify: base64url-decode
each frame field back to raw, re-assemble the transcript in the order below, then
`Ed25519_Verify`.

All fields are raw, fixed-length, concatenated with **no separators**. Each
transcript begins with a distinct ASCII **domain-separation label** so a signature
for one message type can never be replayed as another.

> **⚠️ Signature verification is necessary but NOT sufficient (Step-2 S1/S2).**
> A valid Ed25519 signature only proves *the holder of some signing key* produced the
> transcript — it does **not** prove that key is the one you expect, nor that the
> *contents* of the transcript are the values you sent. Every transcript check in this
> section therefore has **two** obligatory parts: (1) verify the signature, and
> (2) **compare the fields inside the transcript, byte-for-byte, against the values the
> verifier already holds** (its pin, and its own handshake material). Verifying the
> signature alone is a conformance failure and reopens key substitution — see the
> mandatory gates in §4.1 (S2) and §4.3 (S1).

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


> **Note (F11 clarification).** The handshake authenticates the **server to the
> browser**: the browser verifies this signature against the **pinned** server
> Ed25519 key. The browser's `hello` signature (§4.2) is **trust-on-first-use** — it
> binds the browser's own view of the exchange but is not checked against any
> pre-shared browser identity, consistent with the threat model (browser identity is
> not a protected asset).

#### 4.1.1 Mandatory `/pubkey` acceptance rule — the pin is the ONLY root of trust (S2)

`server_ed25519` is a **pin the browser already holds via a trusted out-of-band path**
(hardcoded pin / local config; `threat-model.md` assumptions). The value served on the
wire is **untrusted input** and exists only so the browser can confirm it matches the
pin. The browser MUST, on receiving the `/pubkey` response, in order:

1. **Compare to pin first.** Assert `response.server_ed25519 == PINNED_server_ed25519`
   (byte-for-byte). If it differs, **abort** — do not proceed, do not "learn" the key.
2. `Ed25519_Verify(response.sig, T_pubkey)` using the **pinned** `server_ed25519`
   (equivalently the just-confirmed wire value; they are now identical).
3. Adopt `response.server_x25519` as the server HPKE recipient key **only** because it
   is bound, by this verified signature, to the pinned identity.

- **The server identity MUST NEVER be learned from the wire.** Trust-on-first-use from
  `/pubkey` is a **conformance violation**: an active proxy present at first contact
  would substitute both the key and the identity, and every downstream check (including
  §4.3) would then validate against the attacker's key. There is no first-use exception.
- If no pin is provisioned, the client MUST refuse to run the E2E handshake (fail
  closed) rather than pin-on-first-use.


### 4.2 `hello` — signed by the **browser** Ed25519 key

Binds the browser's ephemeral material **to the specific server key it sealed to**
(anti key-substitution").

```
T_hello = "echovault/hello/v1"     (18 ASCII bytes)
        ‖ browser_x25519           (32 raw)
        ‖ browser_ed25519          (32 raw)
        ‖ enc                      (32 raw)   ← browser→server HPKE encapsulated key
        ‖ server_x25519            (32 raw)   ← pins which server padlock was used
        ‖ server_ed25519           (32 raw)   ← pins the server identity
                                                              total = 178 bytes
sig = Ed25519_Sign(browser_ed25519_priv, T_hello)
```

- The browser MUST place, in `server_x25519` / `server_ed25519`, exactly the
  **pin-confirmed** server keys from §4.1.1 (not whatever a proxy might have injected).
  This is what lets the server's counter-signature in §4.3 be cross-checked back to the
  browser's own view.

### 4.3 `server_hello` — signed by the **server** Ed25519 key

Binds the server's reply material back to the browser's `hello` (both directions
are covered).

```
T_server_hello = "echovault/server_hello/v1"  (25 ASCII bytes)
               ‖ enc                (32 raw)   ← server→browser HPKE encapsulated key
               ‖ browser_x25519     (32 raw)   ← from hello
               ‖ browser_ed25519    (32 raw)   ← from hello
               ‖ server_x25519      (32 raw)
               ‖ server_ed25519     (32 raw)
                                                              total = 185 bytes
sig = Ed25519_Sign(server_ed25519_priv, T_server_hello)
```
#### 4.3.1 Mandatory `server_hello` acceptance gate — closes reply-direction key substitution (S1)

**Motivation (do not remove).** The browser→server (c2s) direction seals to the server's
static key using the browser's *ephemeral* `enc`, so it does **not** depend on
`browser_x25519`. The server→browser (s2c) direction seals the **echo reply — which
carries the prompt back and is a declared protected asset** — to `browser_x25519`, and
the server holds **no pin for the browser**. An active TLS-terminating proxy can
therefore rewrite the `hello` in flight, keeping the real `enc` but substituting its own
`browser_x25519` and re-signing with its own Ed25519 key (the server cannot tell — it
has no browser pin). Result: c2s still delivers the real prompt to the server, but the
server seals the **reply to the proxy's key**, and the proxy decrypts the prompt. A
signature-only check does **not** catch this, because the real, pinned server validly
signs a `server_hello` containing the proxy's `browser_x25519`. The only defense is for
the browser to confirm the transcript reflects **its own** handshake material.

Because the message order is `hello → server_hello → msg…`, the browser receives
`server_hello` **before it seals any prompt**, so this gate aborts the session *before*
any plaintext is exposed.

The browser MUST, on receiving `server_hello`, perform **all** of the following in order,
**before opening the HPKE context or sealing/opening any `msg`**:

1. `Ed25519_Verify(server_hello.sig, T_server_hello)` using the **pinned**
   `server_ed25519` (§4.1.1). Reject on failure.
2. Assert `T_server_hello.server_x25519 == PINNED_server_x25519` **and**
   `T_server_hello.server_ed25519 == PINNED_server_ed25519` (the pin-confirmed server
   identity). Reject on any mismatch.
3. Assert `T_server_hello.browser_x25519 == my browser_x25519` **and**
   `T_server_hello.browser_ed25519 == my browser_ed25519` — byte-for-byte equal to the
   values the browser put in its own `hello` (§4.2). **This is the check that defeats S1.**
   Reject on any mismatch.
4. Only if steps 1–3 all pass: compute `SESSION_ID` (§3.0), open the s2c HPKE context
   with `server_hello.enc`, and begin sealing `msg` frames.

- **On any failure the browser MUST abort the session, seal nothing, and surface a hard
  error** (uniform, no sensitive detail — see §7.4). It MUST NOT downgrade, retry against
  the substituted key, or send any `msg`.
- The server performs the analogous sanity check on `hello`: it MUST verify
  `hello.sig` against `hello.browser_ed25519` and confirm `hello.server_x25519` /
  `hello.server_ed25519` equal **its own** identity keys (rejecting a `hello` that sealed
  to some other server key). Note this does **not** authenticate *which* browser is
  talking (browser identity is out of scope, §4.1 note) — it only ensures the client
  sealed to this server.


**Rule:** every field inside a transcript is **raw** (never base64). Labels are
ASCII. The order above is normative.

---

## 5. Frame shapes (on the wire)

JSON objects. Every binary value is a string (base64url, no padding — §6). The
one exception is `seq`, which is hex. **There is no `iv` field in any frame,
anywhere in EchoVault.**
> Frames divide into two classes. **Handshake frames** (`GET /pubkey`
> response, `hello`, `server_hello`) establish and authenticate the HPKE
> contexts; they carry key material and signatures only and never carry
> prompt content. **Encrypted payload frames** (`msg`) carry prompt content
> exclusively as encrypted `ct`, only after the handshake completes **and the §4.1.1 /
> §4.3.1 acceptance gates have passed**.

### 5.1 `GET /pubkey` → response

```json
{
  "server_x25519":  "…",   // base64url · 32-byte raw X25519 public key
  "server_ed25519": "…",   // base64url · 32-byte raw Ed25519 public key
  "sig":            "…"    // base64url · 64-byte Ed25519 signature over T_pubkey (§4.1)
}
```
> Accepted **only** if it passes the §4.1.1 pin-comparison gate. The `server_ed25519`
> here is confirmation material for the out-of-band pin, never a source of new trust.

### 5.2 `hello`  (browser → server)

```json
{
  "type":            "hello",
  "browser_x25519":  "…",  // base64url · 32-byte raw X25519 public key
  "browser_ed25519": "…",  // base64url · 32-byte raw Ed25519 public key
  "enc":             "…",  // base64url · 32-byte HPKE encapsulated key (browser→server)
  "sig":             "…"   // base64url · 64-byte Ed25519 signature over T_hello (§4.2)
}
```

### 5.3 `server_hello`  (server → browser)

```json
{
  "type":  "server_hello",  // distinct from "hello" so a receiver can tell them apart 
  "enc":   "…",             // base64url · 32-byte HPKE encapsulated key (server→browser)
  "sig":   "…"              // base64url · 64-byte Ed25519 signature over T_server_hello (§4.3)
}
```
> The browser reconstructs `T_server_hello` from `enc`, its **own** `browser_x25519` /
> `browser_ed25519`, and its **pinned** `server_x25519` / `server_ed25519`, then applies
> the §4.3.1 gate. The `browser_*` and `server_*` fields are therefore not re-sent on the
> wire (the browser already holds the authoritative copies); resending them would be
> attacker-controlled input and MUST NOT be trusted if present.


### 5.4 `msg`  (either direction, one per note)

```json
{
  "type":            "msg",
  "seq": "0000000000000007",  // HEX · 16 chars · 8-byte big-endian uint64 counter
  "ct":  "…"                 // base64url · ChaCha20-Poly1305 output = ciphertext ‖ 16-byte tag  
  // ct is the encrypted **LLM PROMPT**
}
```

- `ct` already includes the 16-byte Poly1305 tag appended at the end. There is
  **no** separate `tag` field and **no** `iv` field.
- `seq` is **hex**, not base64 — it is a human-readable counter and a uint64
  exceeds JavaScript's safe-integer range, so it must not be a JSON number.
- Note: a steady-state `msg` frame is `{ type, seq, ct }` — **`enc` appears only in
  the handshake** (`hello` / `server_hello`), not in every message.

### 5.5 No `iv` field — anywhere

**EchoVault has no `iv` field in any frame.** Per-message nonces are *derived*,
not transmitted as random IVs:

- No nonce transmitted; library derives it per-message internally. 

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
| `sig` | pubkey, hello, server_hello | base64url, no pad |
| `ct` (ciphertext ‖ tag) | msg | base64url, no pad |
| `seq` | msg | **lowercase hex**, 16 chars, zero-padded, big-endian |
| `HKDF_SALT` | config / this doc | lowercase hex |
| `INFO_X25519`, `INFO_ED25519` | key derivation | ASCII/UTF-8 bytes, verbatim (no base64) |
| `STATE` (`"echovault"`), `DIRECTION` | inside AAD | ASCII bytes, verbatim (no base64) |
| `SESSION_ID` | inside AAD (derived, §3.0) | raw bytes (SHA-256 truncated); never on the wire |
| transcript labels (`"echovault/hello/v1"`, …) | inside signed bytes | ASCII bytes, verbatim |

Rationale for the split: base64url is JSON/URL/header-safe; dropping padding
removes the single most common cross-stack mismatch (one side pads, the other
rejects `=`). `seq` is hex because it is an eyeball-in-logs counter and a padded
base64 of 8 bytes buys nothing.

---

## 7. Per-message crypto (how a `msg` is built)

Each direction opens **one** HPKE context and then uses idiomatic
`ctx.seal` / `ctx.open` for every `msg`. **HPKE owns the nonce and its own
internal counter**

> **D014 rationale — why HPKE owns the nonce.**  
> Manual nonce handling risks **nonce reuse, a catastrophic AEAD failure**:
> under ChaCha20-Poly1305 a repeated nonce leaks the XOR of the two plaintexts and can
> enable tag forgery. `ctx.seal`/`ctx.open` derive a unique, monotonic per-message
> nonce inside the context, so nothing secret or redundant goes on the wire. The cost
> is the strict in-order / per-context-ceiling tradeoff spelled out in §7.3.


### 7.1 Link setup (once per direction)

```
sender:     enc, ctx_S = SetupBaseS(pkR, info = "echovault/hpke/v1")
recipient:  ctx_R      = SetupBaseR(enc, skR, info = "echovault/hpke/v1")

```

`enc` (32 bytes) is the only setup value on the wire — carried once in `hello`
(browser→server) and `server_hello` (server→browser). `info = "echovault/hpke/v1"`
is ASCII bytes (freeze as v1). Nothing is exported; each context holds its key,
base nonce, and sequence counter internally.

> **Handshake freshness is security-critical (Step-2 S3).** The server MUST run a
> **fresh** `SetupBaseS` (a new ephemeral `enc`) for **every** connection. Reusing an
> `enc`/context across connections makes two handshakes produce the same `SESSION_ID`
> and reopens whole-session replay (a proxy could replay a recorded `hello` and reuse
> the captured `msg` frames). Fresh per-connection `enc` is what makes `SESSION_ID`
> (§3.0) perturb per session; treat it as a MUST, not an optimization to remove.

### 7.2 Sealing / opening message `seq`

```
aad       = STATE ‖ SESSION_ID ‖ DIRECTION ‖ I2OSP(seq, 8)  # §3
ct        = ctx.seal(pt, aad) (recipient: ctx.open(ct, aad))
wire      = { "seq": hex(I2OSP(seq, 8)), "ct": base64url(ct) }
```

`ct` is HPKE's AEAD output (ciphertext ‖ 16-byte tag). HPKE's internal sequence
number starts at 0 and increments by one per `seal`/`open`; it selects the nonce
automatically and it is never exposed. The `seq` we place in the AAD is the
**app-level** counter (8-byte big-endian) and MUST track the context's internal
sequence number one-for-one (both start at 0, both +1 per message per direction).

### 7.3 seq, replay, and reordering

Two consequences of letting HPKE own the counter:

- **In-order delivery per direction.** Because the nonce follows HPKE's internal
  counter, sender and receiver must process each direction's stream in order. A
  dropped or reordered frame desynchronizes the counters and `open()` fails.
- **`seq` stays for the replay/reorder story.** The `seq` bound into the AAD is an
  authenticated position marker the receiver can log and check: reject any frame
  whose `seq` is not the expected next value. Per KB `threat-model.md`, protection
  is only complete if the **receiver tracks the expected `seq` per link** and
  rejects duplicates/rollbacks; document it as partial if not implemented.

> HPKE refuses to `seal` past its per-context message limit (`AEAD` nonce space).
> Before that (far beyond demo needs) rotate the link with a fresh `enc` and a new
> `hello` / `server_hello` (which also mints a fresh `SESSION_ID`, §3.0). This is the
> same epoch/session rotation that D009/D014 name as future work. Note: rotating the
> *static identity* key adds no forward secrecy on its own — real forward secrecy
> would require a fresh **ephemeral recipient** key per epoch (§8).
---

### 7.4 Decrypt-failure & malformed-frame handling (Step-2 S6)

On **any** `open()` failure, malformed frame, bad base64url, wrong field length, out-of-
order `seq`, or failed acceptance gate (§4.1.1 / §4.3.1), the receiver MUST:

- return a **single uniform error** and emit **no** plaintext;
- reveal **no** distinguishing detail on the wire (no "bad tag" vs "bad seq" vs "unknown
  key" oracle) — the peer/proxy learns only that the frame was rejected;
- log the event **without** prompt content (`seq` and a generic reason are fine);
- fail **closed** — never fall back to an unauthenticated or plaintext path.

---


## 8. What is and isn't protected (from `threat-model.md`)

- "End-to-end" here means **browser → intended echo-server process**. The echo
  server decrypts by design; this is not messaging-app E2E where only two humans
  can read.
- HPKE-inside-TLS reduces plaintext exposure at TLS-terminating intermediaries
  that are not the intended reader.
- **Key substitution — both directions (Step-2 S1/S2).** With the mandatory acceptance
  gates (§4.1.1 pin comparison, §4.3.1 `server_hello` self-key check), an active
  TLS-terminating proxy can neither substitute the server HPKE key (browser→server) nor
  redirect the echo reply to its own key (server→browser). Both substitutions cause the
  browser to abort **before** any prompt is sealed. This holds **only** while the server
  Ed25519 identity is a genuine out-of-band pin (§4.1.1); pin-on-first-use voids it.
- **Forward secrecy (D009) — corrected.** EchoVault uses HPKE base
  mode. Each message uses a fresh ephemeral on the *sender* side, but **both**
  directions seal to a **static** recipient key (server X25519 for c2s, BIP-39
  browser X25519 for s2c). HPKE base mode is therefore **not** forward-secret against
  recipient long-term-key compromise in **either** direction — the posture is
  symmetric. Theft of the server's static X25519 key allows decryption of **all
  captured prompts** (browser→server, the most sensitive direction) via
  harvest-now-decrypt-later; theft of the browser static key likewise exposes
  captured replies. This is consistent with `threat-model.md`, which already scopes
  "stolen server private key" out of protection. Real forward secrecy is future work
  and requires per-epoch **ephemeral recipient** keys, not merely rotating the static
  identity (§7.3).
- Key pinning (the signed transcripts of §4) is a **demo trust assumption**: it
  only helps if the browser already holds the expected server identity via a
  trusted path. If the frontend JS that carries the pin is compromised, the
  attacker can swap both the key and the check.
- **Code-delivery integrity (D008).** A bundle hash shown during the demo proves
  nothing if the same origin serves both the bundle and the hash; only an
  out-of-band-verified hash or a locally packaged/pinned client (SRI, packaged app,
  extension) removes the server from the code-integrity trust path. This project
  documents code delivery as a residual limitation rather than solving it.

## Expected public / non-secret endpoints

These endpoints do not carry decrypted prompt content.

- `/api/health`
- `/api/status`
- `/pubkey` — public keys + transcript signature (§5.1); public by design
- `/ws` — transport endpoint; prompt payloads appear only as encrypted
  `ct` fields after handshake setup
```

