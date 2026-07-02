# CYBER 210 FINAL PROJECT Decision Log

> **Format (team convention):** every protocol decision gets a short entry —
> **Chose / Rejected / Why** — so the final paper can reconstruct *why* the channel
> looks the way it does. Keep each entry tight. Add a one-line meta header per entry.
>
> Project: *Protecting LLM Prompt Traffic Beyond TLS* (CYBER 210, Summer 2026).
> Channel: **BIP-39 identity → HPKE seal (RFC 9180) → echo server, inside TLS 1.3.**
> Legend: ✅ decided · 🔁 revisit later · 🧪 stretch/optional.

## Core Project Design 

### D001 - HPKE vs hand-rolled crypto (ECDH→HKDF→GCM) ✅
- **Chose:** HPKE (RFC 9180)
- **Rejected:** ECDH→HKDF→GCM
- **Why:** ECDH→HKDF→GCM is essentially HPKE base mode composed by hand. Hand-rolling crypto is dangerous and not industry-tested, which can lead to implementation errors. The library owns the dangerous details — nonce management, suite binding, and the key schedule — so there are fewer subtle ways to be quietly wrong. Since this is a network security project rather than a cryptography implementation project, using a standard HPKE library is the safer and more defensible choice.

### D002 - BIP-39-derived browser identity vs per-session ephemeral browser key ✅
- **Chose:** BIP-39-derived browser identity/key material for the demo.
- **Rejected:** Pure per-session ephemeral browser identity.
- **Why:** BIP-39 gives the browser a repeatable identity source across demo sessions without needing a full login, database, or external identity provider. A purely ephemeral per-session key is simpler, but it makes identity continuity, key pinning, and repeatable testing harder. Ephemeral per-message HPKE keys can still be used for sealing messages.

### D003 - AES-256-GCM vs ChaCha20-Poly1305 (forward-ratchet mechanisms; practical implementation safety) ✅
- **Chose:** ChaCha20-Poly1305
- **Rejected:** AES-256-GCM (slower without hardware acceleration)
- **Why:** ChaCha20-Poly1305 is a strong AEAD choice with good software performance and broad support in modern protocols/libraries. It avoids relying on AES hardware acceleration, which makes it a practical choice across different test environments. HPKE/library support also helps keep nonce and key-schedule handling out of our custom code. We should still treat nonce reuse as dangerous and rely on the HPKE library to manage this correctly.

### D004 - Handshake authentication: implemented vs hand-waved ✅ *(updated)*
- **Chose:** Authenticated handshake with signed key material / transcript verification.
- **Rejected:** Unauthenticated public-key exchange.
- **Why:** Without handshake authentication, a TLS-terminating proxy could try a key-substitution attack by replacing Bob’s public key with its own. Authentication gives the browser a way to verify that it is sealing the prompt to the intended server key. (Note: this authenticates the *server to the browser* via the pinned Ed25519 key; the browser's own `hello` signature is trust-on-first-use — see protocol.md §4.1 note.)

### D005 — Threat model & trust boundary ✅
- **Chose:** HPKE-protected application payloads inside TLS 1.3. The browser seals the prompt before it enters the socket, and the intended echo server opens it.
- **Rejected:** TLS-only protection as the final security model. Also rejected hiding plaintext from the intended server itself, which would require TEEs/confidential computing and is out of scope.
- **Why:** TLS already protects against a passive network sniffer, but it does not protect plaintext after TLS terminates at a trusted inspection proxy such as mitmproxy. HPKE changes what that TLS-terminating middlebox can see: with E2E on, it sees sealed payload fields instead of prompt plaintext. The intended server remains trusted and still sees plaintext after decryption. Known gaps include served-JS/code delivery, server-side logging after decryption, and traffic analysis such as timing and size.

### D006 — Threat-model audit vs current protocol ✅
- **Chose:** Update `threat-model.md` to match the current protocol and diagrams.
- **Rejected:** Leaving the threat model with outdated AES-GCM references and missing active attacker cases.
- **Why:** The protocol now uses ChaCha20-Poly1305 through HPKE, and the diagrams include an authenticated handshake, key pinning, sealed payloads, replay/order checks, and mitmproxy as an active TLS-terminating intermediary. The threat model should include key substitution, tampering, replay/reorder, reflection, traffic analysis, served-JS/code delivery, and server-side plaintext logging as either threats or limitations.

### D007 — Wire envelope format ✅  *(updated)*
- **Chose:** A structured JSON message envelope with a `type` discriminator and per-message-type fields, frozen in `protocol.md` §5. The steady-state message frame is `{ "type": "msg", "seq", "ct" }` (E2E mode); handshake frames (`hello`, `server_hello`, `GET /pubkey` response) carry key material (`enc`, public keys) and a `sig` only. In plaintext (E2E-OFF) mode the payload may instead be a `text` field.
- **Rejected:** An unstructured raw text message and a single global sequence counter. Also **dropped** the earlier `sender` and `timestamp` envelope fields — `protocol.md` §5.4 (the single source of truth per D013) does not carry them; direction is known per link and freshness is handled via `seq` + session binding, not a wire timestamp.
- **Why:** A stable envelope makes the demo easier to extend. The same message structure can support plaintext mode, E2E mode, replay detection, and ordering checks. Separate client-to-server and server-to-client sequence tracking is clearer than one global counter. HPKE owns nonce handling, so the envelope should not add a custom IV field. **This entry is descriptive; if it ever conflicts with `protocol.md` §5, `protocol.md` wins (D013).**

### D008 — Served-JS / code-delivery integrity ✅ (limitation) · 🧪 (demo aid)
- **Chose:** Document browser code-delivery integrity as an explicit, unsolved limitation of
  this project. Optionally add a demo-only integrity aid — a shown bundle hash or a locally
  packaged client — as stretch work, not a core requirement.
- **Rejected:** Treating delivered browser JavaScript as automatically trustworthy.
- **Why:** Browser-side encryption only protects the prompt if the code performing it is itself
  trustworthy. If the same server or delivery path can modify the JavaScript, malicious code
  could exfiltrate plaintext before HPKE seal or alter key-pinning/verification behavior. We
  scope this out as residual risk, we do not solve it. Note: a hash-on-slide proves nothing if
  the same origin serves both the bundle and the hash — only an out-of-band-verified hash or a
  locally packaged/pinned client (SRI, packaged app, extension) actually removes the server
  from the code-integrity trust path.


### D009 — Identity = BIP-39 24-word mnemonic, deterministic keys via HKDF tree ✅ *(updated)*
- **Chose:** Derive a static identity from a 24-word BIP-39 mnemonic via the standard BIP-39
  seed process and an HKDF-SHA256 key tree, yielding an X25519 HPKE-recipient key and an
  Ed25519 signing key.
- **Rejected:** Random per-session identity keys, raw localStorage key blobs, or any scheme
  that cannot be recovered from the mnemonic.
- **Why:** The mnemonic gives a recoverable, escrow-free, human-transferable demo identity with
  no server-side private-key storage. 
- **Tradeoff (corrected Step-1 F1):** a static identity key is weaker than a fresh per-session
  key. EchoVault uses HPKE **base mode**, which seals every message to a **static** recipient
  key in **both** directions (server X25519 for c2s, browser X25519 for s2c). Base mode is
  therefore **not** forward-secret against recipient long-term-key compromise in **either**
  direction: a stolen server key exposes all captured prompts (harvest-now-decrypt-later). This
  is consistent with `threat-model.md`, which already scopes "stolen server private key" out.
  Real forward secrecy would require per-epoch **ephemeral recipient** keys (not merely rotating
  the static identity) — future work / stretch goal. Private keys never go on the wire and are
  imported non-extractable where the platform allows.


### D010 — Seed derivation = standard BIP-39 mnemonicToSeed parameters ✅
- **Chose:** Standard BIP-39 mnemonic-to-seed derivation: PBKDF2-HMAC-SHA512, 2048 iterations,
  salt = "mnemonic" + passphrase, empty passphrase for the demo.
- **Rejected:** Custom salts, custom iteration counts, custom hash functions, or requiring a
  passphrase in the demo flow.
- **Why:** The goal is deterministic, cross-implementation recovery. The *reason* to use the
  standard process is that BIP-39 already defines exactly how a mnemonic becomes a seed, so the
  same 24 words reproduce deterministic cross-implementation interoperable with any implemenation
  (python, node.js etc). The low 2048-iteration   count is acceptable only because the security 
  lives in the ~256-bit mnemonic entropy, not in a low-entropy password. The empty passphrase 
  drops BIP-39's optional 25th-word second factor — fine for demo simplicity, but documented 
  as a demo limitation, not a production recommendation.

### D011 — Key tree = HKDF-SHA256 with domain-separated outputs ✅
- **Chose:** Derive separate encryption and signing key material from the 64-byte BIP-39 seed
  with HKDF-SHA256, using a frozen salt and distinct `info` strings per key purpose (e.g.
  `echovault-x25519-encryption`, `echovault-ed25519-signing`), 32 bytes each.
- **Rejected:** Splitting the seed by hand, reusing one derived key for multiple purposes, or a
  wallet-style hierarchical scheme (BIP-32 / SLIP-0010).
- **Why:** This is fundamentally a key-purpose separation decision: never use one key for two
  jobs. Two flat keys (one HPKE encryption identity, one signing) with per-purpose `info` domain
  separation is the RFC 5869 idiom — simple, curve-agnostic, easy to reproduce across JS/Python.
  The salt and `info` strings are frozen: changing either silently changes the derived identity.

### D012 — Keypair derivation = deterministic X25519 (HPKE recipient) + Ed25519 (signing) ✅
- **Chose:** Derive deterministic keypairs from the mnemonic-backed key tree — X25519 for HPKE
  recipient encryption, Ed25519 for signing — stating each key's role and the requirement to
  verify them byte-for-byte across both implementations.
- **Rejected:** Randomly generated identity keypairs, persisting private keys as raw blobs, or
  trusting cross-library key handling that has not been interop-tested.
- **Why:** The identity must be reproducible from the mnemonic and byte-identical between the
  browser (hpke-js) and Python/server (pyhpke) sides. The decision log states the roles and the
  interop obligation; it need not reproduce the scalar math. The specific footgun is deterministic 
  X25519 derivation from HKDF bytes, where raw-scalar vs. clamped handling can diverge between 
  libraries and produce mismatched public keys or shared secrets. Move the exact byte-level 
  contract (scalar clamping, encoding) into PROTOCOL.md **Also add `SESSION_ID` (protocol §3.0)
  to the interop test — both sides must compute `SHA-256(T_hello ‖ T_server_hello)[:16]`
  byte-identically.**

### D013 — Freeze the full wire contract in PROTOCOL.md before live handshake ✅
- **Chose:** Freeze the HPKE suite, key-derivation values (salt/info/iterations), public-key
  formats, AAD encoding, transcript byte-layout, frame shapes, and base64 conventions in
  PROTOCOL.md, with Cam's sign-off, before either side implements the live handshake.
- **Rejected:** Writing the handshake first and reconciling encoding/framing differences later
  during interop.
- **Why:** The client and server are built in different languages by different people working
  remotely. Even with correct crypto choices, mismatched encodings or frame formats silently
  break interop. Catching those in document review is far cheaper than debugging them live.

### D014 — Let HPKE ctx.seal / ctx.open own the nonce and message counter ✅
- **Chose:** Let the HPKE context manage nonce derivation and the internal message counter
  through `seal` / `open`.
- **Rejected:** Manually generating, transmitting, or tracking nonces outside the HPKE context.
- **Why:**  Manual nonce handling risks nonce reuse, a catastrophic AEAD failure: under 
ChaCha20-Poly1305 (and GCM) a repeated nonce leaks the XOR of plaintexts and, for GCM, enables 
forgery. RFC 9180's `seal`/`open` derive a unique, monotonic per-message nonce inside the context 
and put nothing secret or redundant on the wire; the API is identical across hpke-js, pyhpke, 
Go, and Rust. 
- **Tradeoff:** Each HPKE context requires strict in-order delivery per direction, offers no
  random-access/stateless decryption, and has a per-context message ceiling. A long-lived link
  must rotate to a fresh context (`enc` + hello/server_hello) before that ceiling — the same
  rotation named in D009. **Note (Step-1 F1):** this rotation bounds nonce exhaustion and mints a
  fresh `SESSION_ID`, but on its own it does **not** add forward secrecy while the recipient key
  is a static BIP-39 identity; forward secrecy needs per-epoch ephemeral recipient keys 
  (future / stretch goal). 

### D015 — Mandatory `server_hello` acceptance gate  ✅
- **Chose:** Require the browser to **cross-check the contents** of `T_server_hello`, not
  just verify its signature, **before** opening the HPKE context or sealing any prompt.
  The browser MUST (protocol.md §4.3.1): (1) `Ed25519_Verify` with the **pinned**
  `server_ed25519`; (2) assert the transcript's `server_x25519`/`server_ed25519` equal
  the pin; (3) assert the transcript's `browser_x25519`/`browser_ed25519` byte-equal the
  values the browser itself put in `hello`; (4) abort hard on any mismatch. The server
  performs the analogous check on `hello` (client sealed to *this* server's keys).
- **Rejected:** Signature-only acceptance of `server_hello` (verify `sig`, then proceed).
- **Why:** The c2s (prompt) direction uses the browser's *ephemeral* `enc`, so it never
  depends on `browser_x25519`. The s2c (echo-reply) direction — a **declared protected
  asset**, since the echo carries the prompt back — seals to `browser_x25519`, and the
  server holds **no pin for the browser**. An active proxy can rewrite `hello` (keep the
  real `enc`, swap in its own `browser_x25519`, re-sign with its own Ed25519); the real
  pinned server then validly signs a `server_hello` containing the proxy's key, so a
  signature-only check passes and the server seals the reply **to the proxy**, which
  decrypts the prompt. The content cross-check is the only thing that detects this. The
  `hello → server_hello → msg` ordering means the gate aborts **before** any prompt is
  sealed, so the fix costs nothing but a comparison. **Tradeoff:** a proxy can still force
  an abort (denial of service) — explicitly out of scope (availability).

### D016 — `/pubkey` is confirmed against the pin, never trusted from the wire ✅
- **Chose:** Treat `server_ed25519` from `/pubkey` as **untrusted input**. The browser
  MUST compare it to a pre-provisioned out-of-band pin **first**, verify the signature
  against the pin, and adopt `server_x25519` only via that pin-anchored signature
  (protocol.md §4.1.1). If no pin is provisioned, refuse to run the E2E handshake (fail
  closed).
- **Rejected:** Trust-on-first-use / pin-on-first-use — learning and caching the server
  identity from the first `/pubkey` response.
- **Why:** The entire key-substitution defense (D004, D015) rests on the server Ed25519
  identity being a genuine out-of-band pin. If the identity is learned from the wire, an
  active proxy present at first contact substitutes **both** the key and the identity, and
  every downstream check — including D015 — then validates against the attacker's key,
  silently voiding the whole guarantee. This keeps the mitigation inside the documented
  "pin is a demo trust assumption" boundary (threat-model.md) and makes that assumption
  *enforceable* rather than implicit. It does **not** claim production key management
  (provisioning/rotation/revocation remain out of scope).

### D017 — Fresh server ephemeral `enc` per connection is security-critical ✅
- **Chose:** Mandate a fresh `SetupBaseS` (new ephemeral `enc`) on the server for **every**
  connection (protocol.md §7.1), so each handshake yields a distinct `SESSION_ID` (§3.0).
- **Rejected:** Reusing an HPKE context / `enc` across connections as an optimization.
- **Why:** The whole-session-replay defense works **only** because a replayed `hello`
  forces the server to emit a fresh `enc`, changing `SESSION_ID` and causing the replayed
  `msg` frames to fail `open()`. That is currently an emergent property of per-connection
  ephemerals, not a stated guarantee — an `enc`-reuse optimization would silently reopen
  session replay, and the server has no independent anti-replay. Documenting it as a MUST
  converts an accident into a guarantee. **Defense-in-depth (🔁 optional):** mix a
  server-chosen random nonce into `T_pubkey`/`server_hello`, or reject a `hello` whose
  `enc` was seen recently.

### D018 — Uniform fail-closed decrypt/handshake error handling (hardens Step-2 S6) ✅
- **Chose:** On any `open()` failure, malformed frame, bad encoding/length, out-of-order
  `seq`, or failed acceptance gate, return a **single uniform error**, emit no plaintext,
  reveal no distinguishing detail on the wire (no bad-tag vs bad-seq vs unknown-key
  oracle), log without prompt content, and never fall back to a plaintext path
  (protocol.md §7.4).
- **Rejected:** Distinct, descriptive error messages per failure cause; any
  plaintext/partial-plaintext on failure.
- **Why:** Satisfies the threat-model integrity requirement ("reject without leaking
  plaintext or sensitive errors") explicitly, avoids padding/oracle-style side channels,
  and gives the Step-3 tamper/malformed tests (T9/T10) a well-defined expected result.
