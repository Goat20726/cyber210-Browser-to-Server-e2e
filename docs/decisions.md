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

### D004 - Handshake authentication: implemented vs hand-waved ✅
- **Chose:** Authenticated handshake with signed key material / transcript verification.
- **Rejected:** Unauthenticated public-key exchange.
- **Why:** Without handshake authentication, a TLS-terminating proxy could try a key-substitution attack by replacing Bob’s public key with its own. Authentication gives the browser a way to verify that it is sealing the prompt to the intended server key.

### D005 — Threat model & trust boundary ✅
- **Chose:** HPKE-protected application payloads inside TLS 1.3. The browser seals the prompt before it enters the socket, and the intended echo server opens it.
- **Rejected:** TLS-only protection as the final security model. Also rejected hiding plaintext from the intended server itself, which would require TEEs/confidential computing and is out of scope.
- **Why:** TLS already protects against a passive network sniffer, but it does not protect plaintext after TLS terminates at a trusted inspection proxy such as mitmproxy. HPKE changes what that TLS-terminating middlebox can see: with E2E on, it sees sealed payload fields instead of prompt plaintext. The intended server remains trusted and still sees plaintext after decryption. Known gaps include served-JS/code delivery, server-side logging after decryption, and traffic analysis such as timing and size.

### D006 — Threat-model audit vs current protocol ✅
- **Chose:** Update `threat-model.md` to match the current protocol and diagrams.
- **Rejected:** Leaving the threat model with outdated AES-GCM references and missing active attacker cases.
- **Why:** The protocol now uses ChaCha20-Poly1305 through HPKE, and the diagrams include an authenticated handshake, key pinning, sealed payloads, replay/order checks, and mitmproxy as an active TLS-terminating intermediary. The threat model should include key substitution, tampering, replay/reorder, reflection, traffic analysis, served-JS/code delivery, and server-side plaintext logging as either threats or limitations.

### D007 — Wire envelope format ✅
- **Chose:** A structured JSON message envelope with fields such as `type`, `seq`, `sender`, `timestamp`, and a payload field. In plaintext mode the payload may be `text`; in E2E mode it becomes sealed HPKE fields such as `enc` and `ct`.
- **Rejected:** An unstructured raw text message and a single global sequence counter.
- **Why:** A stable envelope makes the demo easier to extend. The same message structure can support plaintext mode, E2E mode, replay detection, and ordering checks. Separate client-to-server and server-to-client sequence tracking is clearer than one global counter. HPKE owns nonce handling, so the envelope should not add a custom IV field.

### D008 — Served-JS/code-delivery limitation 🔁
- **Chose:** Revisit whether to include a demo-only code-integrity exhibit, such as a hash shown during the demo or a local packaged client.
- **Rejected:** Treating JavaScript/code-delivery risk as invisible.
- **Why:** Browser-side encryption only helps if the browser code doing the encryption is trustworthy. If the same server or delivery path can modify the JavaScript, malicious code could leak plaintext before encryption or change key verification behavior. For this project, we should at minimum document this as a limitation. A hash-on-slide or local packaged client could be used as a demo aid, but that may be stretch work.
