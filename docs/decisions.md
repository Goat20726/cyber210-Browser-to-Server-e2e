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
- **Why:** ECDH→HKDF→GCM is essentially HPKE base mode composed by hand. Hand-rolling crypto is dangerous and not industry-tested, which can lead to implementation errors. The library owns the dangerous details — nonce management, suite binding, and the key schedule — so there are fewer subtle ways to be quietly wrong. The shortfall is that we lose out on the learning that comes from implementing custom crypto (I think that's justifiable, since this isn't a cryptography course).

### D002 - BIP-39-derived tenant key vs per-session ephemeral browser key ✅
- **Chose:** Leaning toward BIP-39 for deriving tenant keys
- **Rejected:** Per-session ephemeral browser key (high state fragility; complex session handshakes; no native data persistence)
- **Why:** Allows multiple tenant sessions simultaneously.

### D003 - AES-256-GCM vs ChaCha20-Poly1305 (forward-ratchet mechanisms; practical implementation safety) ✅
- **Chose:** ChaCha20-Poly1305
- **Rejected:** AES-256-GCM (slower without hardware acceleration)
- **Why:** When building a real-world system that uses forward-ratchet mechanisms (like the Signal Protocol or Double Ratchet), ChaCha20-Poly1305 is heavily favored by modern cryptographers because of its practical implementation safety.  ChaCha20-Poly1305 inherently resists timing attacks and catastrophic failure from initialization vector (IV) reuse in software-based environments.

### D004 - Handshake authentication: implemented vs hand-waved ✅
- **Chose:** Handshake authentication
- **Rejected:** Hand-waving it
- **Why:** Make this channel as real-world as possible; it's minimal extra work now.

### D005 — Threat model & trust boundary ✅
- Chose:    E2E (HPKE, RFC 9180) INSIDE TLS 1.3; defend the prompt against a TLS-terminating
           mitmproxy by sealing browser→server before the socket.
- Rejected: TLS-only (the proxy terminates TLS → reads cleartext); hiding the prompt from the server
           itself (would need a TEE / confidential computing — out of scope).
- Why:      The only observer E2E changes is the TLS-terminating middlebox (✓→✗ on content).
           A passive sniffer is already handled by TLS; the server is a trusted endpoint by design.
           Documented gaps: served-JS / code-delivery, traffic analysis (size/timing).

### D006 — Threat-model audit vs protocol ✅
- Chose:    Update threat-model.md to match ChaCha20-Poly1305.
- Rejected: Leaving the doc as-is (it still references AES-GCM and omits active MITM).
- Why:      The AEAD is now ChaCha20-Poly1305; this adds an authenticated handshake (P8) that
           defends against key substitution — an attacker the threat model didn't list. Also add
           replay/reorder/reflection actors and a traffic-analysis gap.

### D007 — Wire envelope: structured JSON msg{type, seq, text, sender, timestamp}, frozen in protocol.md
- Chose:    ✅ (your field names; payload = `text` now, becomes `ct` in W4; seq → s2c (server-to-client))
- Rejected:  global single seq counter
- Why:       forward-compatible: sealing swaps one field; seq/direction already present for
           W4 replay/order defense; no iv because HPKE owns the nonce

### D008 — Threat Model Update: Served-JS exhibit: out-of-band code-integrity check (demo only)
- Chose:    ___ (Tier 0 hash-on-slide, Tier 1 Tauri local binary)
- Rejected: Treating the JavaScript-corruption channel as out of scope for this demo.
- Why:      There's no point showing how to secure the data channel if the code-delivery channel can be
           easily manipulated by the same threat. 