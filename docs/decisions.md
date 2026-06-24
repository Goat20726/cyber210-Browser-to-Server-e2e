# CYBER 210 FINAL PROJECT Decision Log

> **Format (team convention):** every protocol decision gets a short entry —
> **Chose / Rejected / Why** — so the final paper can reconstruct *why* the channel
> looks the way it does. Keep each entry tight. Add a one-line meta header per entry.
>
> Project: *Protecting LLM Prompt Traffic Beyond TLS* (CYBER 210, Summer 2026).
> Channel: **BIP-39 identity → HPKE seal (RFC 9180) → echo server, inside TLS 1.3.**
> Legend: ✅ decided · 🔁 revisit later · 🧪 stretch/optional.

## Core Project Design 

### D001 - HPKE vs Rolled Crypto ECDH→HKDF→GCM ✅
- **Chose:** HPKE (RFC 9180)
- **Rejected:** ECDH→HKDF→GCM
- **Why:** ECDH→HKDF→GCM is HPKE base mode, composed by hand.  Hand rolling crypto is dangarous and not industry tested that could lead to implementation errors. The library owns the dangerous details — nonce management, suite binding, the key schedule — so fewer subtle ways to be quietly wrong. The short fall is that we're suffering on the learning of implementing custom crypto (I think it's justafiable since this isn't a cryptography course)

### D002 - BIP-39 Derived tenant key vs per-session ephemeral browser key ✅
- **Chose:** Leaning towards BIP-39 for deriving tenant keys
- **Rejected:** per-session ephemeral browser key;High State Fragility; Complex Session Handshakes;No Native Data Persistence
- **Why:** Allows for multiple tenant sessions simultatiously 

### D003 - AES-256-GCM vs ChaCha20-Poly1305 (forward ratchet mechanisms practical implementation safety) ✅
- **Chose:** ChaCha20-Poly1305 
- **Rejected:** AES-256-GCM (slower without hardware acceleration)
- **Why:** when building a real-world system utilizing forward ratchet mechanisms (like the Signal Protocol or Double Ratchet), ChaCha20-Poly1305 is heavily favored by modern cryptographers due to practical implementation safety

### D004 - Handshake authentication Implemented / Handwaved ✅
- **Chose:** Handshake authentication 
- **Rejected:** Handwaved
- **Why:** Make this channel as real world as possible, it's minimal extra work now.

### D005 — Threat model & trust boundary ✅
Chose:    E2E (HPKE, RFC 9180) INSIDE TLS 1.3; defend the prompt against a TLS-terminating
          mitmproxy by sealing browser→server before the socket.
Rejected: TLS-only (proxy terminates TLS → reads cleartext); hiding prompt from the server
          itself (would need TEE/confidential computing — out of scope).
Why:      The only observer E2E changes is the TLS-terminating middlebox (✓→✗ on content).
          Passive sniffer already handled by TLS; server is a trusted endpoint by design.
          Documented gaps: served-JS/code-delivery, traffic analysis (size/timing).

### D006 — Threat-model audit vs protocol
Chose:    Update threat-model.md to match ChaCha20-Poly1305
Rejected: Leaving the doc as-is (still references AES-GCM, omits active MITM).
Why:      AEAD is now ChaCha20-Poly1305; adds an authenticated handshake (P8) that
          defends key-substitution, an attacker the threat model didn't list. Add
          replay/reorder/reflection actors and a traffic-analysis gap.