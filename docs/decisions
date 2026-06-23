# CYBER 210 FINAL PROJECT Decision Log

> **Format (team convention):** every protocol decision gets a short entry —
> **Chose / Rejected / Why** — so the final paper can reconstruct *why* the channel
> looks the way it does. Keep each entry tight. Add a one-line meta header per entry.
>
> Project: *Protecting LLM Prompt Traffic Beyond TLS* (CYBER 210, Summer 2026).
> Channel: **BIP-39 identity → HPKE seal (RFC 9180) → echo server, inside TLS 1.3.**
> Legend: ✅ decided · 🔁 revisit later · 🧪 stretch/optional.

## Core Project Design 

### D001 - HPKE vs Rolled Crypto ECDH→HKDF→GCM
- **Chose:** HPKE (RFC 9180)
- **Rejected:** ECDH→HKDF→GCM
- **Why:** ECDH→HKDF→GCM is HPKE base mode, composed by hand.  Hand rolling crypto is dangarous and not industry tested that could lead to implementation errors. The library owns the dangerous details — nonce management, suite binding, the key schedule — so fewer subtle ways to be quietly wrong. The short fall is that we're suffering on the learning of implementing custom crypto (I think it's justafiable since this isn't a cryptography course)

