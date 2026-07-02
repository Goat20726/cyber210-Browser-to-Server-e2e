# Threat Model

## Why This Matters

TLS protects data between TLS endpoints. The problem is that in many real deployments, TLS does not terminate directly inside the application process that is meant to read the data. It often terminates first at a reverse proxy, load balancer, CDN edge node, WAF, or API gateway.

Any component that terminates TLS or receives decrypted HTTP/WebSocket traffic can read prompt contents in a TLS-only design. That matters for LLM prompt traffic because prompts may contain sensitive user text, credentials, internal business details, personal information, or other data that should not be broadly visible to infrastructure components.

HPKE inside TLS moves the plaintext boundary from the first TLS termination point to the intended application process holding the recipient private key. That is the core thesis of this demo.

This does not protect against the intended server reading the prompt. It also does not protect against someone with root or administrative access to the server reading plaintext from memory after decryption.

---

## Scope and Security Claim

The demo compares two modes:

1. **TLS-only mode:** prompt-like WebSocket traffic is protected by TLS in transit, but becomes visible wherever TLS terminates.
2. **TLS + HPKE mode:** prompt-like WebSocket traffic is encrypted in the browser before being sent through the WebSocket. TLS still protects the transport, but HPKE adds an application-layer encryption boundary.

In this project, “end-to-end” means **browser to intended echo server process**. The echo server is the intended recipient and decrypts the prompt by design.

This is not end-to-end encryption in the messaging-app sense where only two human users can read the content. The server is trusted to decrypt and echo the message.

**The claim is narrow:**

HPKE inside TLS reduces plaintext exposure at TLS-terminating intermediaries that are not the intended reader of the prompt.

**The claim is not:**

This system does not hide the prompt from the echo server, a compromised browser, compromised frontend JavaScript, a stolen server private key, server-side logs after decryption, or anyone with privileged access to the server process or host.
 
---

## Assumptions

This threat model depends on the following assumptions:

* The browser initially receives the intended demo frontend code.
* The delivered JavaScript is trusted for the purpose of the demo.
* The HPKE and AEAD libraries are implemented correctly and used according to their documentation.
* The server private key is not stolen before or during the demo.
* The server public identity key used for pinning is known to the browser through a trusted demo path, such as a hardcoded pin or trusted local configuration.
* mitmproxy represents a TLS-terminating intermediary, not a fully compromised browser or server.
* The demo uses fake prompt data only.
* The goal is to protect prompt contents from intermediaries after TLS termination, not from the intended echo server.

---

## Protected Asset

The protected asset is sensitive prompt-like text entered into the chat UI, plus the server’s echo reply.

Both directions are test points for the demo:

* Browser to server: user prompt sealed under HPKE.
* Server to browser: echo reply sealed under HPKE.

The demo must use fake values only, such as:

```text
My fake SSN is 123-45-6789
```

No real credentials, real PII, API keys, access tokens, or private project data should be used.

---

## Architecture Summary

| Layer | Component                    | Role                                                                     |
| ----- | ---------------------------- | ------------------------------------------------------------------------ |
| L1    | TLS 1.3 over `wss://`        | Outer transport tunnel; may terminate at a proxy                         |
| L2    | Demo identity material       | BIP-39 mnemonic used for repeatable demo identity and testing            |
| L3    | Demo key-pinning handshake   | Pins expected server identity; binds key material to a signed transcript |
| L4    | HPKE seal/open               | RFC 9180 HPKE using X25519, HKDF-SHA-256, and ChaCha20-Poly1305          |
| L5    | Session and integrity checks | Sequence number + session id in AAD; replay/reorder checks if implemented |
| L6    | Chat UI                      | Next.js/React interface with E2E ON/OFF toggle for comparison            |

The main trust boundary is the echo server application process holding the HPKE private key `skB`.

When E2E is ON, network observers and TLS-terminating intermediaries should see only encrypted HPKE payloads. Handshake frames expose key material (`enc`) and a signature (`sig`); steady-state message frames expose only `{ seq, ct }` (prompt plaintext never appears). (`enc` is carried once per direction in the handshake, not in every message — protocol.md §5.)

Plaintext still exists inside the intended echo server process after HPKE decryption and may be exposed through server memory, debug output, application logs, crash dumps, or privileged host access.

---

## Data Flows and Channels

There are two important channels in this system.

| Channel               | What flows                                           | Served by       | What protects it                                                                                                                    |
| --------------------- | ---------------------------------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Data channel          | WebSocket frames such as `hello` and `msg(seq, ct)`  | FastAPI `:8000` | TLS plus HPKE when E2E is ON                                                                                                        |
| Code-delivery channel | HTML and JavaScript that run the browser-side crypto | Next.js `:3000` | Not protected by HPKE; relies on normal web code-delivery trust such as HTTPS, trusted local development, and untampered JavaScript |

The data channel is what this project protects.

The code-delivery channel is an important residual risk. If the frontend JavaScript is modified before it reaches the browser, an attacker could read the prompt before encryption, send a copy elsewhere, or change which key the browser encrypts to. HPKE only protects data that the honest client code actually seals.

This project does not solve secure frontend code delivery.

---

## Trust Boundaries

### Trusted for the Demo

| Component                                   | Reason                                                                                              |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| User browser, assuming untampered page code | Holds the prompt before encryption and runs the HPKE seal/open logic                                |
| Delivered browser-side JavaScript           | Assumed trusted for the demo; if modified, browser-side encryption can be bypassed before it starts |
| Echo server application process             | Intended HPKE recipient; sees plaintext by design                                                   |
| Server-side crypto code                     | Performs HPKE open and seal-back                                                                    |
| Expected server public identity key         | Used to detect unexpected key substitution in the demo handshake                                    |

### Less Trusted / Observable

| Component                                   | Concern                                                                                  |
| ------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Passive network observer / Wireshark        | Sees encrypted TLS records, IP/port, sizes, and timing, but not plaintext when TLS works |
| mitmproxy with trusted CA installed         | Terminates TLS and can inspect WebSocket frames; named threat actor for this demo        |
| Reverse proxy / load balancer / API gateway | Represents common TLS-terminating infrastructure                                         |
| CDN edge node / WAF                         | May terminate TLS or inspect decrypted HTTP/WebSocket traffic in real deployments        |
| Cloud infrastructure                        | May operate TLS termination, routing, inspection, and logging depending on deployment    |
| Host OS and admin layer                     | Privileged access can expose plaintext after HPKE decryption                             |
| Server-side logging layer                   | May accidentally capture plaintext after HPKE open                                       |

---

## Passive Sniffing vs TLS-Terminating Proxying

These are two different threat positions and should not be conflated.

A **passive observer**, such as Wireshark, watches packets without terminating TLS. When TLS is working, a passive observer sees encrypted TLS records, connection metadata, packet sizes, and timing. TLS already handles this case.

A **TLS-terminating proxy** holds a certificate trusted by the browser or sits at an approved TLS termination point. It decrypts HTTPS or `wss://` traffic and can inspect application-layer data. In the demo, mitmproxy plays this role by using a trusted CA certificate.

The project is about what happens at and after TLS termination, where prompt contents become visible in a TLS-only design.

---

## Threat Actors

| Actor                                   | Capability                                                                | Position              |
| --------------------------------------- | ------------------------------------------------------------------------- | --------------------- |
| Passive network observer                | Captures packets but cannot break TLS                                     | Outside TLS tunnel    |
| mitmproxy with trusted CA               | Decrypts TLS and reads WebSocket frames                                   | TLS termination point |
| Reverse proxy / gateway / load balancer | Terminates or forwards decrypted application traffic                      | Infrastructure layer  |
| CDN / WAF / cloud inspection component  | May inspect decrypted traffic depending on deployment                     | Infrastructure layer  |
| Key-substitution attacker               | Attempts to replace the server public key with an attacker-controlled key | Key delivery path     |
| Tampering attacker                      | Modifies HPKE ciphertext in transit                                       | Network or proxy      |
| Replay / reorder attacker               | Re-sends or reorders valid sealed messages                                | Network or proxy      |
| Reflection attacker                     | Replays ciphertext from one direction or session into another context     | Network or proxy      |
| Denial-of-service attacker              | Floods server or sends malformed ciphertext                               | Network               |

---

## Threats and Mitigations

### Confidentiality

| Threat                                        | E2E OFF: TLS only                                          | E2E ON: TLS + HPKE        | Mitigation                                                                |
| --------------------------------------------- | ---------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------- |
| Passive sniffer reads prompt                  | Hidden by TLS                                              | Hidden by TLS             | TLS 1.3 is sufficient for passive sniffing                                |
| mitmproxy reads prompt                        | Visible after TLS termination                              | Sees HPKE ciphertext only | Browser seals prompt before sending                                       |
| Reverse proxy / gateway reads prompt          | Visible if it receives decrypted traffic                   | Sees HPKE ciphertext only | Application-layer encryption moves plaintext boundary                     |
| CDN / WAF / cloud TLS terminator reads prompt | Visible if it terminates TLS or inspects decrypted traffic | Sees HPKE ciphertext only | Same as above                                                             |
| Server-side log captures prompt               | Possible after application receives plaintext              | Possible after HPKE open  | Log hygiene; outside crypto-layer protection                              |
| Root/admin reads prompt from server memory    | Possible                                                   | Possible                  | Requires stronger isolation such as confidential computing; outside scope |

### Integrity

| Threat                                 | Expected Result                                                        | Mitigation                                       |
| -------------------------------------- | ---------------------------------------------------------------------- | ------------------------------------------------ |
| Ciphertext tampering                   | Message should fail authentication and be rejected                     | ChaCha20-Poly1305 AEAD authentication            |
| Key substitution                       | Browser should detect unexpected server identity key if pin is trusted | Demo key-pinning handshake with Ed25519 identity |
| Replay or reordering                   | Should be rejected or flagged only if sequence tracking is implemented | Monotonic sequence numbers bound into AAD        |
| Reflection across direction or session | Reflected message should fail authentication                           | Direction bound into AAD; **session bound via `SESSION_ID` (SHA-256 of the handshake transcripts) in AAD** (protocol §3.0). Cross-direction reflection fails on the direction token; cross-session reflection fails because the session's derived key differs *and* `SESSION_ID` differs. |
| Malformed ciphertext                   | Server should reject without leaking plaintext or sensitive errors     | Strict decrypt failure handling                  |

### Availability

| Threat                            | Expected Result                                   | Mitigation                        |
| --------------------------------- | ------------------------------------------------- | --------------------------------- |
| Flooding / denial of service      | Service may degrade or fail                       | Not addressed by this project     |
| Repeated malformed ciphertext     | Server may spend resources rejecting bad messages | Not a focus of the demo           |
| Proxy blocking encrypted payloads | Application may fail closed or become unavailable | Operational concern outside scope |

---

## Key-Substitution Risk

The browser encrypts to the server’s HPKE public key. If an attacker can replace that key with their own, the browser may unknowingly encrypt the prompt to the attacker.

The demo uses an Ed25519-based identity/pinning check to reduce this risk. The browser should only accept the server HPKE key if it is associated with the expected pinned server identity and signed handshake transcript.

This only helps if the browser already has the expected server identity key through a trusted path, such as a hardcoded demo pin, local configuration, or previously trusted setup.

If the pin itself is delivered by compromised frontend JavaScript, the attacker can replace both the key and the check. For that reason, key pinning is treated as a demo trust assumption, not a complete production key-management solution.

---

## Replay and Sequence Number Limits

Sequence numbers can help detect replayed or reordered messages when they are bound into HPKE associated data and checked by the receiver.

However, replay protection is only complete if the receiver actually tracks accepted sequence numbers per session and rejects duplicates or old values. Note that the stateful HPKE context also fails closed on an already-consumed frame, but that is a side effect that desynchronizes the stream — not a clean replay check (protocol §3.2 / §7.3).

If the demo implements server-side sequence tracking, replayed messages should be rejected or flagged. If not, replay protection should be documented as partial and not treated as fully solved.

---

## Known Limitations

### The Intended Server Sees Plaintext

The echo server decrypts the prompt by design. This project addresses intermediary visibility, not server-side visibility.

### Code Delivery Is Not Solved

The browser-side encryption depends on honest JavaScript. A compromised frontend server, malicious script injection, compromised npm dependency, browser extension, or build pipeline compromise could read the prompt before encryption.

HPKE does not protect against malicious code running in the browser.

### Server Logs Can Still Leak Plaintext

Plaintext may appear in request body logs, debug output, error logs, crash dumps, or console output after HPKE decryption. The demo should verify that plaintext appears only where expected.

### Root and Admin Access Remain Powerful

Anyone with root access to the server or sufficient access to the runtime can potentially read plaintext from memory after decryption. This includes the host OS, cloud provider administrators, and co-located processes with sufficient privilege.

HPKE does not protect against this threat.

### Key Management Is Demo-Level

The key-pinning handshake is useful for demonstrating key authenticity, but it is not a full production key-management system. Production systems would need stronger decisions around provisioning, rotation, revocation, storage, and user/device identity. Because identity keys are static (D009), there is **no forward secrecy against long-term-key compromise** in either direction; adding per-epoch ephemeral recipient keys is future work.

### Metadata Is Still Visible

TLS and HPKE hide payload contents, but they do not hide all metadata. Observers may still see:

* IP addresses
* Ports
* DNS lookups
* Connection timing
* Payload sizes
* Message counts
* Whether a user is communicating with the service

Traffic analysis is still possible.

### Availability Is Not Addressed

This project does not claim to prevent denial-of-service attacks, resource exhaustion, or proxy-level blocking.

---

## Out of Scope

The following are outside the protection provided by this demo:

* Compromised browser
* Malicious browser extension
* XSS or injected frontend script
* Compromised frontend build pipeline
* Compromised npm dependency
* Tampered JavaScript bundle
* Server private key theft
* Root or administrator access to the server
* Production key management
* Long-term key rotation and revocation
* User authentication and account security
* PII detection or prompt classification
* Prompt injection detection
* Real LLM provider security
* Denial-of-service protection
* Confidential computing or trusted execution environments

These are important security problems, but they are separate from the narrow claim tested in this project.

---

## CIA Triad

### Confidentiality

Confidentiality is the primary goal. The demo shows how HPKE inside TLS changes what a TLS-terminating intermediary can see. In TLS-only mode, mitmproxy can inspect plaintext WebSocket frames. In TLS + HPKE mode, mitmproxy should see only encrypted HPKE payloads.

### Integrity

Integrity is tested through active attacker cases. Because HPKE uses authenticated encryption, modified ciphertext should fail authentication instead of producing corrupted plaintext.

Sequence numbers and associated data can also help detect replay, reordering, or reflection if the receiver enforces them.

### Availability

Availability is not addressed. The system may still be vulnerable to flooding, malformed-message spam, server overload, or intermediary blocking.

---

## Expected Demo Evidence

| Scenario                                | Expected Observation                                                |
| --------------------------------------- | ------------------------------------------------------------------- |
| TLS-only with passive sniffer           | Prompt not visible; encrypted TLS records only                      |
| TLS-only with mitmproxy trusted CA      | Prompt visible in plaintext WebSocket frame                         |
| TLS + HPKE with mitmproxy trusted CA    | Handshake frame shows `{ enc, sig }`; message frames show `{ seq, ct }`; prompt plaintext not visible |
| TLS + HPKE echo reply through mitmproxy | Reply message frame shows `{ seq, ct }`; prompt plaintext not visible |
| Echo server after HPKE open             | Prompt visible to the intended server process                       |
| Tampered HPKE ciphertext                | Authentication failure; no corrupted plaintext echoed               |
| Replayed valid request                  | Rejected or flagged if server-side sequence tracking is implemented |
| Server logs                             | Plaintext should not appear in unexpected logs                      |

---

## Final Security Claim

This project demonstrates that application-layer encryption can reduce plaintext exposure at trusted TLS termination points, such as reverse proxies, gateways, WAFs, load balancers, and inspection tools.

The design is useful because it shows that TLS alone does not define the full plaintext boundary in modern deployments.

The design is limited because it still depends on trusted client code delivery, trusted endpoint execution, safe server-side handling after decryption, and demo-level key management.
