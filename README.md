# **CYBER 210: Protecting LLM Prompt Traffic Beyond TLS: A Browser-to-Server Encryption Demo** 

## **Final Project Operating Document**  
Cameron Faulkner, Aura Gaines, and Fil Dziembowski

### Problem statement

Modern LLM chat apps send your prompt to the server in plaintext (inside TLS, but readable by the server operator, any reverse proxy, and any logging middleware). Privacy gateways like the LLM-VG architecture fix this with an **application-layer end-to-end encrypted channel**: the browser encrypts the prompt *before it leaves the page*, and only the one process that must read it can decrypt (in LLM VG, the redaction supervisor; in your project, a simulated LLM).

This project studies whether adding browser-to-server application-layer encryption can reduce that plaintext exposure. We will use a simple browser chat interface and echo server as a stand-in for LLM prompt traffic. The browser will encrypt the message before sending it, and only the server process intended to read the message will decrypt and echo it back.

The goal is not to build a production LLM gateway or replace TLS. The goal is to compare what different observers can see in three models: plaintext traffic, TLS-protected traffic, and TLS plus application-layer encryption.

**Research question we are asking**: How does browser-to-server application-layer encryption change what intermediaries can see compared with TLS alone for sensitive LLM-style prompt traffic?  


### What we're building (in one picture)

```
   ┌──────────────────────────┐ wss ┌──────────────┐ wss ┌──────────────────────────────┐
   │ BROWSER (Next.js client) │────▶│  mitmproxy   │────▶│ WEBSERVER (Python / FastAPI) │
   │ HPKE (RFC 9180) sealing   │ TLS │ TLS-terminat-│ TLS │ Simulated "LLM": decrypts,   │
   │ seals prompt IN THE PAGE  │◀────│ ing  MITM    │◀────│ echoes "ECHO: <prompt>"      │
   └──────────────────────────┘     └──────┬───────┘     └──────────────────────────────┘
                                           │ sees the TLS-decrypted payload:
                                           │   E2E OFF → prompt in CLEARTEXT   (TLS alone fails)
                                           │   E2E ON  → CIPHERTEXT only        (E2E defeats the MITM)
              ┌──────────── RED TEAM ──────┘
              └ captures the wire · runs the mitmproxy TLS-vs-E2E exhibit · owns the attack suite
```

Scope: This project focuses on demonstrating how sensitive prompt-like traffic changes as it moves through three security models: plaintext traffic, TLS-protected traffic, and TLS plus browser-to-server application-layer encryption. We will use a simple browser chat interface and echo server as a stand-in for LLM prompt traffic so the project stays focused on network security, traffic visibility, encryption boundaries, and threat modeling. 

This project includes:

- [ ] Web Page with chat-style UI that echos the text typed by the user  
- [ ] A web server hosting the page (using Python FastAPI or [Node.js](http://Node.js) with Websocket support)  
- [ ] A browser WebCrypto key-agreement handshake, allowing the browser to start an end-to-encryption channel  
- [ ] An **HPKE** channel using a vetted library (**`hpke-js`** in the browser, **`pyhpke`** on the
  server). Integrating the industry-standard primitive *correctly*, and
  understanding what it does (KEM / key schedule / AEAD / AAD), *is* the learning objective.
- [ ] Authenticated encryption of every message in **both directions** (HPKE seal/open).
- [ ] Protection against **tampering, replay, and reflection** — and tests that prove each.
- [ ] TLS Certificates for the web server  
- [ ] A live demo showing   
      - [ ] (a) plaintext on the wire  
      - [ ] (b) ciphertext protected by TLS  
      - [ ] (c) ciphertext protected by browser-to-server application-layer encryption   
- [ ] A written paper describing the threat model, including what this channel protects against and what it does not protect against 

This project does not attempt to build a production LLM gateway or connect to a real LLM provider; the echo server is used to keep the demo simple and focused on network security. 

**Stretch goals (only if Week 4 checkpoint is green):** untrusted-relay demo, **multi-recipient
HPKE seal** (`{server, second-recipient}`, the Morphex `{supervisor, tenant_envelope}` shape),
**ChaCha20-Poly1305** AEAD to match Morphex exactly, epoch-rotating the server recipient key for
forward secrecy, vendoring `hpke-js` for an offline demo.

Deliverables per week (6 Weeks) 25 JUL (giving us \~2 week fluff):

- [ ] W2 \- Protocol design document   
- [ ] W2 \- Working plain text echo (client / proxy / webserver architecture)  
- [ ] W3 \- Working encrypted echo, end to end   
- [ ] W4 \- Attack test suite (should be confirmed TLS certs, mitmproxy all operational)   
- [ ] W5 \- Final Paper / Presentation complete   
- [ ] W6 \- Final demo runs ≤5-10 min twice; deck \+ paper submitted

### Team roles (3 members; Aura everyone codes)
- Aura : Red Team   
- Cam: WebServer  
- Fil: Browser

| Role | Owns | First task |
|---|---|---|
| **Red Team** — | Attack tests, packet captures, the **mitmproxy TLS-vs-E2E demo**; **also runs the weekly checkpoint + repo hygiene** (the PM duties, since you're three); tries to break the other two every week | Spike: capture localhost WebSocket traffic in Wireshark/DevTools; set up repo + tracker |
| **WebServer** — (WebServer Encryption Integration) | Server HPKE (`pyhpke`) + WebSocket endpoint; same suite as the client | Spike: round-trip a `pyhpke` `seal`/`open`; echo a plaintext WebSocket message |
| **Browser** — (Browser Encryption Integration) | Browser HPKE integration (`hpke-js`) + UI | Spike: round-trip an `hpke-js` sender/recipient `seal`/`open` in a console |
Knowledge Management:

- [ ] 1x Github Repo [https://github.com/Goat20726/cyber210-Browser-to-Server-e2e](https://github.com/Goat20726/cyber210-Browser-to-Server-e2e) protected \`main\`, off weekX-integration PRs reviewed and merged with a slack notification when merge complete.  
- [ ] The Adversary lead gets veto power: if an attack they can demonstrate validity then we continue to iterate   
- [ ] Decision log: every protocol decision (curve, KDF, nonce strategy…) gets 3 lines in   \`docs/decisions.md\` — \*what we chose, what we rejected, why\*.  This will help our final paper  

### Macro Schedule

| Track / Task | Week1 Jun15 | Week2 Jun22 | Week3 Jun29 | Week4 Jul06 | Week5 Jul13 | Week6 Jul20 |
|---|---|---|---|---|---|---|
| **SHARED / SPEC** | | | | | | |
| Toolchain + repo setup | ●●●●· | | | | | |
| Protocol Spec v0→v1→FREEZE | ●●·●● | ●●●●● | ●●●● | | | |
| **BROWSER (Next.js + hpke-js)** | | | | | | |
| Scaffold + plaintext echo | ●●●●● | | | | | |
| HPKE handshake (contexts) | | ●●●●● | | | | |
| HPKE seal/open | | | ●●●●● | | | |
| Harden + fix findings | | | | ●●●●● | | |
| Demo polish + slides | | | | | ●●●●● | |
| Final demo + paper | | | | | | ●●●●● |
| **WEBSERVER (Python / FastAPI)** | | | | | | |
| Scaffold + plaintext echo | ●●●●● | | | | | |
| HPKE handshake (contexts) | | ●●●●● | | | | |
| HPKE seal/open | | | ●●●●● | | | |
| Harden + fix findings | | | | ●●●●● | | |
| Demo polish + slides | | | | | ●●●●● | |
| Final demo + paper | | | | | | ●●●●● |
| **RED TEAM** | | | | | | |
| Baseline + mitmproxy setup | ●●●●● | | | | | |
| Handshake / interop tests | | ●●●●● | | | | |
| Tamper + leak tests | | | ●●●●● | | | |
| Full attack matrix (LEAD) | | | | ●●●●● | | |
| Threat model + paper section | | | | | ●●●●● | |
| TLS-vs-E2E + live attack | | | | | | ●●●●● |
| **DELIVERABLES** | | | | | | |
| Live demo (rehearse →) | | | | · | XXX | ★FINAL |
| Slide deck | | | | | XXX | ★FINAL |
| Paper | | | | draft | XXX | ★FINAL |
