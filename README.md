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
EchoVault — current architecture (v3): BIP-39 identity · authenticated HPKE · ChaCha20-Poly1305, inside TLS

   ┌──────────────────────────┐ wss ┌──────────────┐ wss ┌──────────────────────────────┐
   │ BROWSER (Next.js / Node) │────▶│  mitmproxy   │────▶│ WEBSERVER (Python / FastAPI) │
   │ BIP-39 keys · hpke-js    │ TLS │ TLS-terminat-│ TLS │ pyhpke: verify sig, opens,   │
   │ seals prompt IN THE PAGE │◀────│ ing  MITM    │◀────│ echoes "ECHO: <prompt>"      │
   └──────────────────────────┘     └──────┬───────┘     └──────────────────────────────┘
                                           │ sees the TLS-decrypted payload:
                                           │   E2E OFF → prompt in CLEARTEXT       (TLS alone fails)
                                           │   E2E ON  → { enc, ct } CIPHERTEXT    (E2E defeats the MITM)
                                           │   swap /pubkey key → SIG VERIFY FAILS (auth handshake · T11)
              ┌──────────── RED TEAM ──────┘
              └ captures the wire · runs the mitmproxy TLS-vs-E2E exhibit (A→B→C) · owns the attack suite
```

Scope: This project focuses on demonstrating how sensitive prompt-like traffic changes as it moves through three security models: plaintext traffic, TLS-protected traffic, and TLS plus browser-to-server application-layer encryption. We will use a simple browser chat interface and echo server as a stand-in for LLM prompt traffic so the project stays focused on network security, traffic visibility, encryption boundaries, and threat modeling. 

This project includes:

- [ ] A **Node.js (Next.js/React)** chat-style web page.
- [ ] A **Python FastAPI** server that accepts a WebSocket connection (and serves `GET /pubkey`). 
- [ ] A browser WebCrypto key-agreement handshake, allowing the browser to start an end-to-encryption channel  
- [ ] An **HPKE** channel using a vetted library (**`hpke-js`** in the browser, **`pyhpke`** on the
  server). Integrating the industry-standard primitive *correctly*, and
  understanding what it does (KEM / key schedule / AEAD / AAD), *is* the learning objective.
- [ ] **BIP-39 browser identity:** a 24-word mnemonic → HKDF tree → X25519 (HPKE recipient) + Ed25519
  (signing) keypairs, derived **in the page**, private keys non-extractable.
- [ ] Authenticated encryption of every message in **both directions** (HPKE seal/open).
- [ ] Protection against **tampering, replay, and reflection** — and tests that prove each.
- [ ] TLS Certificates for the web server  
- [ ] A live demo showing   
      - [ ] (a) plaintext on the wire  
      - [ ] (b) ciphertext protected by TLS  
      - [ ] (c) ciphertext protected by browser-to-server application-layer encryption   
- [ ] A written paper describing the threat model, including what this channel protects against and what it does not protect against 

This project does not attempt to build a production LLM gateway or connect to a real LLM provider; the echo server is used to keep the demo simple and focused on network security. 

**Stretch goals (only if Week 4 checkpoint is green):**
- **Headline — Forward-secrecy epoch ratchet:** rotate the recipient key material on a
  schedule so a stolen static key can't decrypt recorded traffic (restores the forward secrecy that a
  static BIP-39 recipient key trades away).
- Multi-recipient HPKE seal (`{server, second-recipient}`, the VG `{supervisor, tenant}` shape);
  post-quantum hybrid X25519+ML-KEM-768; vendoring `hpke-js` for an offline demo; WebAuthn-gated
  mnemonic unlock; an untrusted-relay demo.

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
| **Red Team** | Attack tests, packet captures, the **mitmproxy TLS-vs-E2E demo**; **runs the weekly checkpoint + repo hygiene** | Spike: capture localhost WebSocket traffic in Wireshark/DevTools;  |
| **WebServer** (WebServer Encryption Integration) | Server HPKE (`pyhpke`) + WS endpoint + `GET /pubkey` + signature verify; same suite as the client | Spike: round-trip a `pyhpke` `seal`/`open`; echo a plaintext WebSocket message |
| **Browser** (Browser Encryption Integration) | Browser HPKE + **BIP-39 identity** + handshake signing + UI (`hpke-js`, Next.js) | Spike: round-trip an `hpke-js` ChaCha20 `seal`/`open` in a console; derive a keypair from a test mnemonic; set up repo + tracker |

> **spike** = a short-term, experimental task focused on research, prototyping, or gathering data rather than writing production-ready code

### Knowledge Management:

- [ ] 1x Github Repo [https://github.com/Goat20726/cyber210-Browser-to-Server-e2e](https://github.com/Goat20726/cyber210-Browser-to-Server-e2e) protected \`main\`, off weekX-integration PRs reviewed and merged with a slack notification when merge complete.  
- [ ] The Adversary lead gets veto power: if an attack they can demonstrate validity then we continue to iterate   
- [ ] Decision log: every protocol decision (curve, KDF, nonce strategy…) gets 3 lines in   \`docs/decisions.md\` — \*what we chose, what we rejected, why\*.  This will help our final paper  

### Macro Schedule

| Track | Task | W1 Jun15 | W2 Jun22 | W3 Jun29 | W4 Jul06 | W5 Jul13 | W6 Jul20 |
|---|---|---|---|---|---|---|---|
| **Browser** | scaffold + plaintext | ●●●●● | | | | | |
| | BIP-39 + auth handshake | | ●●●●● | | | | |
| | ChaCha20 seal/open | | | ●●●●● | | | |
| | fix findings | | | | ●●●●● | | |
| | demo UI + slides | | | | | ●●●●● | |
| | final demo + paper | | | | | | ●●●●● |
| **WebServer** | scaffold + plaintext | ●●●●● | | | | | |
| | HPKE handshake + verify | | ●●●●● | | | | |
| | ChaCha20 seal/open + del pln | | | ●●●●● | | | |
| | fix findings | | | | ●●●●● | | |
| | hardening + slides | | | | | ●●●●● | |
| | final demo + paper | | | | | | ●●●●● |
| **Red Team** | baseline + mitmproxy | ●●●●● | | | | | |
| | handshake/interop + MITM | | ●●●●● | | | | |
| | tamper + leak + Scenario C | | | ●●●●● | | | |
| | attack matrix (LEAD) | | | | ●●●●● | | |
| | security eval + reh. #1 | | | | | ●●●●● | |
| | TLS-vs-E2E + attack | | | | | | ●●●●● |
| **DELIVERABLES** | | | | | | |
| Live demo (rehearse →) | | | | | |· | XXX | ★FINAL |
| Slide deck | | | | | || XXX | ★FINAL |
| Paper | | | || | draft | XXX | ★FINAL |


### Project Basic Setup
```
cyber210-Browser-to-Server-e2e/
├── client
├── docs
├── evidence
├── scripts
└── server
```
#### Run the browser client 
```
cd client
npm install
npm run dev          
http://localhost:3000
```
#### Run the web server
```
cd server
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt          # or: pip install "fastapi[standard]" "uvicorn[standard]"
uvicorn main:app --reload --port 8000
http://localhost:8000/api/health
```