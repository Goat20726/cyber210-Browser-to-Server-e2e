# Red Team Evidence Run

Owner: Aura  
Run type: Local WSL / Docker Desktop  
Date: 2026-07-07  
Branch: aura-borealis-red-team-evidence  

## Goal

Capture evidence for TLS-only vs TLS + browser-to-server HPKE behavior in EchoVault WebSocket traffic.

## Evidence checklist

- [x] Environment verified
- [x] Local stack starts successfully
- [x] mitmproxy/mitmweb accessible
- [x] EchoVault client accessible
- [x] Server key verified
- [x] WebSocket established
- [x] TLS-only mode shows plaintext prompt-like traffic
- [x] E2E mode hides prompt content and shows ciphertext fields only
- [ ] Adversarial tests completed
- [ ] Logs checked for plaintext leakage

## Core findings so far

1. With Encrypt Off, mitmproxy can read the fake sensitive prompt inside the WebSocket frame.
2. With Encrypt On, mitmproxy can still observe WebSocket traffic, but prompt content is hidden in ciphertext fields.
3. Plaintext mode produced an additional server close/error: code 4001, malformed msg frame involving `seq` parsing.

## Evidence folders

- `00-environment/`
- `01-tls-only-plaintext/`
- `02-e2e-ciphertext/`
- `03-adversarial-tests/`
- `04-logs/`
