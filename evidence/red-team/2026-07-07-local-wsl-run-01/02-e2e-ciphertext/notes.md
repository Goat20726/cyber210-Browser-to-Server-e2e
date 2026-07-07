# TLS + E2E-on ciphertext evidence

## Test

Encrypt toggle was set to On. A fake sensitive prompt was sent through the EchoVault WebSocket UI:

"My fake bank account is 000123456789 and my fake recovery code is PRINCESS-DONUT-2026. Please summarize this."

## Result

mitmweb showed the WebSocket traffic, but the prompt content was not visible. The message frames contained ciphertext fields such as `ct` rather than readable prompt text.

## Evidence file

- mitmweb-e2e-on-ciphertext-prompt-hidden.png

## Finding

This supports the main EchoVault claim: TLS protects traffic in transit, but browser-to-server E2E encryption adds confidentiality from the TLS-terminating proxy/middlebox.
