# TLS-only / E2E-off plaintext evidence

## Test

Encrypt toggle was set to Off. A fake sensitive prompt was sent through the EchoVault WebSocket UI:

"My fake SSN is 123-45-6789 and my fake password is Redwood!2026. Please summarize this."

## Result

mitmweb showed the plaintext prompt inside the WebSocket frame.

## Evidence file

- mitmweb-e2e-off-plaintext-prompt-visible.png

## Additional observation

After the plaintext message, the server closed the connection with code 4001 and the message:

"malformed msg frame: int() can't convert non-string with explicit base"

This appears to be a plaintext-mode/protocol handling bug or mismatch. It does not change the confidentiality finding, because the plaintext prompt was visible to mitmproxy before the close occurred.
