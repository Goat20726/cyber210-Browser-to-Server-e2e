# Attack/Test Matrix

This file tracks the tests for the Network Validation / Threat Model lane.

The goal is to compare what different observers can see in three models:

1. Plaintext traffic
2. TLS-only traffic
3. TLS plus browser-to-server application-layer encryption

## Standard Test Prompt

Use fake data only:

`My fake SSN is 123-45-6789 and my fake password is BlueTiger42.`

Do not use real passwords, real SSNs, real API keys, real personal data, or real sensitive prompts.

## Test Matrix

| Test ID | Security Model             | Observer / Tool              | Test Goal                                                    | Expected Visibility                                                     | Evidence Status | Evidence Notes                                          |
| ------- | -------------------------- | ---------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------- | --------------- | ------------------------------------------------------- |
| T1      | Plaintext HTTP/WebSocket   | Wireshark / passive observer | Confirm raw prompt is visible without encryption             | Raw prompt should be visible on the wire                                | Not started     | Need Wireshark screenshot showing prompt text           |
| T2      | Plaintext HTTP/WebSocket   | mitmproxy                    | Confirm proxy can see raw prompt in plaintext model          | Raw prompt should be visible                                            | Not started     | Need mitmproxy screenshot showing prompt text           |
| T3      | TLS only                   | Wireshark / passive observer | Confirm passive observer cannot read prompt protected by TLS | Prompt should not be visible; observer should see TLS records           | Not started     | Need Wireshark screenshot showing encrypted TLS traffic |
| T4      | TLS only                   | mitmproxy with trusted CA    | Confirm TLS-terminating proxy can read prompt                | Raw prompt should be visible after TLS termination                      | Not started     | Need mitmproxy screenshot showing prompt text           |
| T5      | TLS + app-layer encryption | Wireshark / passive observer | Confirm passive observer cannot read prompt                  | Prompt should not be visible; observer should see TLS records           | Not started     | Need Wireshark screenshot                               |
| T6      | TLS + app-layer encryption | mitmproxy with trusted CA    | Confirm TLS-terminating proxy cannot read raw prompt         | Proxy should see application-layer ciphertext, not raw prompt           | Not started     | Need mitmproxy screenshot showing ciphertext            |
| T7      | TLS + app-layer encryption | Intended server application  | Confirm intended server can decrypt message                  | Server should decrypt and echo the prompt                               | Not started     | Need server log or app output                           |
| T8      | TLS + app-layer encryption | Browser client               | Confirm browser can decrypt response                         | Browser should display decrypted echo response                          | Not started     | Need browser screenshot                                 |
| T9      | Tampered ciphertext        | Server application           | Confirm ciphertext modification is detected                  | Server should reject modified ciphertext or show authentication failure | Not started     | Need server error/log screenshot                        |
| T10     | Logging leak check         | Proxy/server logs            | Check whether raw prompt appears in unexpected logs          | Raw prompt should not appear in proxy logs during encrypted model       | Not started     | Need log review notes/screenshots                       |

## Observer Summary

| Observer                            | Plaintext Model             | TLS-Only Model                           | TLS + App-Layer Encryption Model                          |
| ----------------------------------- | --------------------------- | ---------------------------------------- | --------------------------------------------------------- |
| Passive network observer            | Can see raw prompt          | Cannot see raw prompt                    | Cannot see raw prompt                                     |
| Wireshark                           | Can show raw prompt         | Shows TLS records only                   | Shows TLS records only                                    |
| mitmproxy without trusted CA        | May see connection metadata | Cannot decrypt TLS payload               | Cannot decrypt TLS payload                                |
| mitmproxy with trusted CA           | Can see raw prompt          | Can see raw prompt after TLS termination | Should see ciphertext only                                |
| Reverse proxy / TLS gateway         | Can see raw prompt          | Can see raw prompt after TLS termination | Should see ciphertext only if app encryption is preserved |
| Intended server application         | Can see raw prompt          | Can see raw prompt                       | Can decrypt and see raw prompt                            |
| Compromised browser                 | Out of scope                | Out of scope                             | Out of scope                                              |
| Compromised server after decryption | Out of scope                | Out of scope                             | Out of scope                                              |

## Evidence Collection Plan

For each test, collect:

* Tool used
* Date/time
* Security model tested
* Test prompt used
* Screenshot or log output
* What was visible
* What was not visible
* Why the result matters

## Evidence Folder Plan

Suggested folder structure:

```text
evidence/
  01_plaintext/
    notes.md
    wireshark_screenshot.png
    mitmproxy_screenshot.png

  02_tls_only/
    notes.md
    wireshark_screenshot.png
    mitmproxy_screenshot.png

  03_tls_plus_app_encryption/
    notes.md
    wireshark_screenshot.png
    mitmproxy_screenshot.png
    browser_screenshot.png

  04_tamper_tests/
    notes.md
    server_error_screenshot.png

  05_logging_leak_check/
    notes.md
    log_screenshot.png
```

## Test Notes Template

Use this template when adding evidence later:

```text
Test ID:
Date/time:
Security model:
Tool:
Test prompt:
Expected result:
Observed result:
Raw prompt visible? yes/no
Ciphertext visible? yes/no
Screenshot/log path:
Notes:
```

## Current Status

| Area                            | Status                       |
| ------------------------------- | ---------------------------- |
| ZeroTier access                 | Mostly complete              |
| SSH access                      | Complete                     |
| Wireshark setup                 | Needs confirmation           |
| mitmproxy setup                 | Mostly complete              |
| mitmproxy CA                    | Pending                      |
| Plaintext demo                  | Waiting on demo availability |
| TLS-only demo                   | Waiting on demo availability |
| TLS + app-layer encryption demo | Waiting on demo availability |
| Evidence screenshots            | Not started                  |

## Main Security Claim To Validate

The key claim is not that the prompt is hidden from the final server.

The intended server still decrypts the prompt.

The claim is narrower:

**Browser-to-server application-layer encryption can reduce plaintext exposure at intermediaries, especially TLS-terminating proxies, gateways, and logging layers.**
