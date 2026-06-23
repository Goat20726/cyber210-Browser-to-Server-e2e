# Threat Model

## Project Security Question

This project asks:

How does browser-to-server application-layer encryption change what intermediaries can see compared with TLS alone for sensitive LLM-style prompt traffic?

The demo compares three models:

1. Plaintext traffic
2. TLS-protected traffic
3. TLS plus browser-to-server application-layer encryption

The goal is not to replace TLS or build a production LLM gateway. The goal is to show how plaintext visibility changes depending on where encryption starts and where it ends.

## Protected Asset

The main asset we are protecting is sensitive prompt text typed by a user into a browser-based chat interface.

Example fake test prompt:

`My fake SSN is 123-45-6789 and my fake password is BlueTiger42.`

This is fake test data only. The demo should not use real passwords, real SSNs, real API keys, real personal data, or real sensitive prompts.

## Security Claim

TLS protects data while it travels between TLS endpoints. However, TLS alone does not protect the prompt after TLS terminates at a reverse proxy, gateway, web server, logging layer, or other backend service.

Browser-to-server application-layer encryption adds another layer of protection by encrypting the message before it leaves the browser. In the encrypted model, a TLS-terminating intermediary should see only application-layer ciphertext instead of the raw prompt.

The claim is narrow:

Application-layer encryption can reduce plaintext exposure at intermediaries.

The claim is not:

This system hides the prompt from the intended server.

The intended server application still decrypts the message.

## Trusted Components

For this demo, we treat these components as trusted:

| Component                              | Reason                                                                     |
| -------------------------------------- | -------------------------------------------------------------------------- |
| User browser                           | It creates or handles the prompt before encryption                         |
| Browser-side JavaScript/WebCrypto code | It performs browser-side key agreement and encryption                      |
| Intended server application process    | It is supposed to decrypt and echo the message                             |
| Server-side cryptographic code         | It performs server-side key agreement, decryption, and response encryption |

## Less-Trusted Components

For this demo, we treat these components as less trusted or potentially observable:

| Component                                        | Concern                                                   |
| ------------------------------------------------ | --------------------------------------------------------- |
| Network path                                     | Traffic may be captured by a passive observer             |
| Wireshark/passive packet observer                | Can inspect packets on the wire                           |
| Reverse proxy                                    | May terminate TLS or forward traffic                      |
| TLS-terminating gateway                          | Can see plaintext in a TLS-only design                    |
| mitmproxy with trusted CA                        | Simulates a TLS-terminating intermediary                  |
| Logging layer                                    | May accidentally log sensitive prompt text                |
| Backend service not intended to read raw prompts | May receive plaintext if encryption boundary is too early |

## Threat Actors / Observers

| Observer                      | Capability                                      | Why It Matters                                                                     |
| ----------------------------- | ----------------------------------------------- | ---------------------------------------------------------------------------------- |
| Passive network observer      | Can capture traffic but cannot terminate TLS    | Tests whether prompts are visible on the wire                                      |
| Wireshark user                | Can inspect packet captures                     | Shows plaintext or encrypted traffic at the packet level                           |
| TLS-terminating proxy         | Can decrypt TLS if trusted by the browser       | Represents reverse proxies, gateways, or enterprise inspection points              |
| mitmproxy with trusted CA     | Can inspect HTTPS traffic from the test browser | Lets us prove what a TLS-terminating intermediary can see                          |
| Intended server application   | Can decrypt the application-layer ciphertext    | Represents the only process that should read the raw prompt in the encrypted model |
| Attacker modifying ciphertext | Can tamper with encrypted messages in transit   | Tests whether AES-GCM authentication detects changes                               |

## In Scope

This project focuses on network security and traffic visibility.

In scope:

* Plaintext traffic visibility
* TLS-only traffic visibility
* TLS termination and proxy visibility
* Browser-to-server application-layer encryption
* Wireshark evidence
* mitmproxy evidence
* Tamper testing
* Logging/leak checks
* CIA triad analysis
* Trust boundary analysis

## Out Of Scope

This project does not attempt to solve every possible LLM security problem.

Out of scope:

* Compromised browser
* Malicious browser extension
* Malicious JavaScript served to the browser
* Compromised server after decryption
* Root/admin compromise of the server
* Key theft from browser or server memory
* Real LLM provider security
* Production-grade key management
* Long-term key storage
* User authentication
* Denial-of-service protection
* Prompt injection detection
* PII classification accuracy

## Important Wording

We should be careful with the phrase “end-to-end encryption.”

This demo is not end-to-end encryption in the same sense as Signal or iMessage, where only user devices can read the message.

A more accurate phrase is:

**Browser-to-application-server encryption layered on top of TLS**

or:

**Application-layer encryption between the browser and intended server process**

This is more precise because the server still decrypts the prompt.

## CIA Triad Analysis

### Confidentiality

Confidentiality is the main focus of this project.

Expected result:

* Plaintext model: prompt visible to passive observers
* TLS-only model: prompt hidden from passive observers but visible at TLS termination
* TLS plus app-layer encryption model: prompt hidden from passive observers and TLS-terminating intermediaries; visible only to the intended server application after decryption

### Integrity

Integrity is tested through tamper checks.

If AES-GCM is implemented correctly, modifying ciphertext should cause authentication failure. The server should reject the modified message instead of decrypting or echoing it.

### Availability

Availability is not the main goal of the project.

Application-layer encryption may add complexity and failure modes. For example, bad key exchange, broken nonce handling, or failed decryption could prevent messages from being processed. This design does not directly protect against denial-of-service attacks.

## Expected Security Boundary

The intended security boundary is:

Browser plaintext → browser encrypts → network/proxy sees ciphertext → intended server application decrypts

The point is to move the plaintext exposure boundary closer to the intended application process and away from intermediaries.
