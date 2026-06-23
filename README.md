# **CYBER 210: Protecting LLM Prompt Traffic Beyond TLS: A Browser-to-Server Encryption Demo** 

**Final Project Operating Document**  
Cameron Faulkner, Aura Gaines, and Fil Dziembowski

Modern LLM chat applications often send user prompts to a server over HTTPS/TLS. TLS protects the prompt while it travels across the network, but the prompt may still become readable after TLS terminates at a reverse proxy, gateway, web server, logging layer, or backend service.

This project studies whether adding browser-to-server application-layer encryption can reduce that plaintext exposure. We will use a simple browser chat interface and echo server as a stand-in for LLM prompt traffic. The browser will encrypt the message before sending it, and only the server process intended to read the message will decrypt and echo it back.

The goal is not to build a production LLM gateway or replace TLS. The goal is to compare what different observers can see in three models: plaintext traffic, TLS-protected traffic, and TLS plus application-layer encryption.

**Research question we are asking**: How does browser-to-server application-layer encryption change what intermediaries can see compared with TLS alone for sensitive LLM-style prompt traffic?  

![][image1]

Scope: This project focuses on demonstrating how sensitive prompt-like traffic changes as it moves through three security models: plaintext traffic, TLS-protected traffic, and TLS plus browser-to-server application-layer encryption. We will use a simple browser chat interface and echo server as a stand-in for LLM prompt traffic so the project stays focused on network security, traffic visibility, encryption boundaries, and threat modeling. 

This project includes:

- [ ] Web Page with chat-style UI that echos the text typed by the user  
- [ ] A web server hosting the page (using Python FastAPI and [Node.js](http://Node.js) with Websocket support)  
- [ ] A browser WebCrypto key-agreement handshake, allowing the browser to start an end-to-encryption channel  
- [ ] Authentication and encryption of messages in both directions  
- [ ] TLS Certificates for the web server  
- [ ] A live demo showing   
      - [ ] (a) plaintext on the wire  
      - [ ] (b) ciphertext protected by TLS  
      - [ ] (c) ciphertext protected by browser-to-server application-layer encryption   
- [ ] A written paper describing the threat model, including what this channel protects against and what it does not protect against 

This project does not attempt to build a production LLM gateway or connect to a real LLM provider; the echo server is used to keep the demo simple and focused on network security. 

Deliverables per week (6 Weeks) 25 JUL (giving us \~2 week fluff):

- [ ] W2 \- Protocol design document   
- [ ] W2 \- Working plain text echo (client / proxy / webserver architecture)  
- [ ] W3 \- Working encrypted echo, end to end   
- [ ] W4 \- Attack test suite (should be confirmed TLS certs, mitmproxy all operational)   
- [ ] W5 \- Final Paper / Presentation complete   
- [ ] W6 \- Final demo runs ≤5-10 min twice; deck \+ paper submitted

Team Roles:

Aura : Network Val / Threat   
Cam: Server / Protocol Lead   
 Fil: Client Lead

## 4. Team roles (3 members; everyone codes)

| Role | Owns | First task |
|---|---|---|
| **Browser** — Member A (Browser Encryption Integration) | Browser HPKE integration (`hpke-js`) + UI | Spike: round-trip an `hpke-js` sender/recipient `seal`/`open` in a console |
| **WebServer** — Member B (WebServer Encryption Integration) | Server HPKE (`pyhpke`) + WebSocket endpoint; same suite as the client | Spike: round-trip a `pyhpke` `seal`/`open`; echo a plaintext WebSocket message |
| **Red Team** — Member C | Attack tests, packet captures, the **mitmproxy TLS-vs-E2E demo**; **also runs the weekly checkpoint + repo hygiene** (the PM duties, since you're three); tries to break the other two every week | Spike: capture localhost WebSocket traffic in Wireshark/DevTools; set up repo + tracker |

Knowledge Management:

- [ ] 1x Github Repo [https://github.com/Goat20726/cyber210-Browser-to-Server-e2e](https://github.com/Goat20726/cyber210-Browser-to-Server-e2e) protected \`main\`, off weekX-integration PRs reviewed and merged with a slack notification when merge complete.  
- [ ] The Adversary lead gets veto power: if an attack they can demonstrate validity then we continue to iterate   
- [ ] Decision log: every protocol decision (curve, KDF, nonce strategy…) gets 3 lines in   \`docs/decisions.md\` — \*what we chose, what we rejected, why\*.  This will help our final paper  


                                   W1     W2     W3     W4     W5     W6
                                   Jun15  Jun22  Jun29  Jul06  Jul13  Jul20
 Browser    scaffold+plaintext     #####
            HPKE handshake               #####
            HPKE seal/open                       #####
            fix findings                                #####
            demo UI + slides                                  #####
            final demo + paper                                       #####
 WebServer  scaffold+plaintext     #####
            HPKE handshake               #####
            HPKE seal/open + del plain           #####
            fix findings                                #####
            hardening + slides                                #####
            final demo + paper                                       #####
 Red Team   baseline + mitmproxy   #####
            handshake/interop test       #####
            tamper + Scenario C                  #####
            attack matrix (LEAD)                        #####
            security eval + reh.#1                            #####
            TLS-vs-E2E + attack                                      #####

   Milestones:  M1^Jun19  M2^Jun26  M3^Jul03  M4^Jul10  M5^Jul17  M6^Jul24

