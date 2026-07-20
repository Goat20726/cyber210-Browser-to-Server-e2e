/* ============================================================================
 * BOREALIS ASSISTANT — chat front end, now with EchoVault E2E encryption
 * ============================================================================
 *
 * WHAT CHANGED vs the plain chat version?
 *   1) The mnemonic is loaded from the Identity page (localStorage "mnemonic")
 *      and turned into the browser's two key pairs (protocol.md §2).
 *   2) A "Server key" text box + Verify button: paste the server's Ed25519
 *      public key (the PIN printed in the server console). Verify fetches
 *      /pubkey and runs the §4.1.1 pin gate; a green stoplight means the
 *      served key matched your pin AND its signature checked out.
 *   3) After a green light, the page runs hexToBytesthe full EchoVault handshake
 *      (hello / server_hello, §4.2–§4.3) over the WebSocket. Only then is the
 *      encrypted channel "established" and the Encrypt toggle usable.
 *   4) When Encrypt is ON, every message you send is sealed in the browser
 *      (HPKE, ChaCha20-Poly1305) and every echo is opened in the browser —
 *      a TLS-terminating proxy sees only { type, seq, ct }.
 *
 * Extra npm packages this page needs (on top of the original):
 *   npm i @scure/bip39 @noble/hashes @noble/curves \
 *         @hpke/core @hpke/dhkem-x25519 @hpke/chacha20poly1305
 * ========================================================================== */

"use client";
import React, { useState, useEffect, useRef } from 'react';
import Link from "next/link";
import { validateMnemonic, mnemonicToSeed } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
// Crypto building blocks for EchoVault (same libraries the spec was tested with):
import { sha256 } from "@noble/hashes/sha2.js";              // hashing
import { extract, expand } from "@noble/hashes/hkdf.js";     // key derivation
import { ed25519, x25519 } from "@noble/curves/ed25519.js";  // signatures + DH keys
import { CipherSuite, HkdfSha256 } from "@hpke/core";        // HPKE seal/open
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";


/* ----------------------------------------------------------------------------
 * ECHOVAULT PROTOCOL CONSTANTS — frozen values from protocol.md §0 (D011/D013).
 * These byte strings MUST match the server character-for-character, or nothing
 * will decrypt. Think of them as the "dialect" both sides agreed to speak.
 * -------------------------------------------------------------------------- */
const te = new TextEncoder();
const HKDF_SALT = hexToBytes(
  "65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95",
);
const INFO_X25519 = te.encode("echovault-x25519-encryption");
const INFO_ED25519 = te.encode("echovault-ed25519-signing");
const HPKE_INFO = te.encode("echovault/hpke/v1");
const LABEL_PUBKEY = te.encode("echovault/pubkey/v1");
const LABEL_HELLO = te.encode("echovault/hello/v1");
const LABEL_SERVER_HELLO = te.encode("echovault/server_hello/v1");
const AAD_STATE = te.encode("echovault");
const DIR_C2S = te.encode("c2s"); // browser → server
const DIR_S2C = te.encode("s2c"); // server → browser
const TYPE_MSG = new Uint8Array([0x01]);

// The HPKE cipher suite: X25519 key agreement + SHA-256 KDF + ChaCha20-Poly1305.
const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Chacha20Poly1305(),
});

/* ----------------------------------------------------------------------------
 * SMALL BYTE HELPERS — encoding rules from protocol.md §6.
 * All binary goes on the wire as base64url WITHOUT padding; seq is 16-char hex.
 * -------------------------------------------------------------------------- */
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function b64u(raw: Uint8Array): string {
  let bin = "";
  raw.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Strict decoder: refuses standard base64 (+ / =) and wrong-length values.
function unb64u(s: string, expectedLen: number): Uint8Array {
  if (typeof s !== "string" || /[+/=]/.test(s)) throw new Error("bad encoding");
  const bin = atob(
    s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (s.length % 4)) % 4),
  );
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  if (expectedLen >= 0 && out.length !== expectedLen)
    throw new Error("bad length");
  if (b64u(out) !== s) throw new Error("bad encoding");  //Base64URL non-canonical encoding
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// hpke-js wants standalone ArrayBuffers, not views into shared memory.
function ab(u8: Uint8Array): ArrayBuffer {
  return u8.slice().buffer as ArrayBuffer;
}

function seqToBytes8(seq: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(seq), false);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// The 37-byte authentication label sealed into every message (protocol §3.1):
// app name ‖ session fingerprint ‖ direction ‖ frame type ‖ counter.
function buildAad(sessionId: Uint8Array, dir: Uint8Array, seq: number): Uint8Array {
  return concatBytes(AAD_STATE, sessionId, dir, TYPE_MSG, seqToBytes8(seq));
}

/* ----------------------------------------------------------------------------
 * IDENTITY — protocol.md §2: one mnemonic → two unrelated key pairs.
 * The mnemonic comes from the Identity page ("Key Vault"), which saved it in
 * localStorage under "mnemonic". Same words in = same keys out, every time.
 * -------------------------------------------------------------------------- */
interface Identity {
  xScalar: Uint8Array;  // X25519 private key (decrypts echoes sent to us)
  xPub: Uint8Array;     // X25519 public key (the server seals echoes TO this)
  edSeed: Uint8Array;   // Ed25519 private key (signs our half of the handshake)
  edPub: Uint8Array;    // Ed25519 public key (server checks our signature with this)
}

async function deriveIdentity(mnemonic: string): Promise<Identity> {
  // Standard BIP-39 words → 64-byte seed, then HKDF splits it into the two
  // independent keys using the frozen salt/labels above.
  const seed = await mnemonicToSeed(mnemonic, "");
  const prk = extract(sha256, seed, HKDF_SALT);
  const xScalar = expand(sha256, prk, INFO_X25519, 32);
  const edSeed = expand(sha256, prk, INFO_ED25519, 32);
  return {
    xScalar,
    xPub: x25519.getPublicKey(xScalar),
    edSeed,
    edPub: ed25519.getPublicKey(edSeed),
  };
}

/* ----------------------------------------------------------------------------
 * THE SHAPE OF DATA (unchanged from the original page)
 * -------------------------------------------------------------------------- */
type Sender = 'user' | 'assistant';

interface ChatMessage {
  id: number;         // render identity — unique for the page's lifetime.
                      // seq is NOT usable as a React key: it resets to 0 on
                      // every new session (plain↔secure switches, re-handshakes).
  seq: number;        // a counter/ID number for ordering messages (0, 1, 2, ...)
  text: string;       // the actual words of the message
  type: string;       // a label for the kind of message (e.g. 'msg')
  sender: Sender;     // who sent it: 'user' or 'assistant'
  timestamp: string;  // a human-readable time, e.g. "3:42:10 PM"
  encrypted: boolean; // wire framing: true → sealed {ct} block; false → {text}
                      // plaintext block, rendered in RED in the transcript
}

// Which wire mode the CURRENT WebSocket speaks:
//   'secure' → /ws       (HPKE, message blocks carry 'ct')
//   'plain'  → /ws/plain (E2E OFF,  message blocks carry 'text')
//   'none'   → no live socket
type WireMode = 'secure' | 'plain' | 'none';

// Traffic-light states for the server-key check.
type PinStatus = 'unchecked' | 'valid' | 'invalid';

/* ----------------------------------------------------------------------------
 * THE COMPONENT
 * -------------------------------------------------------------------------- */
export default function ChatApp() {

  /* ---------------------------- chat state ------------------------------ */
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isTyping, setIsTyping] = useState(false);

  // ---- Sequence state ----
  // c2sSeq : next client→server seq to send (must track the HPKE context's
  //          internal counter one-for-one, so ONLY advance it after a seal).
  // lastS2C: highest server→client seq already accepted. Starts at -1 so the
  //          first server frame (seq 0) is accepted. In encrypted mode the
  //          check is STRICT (must be exactly lastS2C+1): a gap or repeat is
  //          a protocol fault and tears the channel down (protocol §7.3).
  const c2sSeq = useRef<number>(0);
  const lastS2C = useRef<number>(-1);

  // Which protocol the live socket speaks (see WireMode above). Plaintext
  // frames are ONLY legal while this is 'plain'; on the secure channel a
  // 'text' frame is a fault that forces a brand-new secure connection.
  const wireMode = useRef<WireMode>('none');

  // Echo-gate for plaintext mode: number of plaintext transmits still
  // awaiting their echo. A plaintext echo that arrives when this is 0 was
  // NOT preceded by a plaintext transmit → it is dropped, never rendered.
  const plainPending = useRef<number>(0);

  // Monotonic id for React keys — never resets, unlike the per-session seq.
  const nextMsgId = useRef<number>(0);

  const socketRef = useRef<WebSocket | null>(null);
  const endRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const typingTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* ------------------------- EchoVault state ---------------------------- */
  // The pasted server public key (Ed25519, base64url) — the PIN. This is the
  // demo's out-of-band trust root: it must come to you OUTSIDE the connection
  // (the server prints it in its own console at startup).
  const [serverPinInput, setServerPinInput] = useState('sQZN15q8euUzuIcJ6D1t99BR-ltN078vmHq_LJYwpPM');
  // Traffic light: did the served /pubkey match the pasted pin + valid signature?
  const [pinStatus, setPinStatus] = useState<PinStatus>('unchecked');
  const [hasSavedMnemonic, setHasSavedMnemonic] = useState(false);
  const [channelEstablished, setEncChannel] = useState(false);
  const [encrypt, setEncrypt] = useState(true);
  const [statusNote, setStatusNote] = useState('');

  // The mnemonic itself, loaded from the Identity page's saved variable.
  const mnemonicRef = useRef<string>('');

  // Everything crypto about the CURRENT link lives in this one box. It's a
  // ref (not state) because none of it should redraw the screen, and it must
  // never be half-updated: teardown wipes it all at once.
  const link = useRef<{
    identity: Identity | null;                                            // our keys
    pinnedEd: Uint8Array | null;                                          // trusted server signing key
    pinnedX: Uint8Array | null;                                           // server encryption key (adopted via §4.1.1)
    sender: Awaited<ReturnType<CipherSuite["createSenderContext"]>> | null;   // seals c2s
    recipient: Awaited<ReturnType<CipherSuite["createRecipientContext"]>> | null; // opens s2c
    sessionId: Uint8Array | null;                                         // this handshake's fingerprint
    tHello: Uint8Array | null;                                            // our signed hello bytes
  }>({ identity: null, pinnedEd: null, pinnedX: null, sender: null, recipient: null, sessionId: null, tHello: null });

  /* ---------------------------- auto-scroll ----------------------------- */
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isTyping]);

  /* --------------- load the mnemonic from the Identity page ------------- */
  // The Identity page ("Key Vault") stores the mnemonic in localStorage under
  // the key "mnemonic". We load it once, validate the words, and derive the
  // browser's key pairs from it. No mnemonic → no identity → the Verify /
  // handshake path below refuses to run (fail closed).
  useEffect(() => {
    const savedMnemonic = localStorage.getItem("mnemonic") ?? "";
    if (savedMnemonic.trim() && validateMnemonic(savedMnemonic.trim(), wordlist)) {
      mnemonicRef.current = savedMnemonic.trim();
      setHasSavedMnemonic(true);
      deriveIdentity(mnemonicRef.current)
        .then((id) => { link.current.identity = id; })
        .catch(() => setHasSavedMnemonic(false));
    } else {
      setHasSavedMnemonic(false);
    }
  }, []);

  // Hang up the phone line if the user leaves the page.
  useEffect(() => {
    return () => {
      if (typingTimeout.current) clearTimeout(typingTimeout.current);
      socketRef.current?.close();
    };
  }, []);

  /* ------------------------------ teardown ------------------------------ */
  // EchoVault is fail-closed (protocol §7.3/§7.4): on ANY fault — bad
  // signature, wrong counter, tampered ciphertext, unexpected frame — we
  // abandon the whole encrypted channel and require a fresh Verify+handshake.
  // We never try to "keep going" on a connection we no longer trust.
  const teardown = (note: string) => {
    socketRef.current?.close();
    socketRef.current = null;
    link.current.sender = null;
    link.current.recipient = null;
    link.current.sessionId = null;
    link.current.tHello = null;
    c2sSeq.current = 0;
    lastS2C.current = -1;
    wireMode.current = 'none';
    plainPending.current = 0;
    setEncChannel(false);
    setIsConnected(false);
    setIsTyping(false);
    setStatusNote(note);
  };

  /* -------------------- server base URLs (HTTP + WS) -------------------- */
// One env var, HTTP-flavored. For your mitmproxy setup:
//   NEXT_PUBLIC_API_URL=https://echo.server.test
const httpBase =
  process.env.NEXT_PUBLIC_API_URL ??
  (typeof window !== 'undefined' && window.location.protocol === 'https:'
    ? `https://${window.location.host}`
    : 'http://localhost:8000');

// The WS base is DERIVED: https→wss, http→ws. Same host, same TLS decision.
const wsBase =
  process.env.NEXT_PUBLIC_WS_URL ?? httpBase.replace(/^http/, 'ws');

  /* ------------------- VERIFY BUTTON: the §4.1.1 pin gate ---------------- */
  // What happens when you click Verify, in plain English:
  //   1. Take the key YOU pasted (the pin) — that is the only thing we trust.
  //   2. Fetch /pubkey from the server. Whatever comes back is UNTRUSTED
  //      input; it exists only so we can compare it against the pin.
  //   3. Compare the served signing key to the pin, byte for byte. Mismatch
  //      → red light, stop. (A middleman swapping keys is caught right here.)
  //   4. Check the signature over the served keys using the pinned key. This
  //      proves the encryption key really belongs to the pinned identity.
  //   5. Only then adopt the server's encryption key and light up GREEN.
  // After the green light we immediately run the handshake to establish the
  // encrypted channel (see establishChannel below).
  const handleVerify = async () => {
    try {
      setStatusNote('');
      if (!link.current.identity) {
        setPinStatus('unchecked');
        setStatusNote('No valid mnemonic — create one on the Key Vault page first.');
        return;
      }
      const pinText = serverPinInput.trim();
      if (!pinText) {
        // No pin provisioned → refuse to handshake at all (fail closed, §4.1.1).
        setPinStatus('unchecked');
        setStatusNote('Paste the server public key (printed in the server console).');
        return;
      }
      const pinnedEd = unb64u(pinText, 32);

      const res = await fetch(`${httpBase}/pubkey`);
      const pk = await res.json();
      const wireEd = unb64u(pk.server_ed25519, 32);
      const wireX = unb64u(pk.server_x25519, 32);
      const sig = unb64u(pk.sig, 64);

      // Step 3 — pin comparison FIRST. The wire never teaches us a new key.
      if (!bytesEqual(wireEd, pinnedEd)) throw new Error('pin mismatch');

      // Step 4 — signature over label ‖ encryption key ‖ signing key.
      const tPubkey = concatBytes(LABEL_PUBKEY, wireX, wireEd);
      if (!ed25519.verify(sig, tPubkey, pinnedEd)) throw new Error('bad sig');

      // Step 5 — adopt the encryption key, bound to the pinned identity.
      link.current.pinnedEd = pinnedEd;
      link.current.pinnedX = wireX;
      setPinStatus('valid');
      setStatusNote('Server key verified against pin — establishing encrypted channel…');

      await establishChannel();
    } catch {
      // One uniform failure path: red light, no channel, no detail an
      // attacker could learn from.
      link.current.pinnedEd = null;
      link.current.pinnedX = null;
      setPinStatus('invalid');
      teardown('Server key verification failed — channel not established.');
    }
  };

  /* --------------- THE HANDSHAKE: hello / server_hello ------------------ */
  // Runs only after the green light. In plain English:
  //   1. Create our outgoing encryption "pipe" aimed at the verified server
  //      key; this mints a one-time key share ("enc") to send along.
  //   2. Sign a transcript of everything that matters (our keys, our enc,
  //      and the PINNED server keys) and send it as "hello".
  //   3. Wait for "server_hello". Rebuild the transcript the server should
  //      have signed — from OUR OWN values and the PIN, never from the wire —
  //      and check the signature with the pinned key. If a middleman swapped
  //      anything (even just our own key on its way to the server!), this
  //      check fails and we abort BEFORE any message is ever sealed (§4.3.1).
  //   4. Derive the session fingerprint and open our incoming pipe. Done:
  //      the Encrypt toggle comes alive.
  const establishChannel = async () => {
    const id = link.current.identity!;
    const pinnedX = link.current.pinnedX!;
    const pinnedEd = link.current.pinnedEd!;

    // Fresh counters for a fresh handshake (a new session restarts at 0).
    c2sSeq.current = 0;
    lastS2C.current = -1;

    // Step 1 — outgoing pipe + one-time key share.
    const serverPk = await suite.kem.importKey("raw", ab(pinnedX), true);
    const sender = await suite.createSenderContext({
      recipientPublicKey: serverPk,
      info: ab(HPKE_INFO),
    });
    const enc = new Uint8Array(sender.enc);

    // Step 2 — signed hello transcript (§4.2).
    const tHello = concatBytes(LABEL_HELLO, id.xPub, id.edPub, enc, pinnedX, pinnedEd);
    const helloSig = ed25519.sign(tHello, id.edSeed);

    const ws = new WebSocket(`${wsBase}/ws`);
    socketRef.current = ws;
    wireMode.current = 'secure';
    link.current.sender = sender;
    link.current.tHello = tHello;

    ws.onopen = () => {
      setIsConnected(true);
      ws.send(JSON.stringify({
        type: "hello",
        browser_x25519: b64u(id.xPub),
        browser_ed25519: b64u(id.edPub),
        enc: b64u(enc),
        sig: b64u(helloSig),
      }));
    };
    ws.onerror = () => teardown('Connection error.');
    ws.onclose = (event) => {
      if (socketRef.current !== ws) return;
      setIsConnected(false);
      setEncChannel(false);
      // Server detected plaintext on the secure channel (close 4001 with a
      // "plaintext..." reason): the old session is dead by design. Validate
      // the requirement by RE-ESTABLISHING a brand-new secure connection —
      // full pin re-verify + fresh handshake, never a resumed session.
      if (event.code === 4001 && /plaintext/i.test(event.reason)) {
        teardown('Plaintext detected on secure channel — re-establishing a NEW secure connection…');
        void handleVerify();
      }
    };
    ws.onmessage = (event) => {
      handleFrame(event.data as string).catch((err: unknown) => {
        if (err instanceof Error && err.message === 'PLAINTEXT_ON_SECURE') {
          // A plaintext echo showed up on the encrypted channel: never render
          // it; tear down and re-establish a new secure connection.
          teardown('Plaintext frame on secure channel — re-establishing a NEW secure connection…');
          void handleVerify();
          return;
        }
        teardown('Encrypted channel fault — torn down. Verify again to reconnect.');
      });
    };
  };

  /* ---------------- PLAINTEXT MODE (E2E OFF, /ws/plain) ------------------ */
  // Deliberately mirrors establishChannel but with NO crypto: message blocks
  // carry 'text' instead of 'ct', and every frame is rendered in RED. Used
  // for the mitmproxy comparison exhibit. Any secure-session material is
  // wiped first (teardown) so plaintext use can never touch HPKE state.
  const connectPlain = () => {
    teardown('');
    const ws = new WebSocket(`${wsBase}/ws/plain`);
    socketRef.current = ws;
    wireMode.current = 'plain';

    ws.onopen = () => {
      setIsConnected(true);
      setStatusNote('⚠ PLAINTEXT mode — messages are NOT end-to-end encrypted (TLS only).');
    };
    ws.onerror = () => teardown('Connection error.');
    ws.onclose = () => {
      if (socketRef.current === ws) {
        setIsConnected(false);
        wireMode.current = 'none';
      }
    };
    ws.onmessage = (event) => {
      handleFrame(event.data as string).catch(() =>
        teardown('Plaintext channel fault — connection closed.'),
      );
    };
  };

  /* ----------------------- ENCRYPT TOGGLE HANDLER ------------------------ */
  // OFF → drop the secure channel entirely and speak plaintext on /ws/plain.
  // ON  → plaintext was (or may have been) used in between, so the previous
  //       secure session is treated as burned: run the FULL Verify + handshake
  //       again and mint a brand-new secure connection (new enc, new session
  //       id, counters back to 0). We never resume across a plaintext gap.
  const handleEncryptToggle = async (checked: boolean) => {
    setEncrypt(checked);
    if (!checked) {
      connectPlain();
    } else {
      teardown('Re-establishing a new secure connection after plaintext use…');
      await handleVerify();
    }
  };

  /* --------------- INCOMING FRAMES (handshake + sealed msgs) ------------- */
  const handleFrame = async (raw: string) => {
    const L = link.current;
    const data = JSON.parse(raw);
    if (typeof data !== 'object' || data === null) throw new Error('bad frame');

    // The server's uniform rejection — it already tore the link down.
    if (data.type === 'error') throw new Error('server rejected');

    // ------------------- PLAINTEXT MODE (/ws/plain) ------------------------
    // Message blocks here carry 'text' (never 'ct'). Two gates:
    //   1. a 'ct' frame on the plain channel is a protocol mix-up → fault;
    //   2. a plaintext echo is accepted ONLY if a plaintext transmit is
    //      still outstanding (plainPending > 0) — an unsolicited plaintext
    //      echo is dropped and never reaches the transcript.
    if (wireMode.current === 'plain') {
      if (data.type !== 'msg' || typeof data.text !== 'string' || typeof data.ct === 'string')
        throw new Error('bad plaintext frame');
      if (plainPending.current <= 0) {
        setStatusNote('Dropped unsolicited plaintext echo (no plaintext transmit outstanding).');
        return;
      }
      plainPending.current -= 1;
      setIsTyping(false);
      const incoming: ChatMessage = {
        id: nextMsgId.current++,
        seq: typeof data.seq === 'number' ? data.seq : lastS2C.current + 1,
        text: data.text,
        type: 'msg',
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString(),
        encrypted: false,           // → rendered RED in the transcript
      };
      lastS2C.current = incoming.seq;
      setMessages((prev) => [...prev, incoming]);
      return;
    }

    // -------- waiting for server_hello (strict state machine, §5.6) --------
    if (L.recipient === null) {
      if (data.type !== 'server_hello') throw new Error('wrong frame for phase');
      const encS2c = unb64u(data.enc, 32);
      const sig = unb64u(data.sig, 64);

      // Step 3 of the handshake (see establishChannel comment): rebuild the
      // transcript from our own material + the pin, verify with the pin.
      const tServerHello = concatBytes(
        LABEL_SERVER_HELLO, encS2c, L.identity!.xPub, L.identity!.edPub,
        L.pinnedX!, L.pinnedEd!,
      );
      if (!ed25519.verify(sig, tServerHello, L.pinnedEd!))
        throw new Error('server_hello rejected');

      // Step 4 — session fingerprint + incoming pipe. Channel is live.
      L.sessionId = sha256(concatBytes(L.tHello!, tServerHello)).slice(0, 16);
      const myPriv = await suite.kem.importKey("raw", ab(L.identity!.xScalar), false);
      L.recipient = await suite.createRecipientContext({
        recipientKey: myPriv,
        enc: ab(encS2c),
        info: ab(HPKE_INFO),
      });
      setEncChannel(true);
      setStatusNote('Encrypted channel established.');
      return;
    }

    // ----------------------- established: sealed msg -----------------------
    if (data.type !== 'msg') throw new Error('wrong frame for phase');

    setIsTyping(false);

    if (typeof data.ct === 'string') {
      // ENCRYPTED echo. The counter must be EXACTLY the next one (16-char
      // lowercase hex). Anything else — repeat, gap, garbage — is a fault.
      if (typeof data.seq !== 'string' || !/^[0-9a-f]{16}$/.test(data.seq))
        throw new Error('malformed seq');
      const seq = parseInt(data.seq, 16);
      if (seq !== lastS2C.current + 1) throw new Error('seq gate');

      // Rebuild the authentication label from what WE know and open the
      // ciphertext. Wrong session, direction, type, counter, or a single
      // flipped bit → open() throws → teardown (caught by the caller).
      const ct = unb64u(data.ct, -1);
      if (ct.length < 16) throw new Error('bad ct');
      const aad = buildAad(L.sessionId!, DIR_S2C, seq);
      const pt = await L.recipient.open(ab(ct), ab(aad));
      lastS2C.current = seq;

      const incoming: ChatMessage = {
        id: nextMsgId.current++,
        seq,
        text: new TextDecoder().decode(pt),
        type: 'msg',
        sender: 'assistant',
        timestamp: new Date().toLocaleTimeString(),
        encrypted: true,            // sealed 'ct' block — normal styling
      };
      setMessages((prev) => [...prev, incoming]);
      return;
    }

    // A 'text' (plaintext) message block on the SECURE channel. This replaces
    // the old permissive legacy path: plaintext is never rendered here, and
    // the fault forces a brand-new secure connection (see ws.onmessage catch).
    throw new Error('PLAINTEXT_ON_SECURE');
  };

  /* ------------------------------ SENDING -------------------------------- */
  const handleSend = async (e?: React.FormEvent) => {
    e?.preventDefault();

    const text = inputValue.trim();
    if (!text) return;

    const ws = socketRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      setStatusNote('Not connected — verify the server key first.');
      return;
    }

    const currentSeq = c2sSeq.current;
    const sendingEncrypted =
      wireMode.current === 'secure' && encrypt && channelEstablished &&
      !!link.current.sender && !!link.current.sessionId;

    // What we show in OUR OWN transcript (always the readable words — it's our
    // message; encryption only changes what goes over the wire). The
    // 'encrypted' flag drives the RED plaintext highlight.
    const localEcho: ChatMessage = {
      id: nextMsgId.current++,
      seq: currentSeq,
      text,
      type: 'msg',
      sender: 'user',
      timestamp: new Date().toLocaleTimeString(),
      encrypted: sendingEncrypted,
    };

    try {
      if (sendingEncrypted) {
        // ENCRYPTED path: build the authentication label for "browser→server,
        // message, counter N", seal the text, and put ONLY {type, seq, ct} on
        // the wire. A proxy that terminates TLS sees ciphertext, not words.
        const aad = buildAad(link.current.sessionId!, DIR_C2S, currentSeq);
        const ct = new Uint8Array(
          await link.current.sender!.seal(ab(te.encode(text)), ab(aad)),
        );
        ws.send(JSON.stringify({
          type: 'msg',
          seq: currentSeq.toString(16).padStart(16, '0'),
          ct: b64u(ct),
        }));
      } else if (wireMode.current === 'plain') {
        // PLAINTEXT path (E2E OFF, /ws/plain only) — the TLS-only comparison
        // mode from the threat model. The message block carries 'text' where
        // the secure channel carries 'ct'. Registering the transmit in
        // plainPending is what LICENSES the matching echo: without it the
        // incoming plaintext echo would be dropped by handleFrame.
        ws.send(JSON.stringify({ type: 'msg', seq: currentSeq, text }));
        plainPending.current += 1;
      } else {
        // Mode mismatch (e.g. Encrypt is ON but the channel is not
        // established). Fail closed: never silently downgrade to plaintext.
        setStatusNote('Channel not ready — toggle Encrypt or press Verify to reconnect.');
        return;
      }
    } catch {
      teardown('Failed to seal message — channel torn down.');
      return;
    }

    // Optimistically render our own message immediately.
    setMessages((prev) => [...prev, localEcho]);
    setInputValue('');

    // Advance the counter only AFTER a successful seal+send, so it stays in
    // lock-step with the encryption pipe's internal counter.
    c2sSeq.current += 1;

    setIsTyping(true);
    if (typingTimeout.current) clearTimeout(typingTimeout.current);
    typingTimeout.current = setTimeout(() => setIsTyping(false), 12000);

    if (textareaRef.current) textareaRef.current.style.height = 'auto';
  };

  /* --------------------- keyboard + auto-grow (unchanged) ---------------- */
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value);
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  };

  /* ========================================================================
   * THE VISIBLE LAYOUT (HTML / JSX)
   * ====================================================================== */
  return (
    <div className="cg-app">
      <div className="cg-window">

        {/* ---------- Header ---------- */}
        <header className="cg-header">
          <div className="cg-brand">
            <div className="cg-logo">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                <path
                  d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                  fill="#fff"
                />
                <circle cx="18.5" cy="17.5" r="1.6" fill="#fff" />
                <circle cx="6" cy="16" r="1.1" fill="#fff" />
              </svg>
            </div>

            <div className="cg-titles">
              <h1 className="cg-title">Borealis Assistant</h1>
              <span className={`cg-status ${isConnected ? 'on' : 'off'}`}>
                <span className="cg-dot" />
                {isConnected ? 'Online' : 'Connecting…'}
              </span>
            </div>
          </div>
          <div className="cg-header-actions">
            {/* The Encrypt switch. OFF drops to the plaintext demo channel
                (/ws/plain); switching back ON always re-runs Verify and mints
                a brand-new secure connection — a session that saw plaintext
                in between is never resumed. */}
            <label className="cg-toggle" title="Toggle browser-side HPKE encryption">
              <span>Encrypt</span>
              <input
                type="checkbox"
                checked={encrypt}
                onChange={(e) => { void handleEncryptToggle(e.target.checked); }}
              />
              <span className="cg-toggle-track"><span className="cg-toggle-thumb" /></span>
              <span className="cg-toggle-state">{encrypt ? 'On' : 'Off'}</span>
            </label>

            <a className="cg-mnemonic-btn" href="/identity">Key Vault</a>
          </div>
        </header>

        {/* ---------- Key bar: identity + server-key verification ---------- */}
        <div className="cg-keybar">
          {/* Light 1: does the Identity page have a valid saved mnemonic? */}
          <span className="cg-keychip">
            <span className={`cg-light ${hasSavedMnemonic ? "green" : "red"}`} />
            Mnemonic Saved
          </span>

          {/* Light 2: the /pubkey stoplight. Green ONLY after the served key
              matched the pasted pin byte-for-byte AND its signature verified. */}
          <span className="cg-keychip">
            <span
              className={`cg-light ${
                pinStatus === 'valid' ? 'green' : pinStatus === 'invalid' ? 'red' : ''
              }`}
              style={pinStatus === 'unchecked' ? { background: '#999' } : undefined}
            />
            Server Key {pinStatus === 'valid' ? 'Verified' : pinStatus === 'invalid' ? 'REJECTED' : 'Unverified'}
          </span>

          {/* Light 3: is the end-to-end channel actually up? */}
          <span className="cg-keychip">
            <span className={`cg-light ${channelEstablished ? "green" : "red"}`} />
            E2E Channel
          </span>
        </div>

        {/* The pin box + Verify button. Paste the base64url Ed25519 key the
            server printed at startup. This must reach you OUT-OF-BAND (read
            it off the server console yourself) — never trust a key the
            network handed you. */}
        <div
          className="cg-pinbar"
          style={{ display: 'flex', gap: 8, alignItems: 'center', padding: '8px 16px' }}
        >
          <input
            value={serverPinInput}  className="cg-input"
            onChange={(e) => { setServerPinInput(e.target.value); setPinStatus('unchecked'); }}
            placeholder="Paste server public key (Ed25519, base64url) from server console"
            style={{ flex: 1, fontFamily: 'monospace', fontSize: 12, padding: '6px 10px' }}
            spellCheck={false}
          />
          <button className="cg-mnemonic-btn"
            type="button"
            onClick={handleVerify}
            disabled={!hasSavedMnemonic}
            title={hasSavedMnemonic ? 'Verify against /pubkey and connect' : 'Save a mnemonic on the Key Vault page first'}
          >
            Verify
          </button>
        </div>
        {statusNote && (
          <p style={{ margin: '0 16px 8px', fontSize: 12, opacity: 0.8 }}>{statusNote}</p>
        )}

        {/* ---------- Transcript ---------- */}
        <div className="cg-transcript">

          {messages.length === 0 && !isTyping && (
            <div className="cg-empty">
              <div className="cg-empty-orb">
                <svg viewBox="0 0 24 24" width="34" height="34" fill="none">
                  <path
                    d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                    fill="#fff"
                  />
                </svg>
              </div>
              <h2 className="cg-empty-title">How can I help you today?</h2>
              <p className="cg-empty-sub">
                Ask me anything — your conversation starts here.
              </p>
            </div>
          )}

          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`cg-row ${msg.sender}`}
            >
              <div className={`cg-avatar ${msg.sender}`}>
                {msg.sender === 'assistant' ? (
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                    <path
                      d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                      fill="#fff"
                    />
                  </svg>
                ) : (
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                    <circle cx="12" cy="8" r="3.4" fill="#fff" />
                    <path
                      d="M4.5 19c.8-3.4 3.7-5 7.5-5s6.7 1.6 7.5 5"
                      stroke="#fff"
                      strokeWidth="2"
                      strokeLinecap="round"
                      fill="none"
                    />
                  </svg>
                )}
              </div>

              {/* Plaintext ('text') message blocks get the red treatment so a
                  glance at the transcript shows what was NOT encrypted. */}
              <div className={`cg-bubble${msg.encrypted ? '' : ' plain'}`}>
                {!msg.encrypted && (
                  <div className="cg-plain-badge">⚠ plaintext — not encrypted</div>
                )}
                <div className={`cg-text${msg.encrypted ? '' : ' plain'}`}>{msg.text}</div>
                <div className="cg-time">{msg.timestamp}</div>
              </div>
            </div>
          ))}

          {isTyping && (
            <div className="cg-row assistant">
              <div className="cg-avatar assistant">
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                  <path
                    d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                    fill="#fff"
                  />
                </svg>
              </div>
              <div className="cg-bubble cg-typing">
                <span className="cg-typing-dot" />
                <span className="cg-typing-dot" />
                <span className="cg-typing-dot" />
              </div>
            </div>
          )}

          <div ref={endRef} />
        </div>

        {/* ---------- Composer ---------- */}
        <form className="cg-composer" onSubmit={handleSend}>
          <div className="cg-inputwrap">
            <textarea
              ref={textareaRef}
              rows={1}
              value={inputValue}
              onChange={handleInput}
              onKeyDown={handleKeyDown}
              placeholder="Message Borealis…"
              className="cg-input"
            />

            <button
              type="submit"
              className="cg-send"
              disabled={!inputValue.trim()}
              aria-label="Send message"
            >
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                <path
                  d="M12 19V5M12 5l-6 6M12 5l6 6"
                  stroke="currentColor"
                  strokeWidth="2.2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>
            </button>
          </div>

          <p className="cg-footnote">
            Borealis can make mistakes. Press <kbd>Enter</kbd> to send ·{' '}
            <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line.
          </p>
        </form>
      </div>
    </div>
  );
}
