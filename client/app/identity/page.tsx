/* ============================================================================
 * IDENTITY PAGE — app/identity/page.tsx
 * ============================================================================

 * ========================================================================== */

"use client";

import React, { useState, useEffect } from "react";
import { validateMnemonic, entropyToMnemonic, mnemonicToSeed} from "@scure/bip39";
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js'; 
import { bytesToHex } from '@noble/hashes/utils.js';
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { CipherSuite, KemId, KdfId, AeadId } from "hpke-js"; // Successfully imports!
import Link from "next/link";
import { useRouter } from "next/navigation";


export default function IdentityPage() {
  const router = useRouter(); // Initialize the router instance
  // The mnemonic shown in the textarea.
  const [mnemonic, setMnemonic] = useState("");
  const [hasSavedMnemonic, setHasSavedMnemonic] = useState(false);
  // A small status message under the buttons.
  const [note, setNote] = useState("");
  // DEBUG STATES: Track derived variables for the inspect panel
  const [debugData, setDebugData] = useState<{
        masterSeedHex: string,
        hexSalt: string,
        info_x25: string,
        info_ed25: string,
        sk_x25519: string,
        pk_x25519: string,
        sk_ed25519: string,
        pk_ed25519: string,
    
  } | null>(null);
  // On open, load whatever is already saved so the lights/textarea reflect it.
  useEffect(() => {

    setMnemonic(localStorage.getItem("mnemonic") ?? "");
  }, []);


  /* --------------------------------------------------------------------------
   * STEP #1 — make a mnemonic and show it in the textarea.
   *
   * ------------------------------------------------------------------------ */
  

  const handleGenerateMnemonic = () => {
        const entropy = new Uint8Array(32);
        // CRITICAL SECURITY FIX (silent backdoor.): THIS IS HOW YOU FOOL SOMEONE WITH A HIDDEN EASTER 
        // EGG IF YOU DONT randomize the 000 above which would produce a real valid key!!! 
        crypto.getRandomValues(entropy); 
        const mnemonic24 = entropyToMnemonic(entropy, wordlist); 

        const isValid = validateMnemonic(mnemonic24,wordlist); // true
        //console.log(`Is phrase valid?: ${isValid}`); // true
        if( isValid){
            setMnemonic(mnemonic24);
            localStorage.setItem("mnemonic", mnemonic24);
            setHasSavedMnemonic(true);
            setNote("Mnemonic generated successfully.");
        }
    };

  /* --------------------------------------------------------------------------
   * STEP #2 — Validate Mnemonic and redirect to ChatApp
   *
   * ------------------------------------------------------------------------ */
  const handleValidateMnemonic = async () => {

    const cleanMnemonic = mnemonic.trim();

    // 1. Check if empty
    if (!cleanMnemonic) {
      setNote("Generate or paste a mnemonic first (step #1).");
      return;
    }

    // 2. Validate checksum and word spelling using @scure/bip39
    const isValid = validateMnemonic(cleanMnemonic, wordlist);
    
    if (!isValid) {
      setNote("Invalid mnemonic! Check for spelling errors or a broken checksum.");
      setHasSavedMnemonic(false);
      return;
    }
    try {
      // Generate the master binary seed array
      const seedBytes = await mnemonicToSeed(cleanMnemonic, "");
      // console.log("Seed derived successfully!");
      // console.log("Seed byte length:", seedBytes.length); 
      // console.log("Seed Hex:", bytesToHex(seedBytes));
      const hexSalt = 'b65b9295c885b667d3ce7d06afaee50edabb816af6f3b64a763d6b75201e6ed95';
      const saltBytes = new Uint8Array(
        hexSalt.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16))
      );
      const encoder = new TextEncoder();
      const x25519Info = encoder.encode("echovault-x25519-encryption");
      const ed25519Info = encoder.encode("echovault-ed25519-signing");

      // Derive the 32-byte secret key components using HKDF
      const xSecret  = hkdf(sha256, seedBytes, saltBytes, x25519Info,  32); 
      const edSecret = hkdf(sha256, seedBytes, saltBytes, ed25519Info, 32); 

      // Compute the 32-byte Public Keys directly from those secret vectors
      const xPubBytes = x25519.getPublicKey(xSecret);
      const edPubBytes = ed25519.getPublicKey(edSecret);
      
      // Initialize your hpke-js CipherSuite to generate compatible crypto keys
      const suite = new CipherSuite({
        kem: KemId.DhkemX25519HkdfSha256,
        kdf: KdfId.HkdfSha256,
        aead: AeadId.Chacha20Poly1305,
      });

      // Generate the WebCrypto X25519 Private Key Object using the raw secret bytes
      const xPrivateKey = await suite.kem.importKey("raw", xSecret, false); 
      // Generate the WebCrypto X25519 Public Key Object using the raw public bytes
      const xPublicKey = await suite.kem.importKey("raw", xPubBytes, true);

      // Save derived hex tracking parameters to debug panel
      setDebugData({
        masterSeedHex: bytesToHex(seedBytes),
        hexSalt: hexSalt,
        info_x25: x25519Info,
        info_ed25: ed25519Info,
        sk_x25519: bytesToHex(xSecret),
        pk_x25519: bytesToHex(xPubBytes),
        sk_ed25519: bytesToHex(edSecret),
        pk_ed25519: bytesToHex(edPubBytes),
        
      });



      // Save your mnemonic text
      localStorage.setItem("mnemonic", cleanMnemonic);
      setHasSavedMnemonic(true);
      setNote("Mnemonic validated and seed derived! ");


    } catch (err) {
      setNote("Cryptographic seed derivation failed.");
    }

    //router.push("/");
  };
    /* --------------------------------------------------------------------------
   * STEP #3 — Destroy Mnemonic
   *
   * ------------------------------------------------------------------------ */
    const handleDestroyMnemonic = () => {
        setMnemonic("");                     

        // clear and remove the pointer
        localStorage.setItem("mnemonic", "");
        localStorage.removeItem("mnemonic");

        // Reset your UI status indicators
        setHasSavedMnemonic(false);
        setNote("Mnemonic destroyed.");
    };


  return (
    <div className="cg-app">
      <div className="cg-window">

        {/* ---------- Header (same shell as the chat page) ---------- */}
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
              <h1 className="cg-title">Borealis Assistant - Mnemonic → Ed25519 + X25519</h1>
             
            </div>
          </div>

          {/* Back to the chat. Reuses the Mnemonic-button look. */}
          <Link className="cg-mnemonic-btn" href="/">
            ← Chat
          </Link>
        </header>

        {/* ---------- Key-status strip (turns green as keys are made) ---------- */}
            <div className="cg-keybar">
            <span className="cg-keychip">
                <span className={`cg-light ${hasSavedMnemonic ? "green" : "red"}`} />
                Mnemonic Saved
            </span>
            </div>

        {/* ---------- Middle: textarea + two buttons ---------- */}
        <div className="cg-identity">
          <label className="cg-id-label" htmlFor="mnemonic">
            Recovery mnemonic
          </label>

          <textarea
            id="mnemonic"
            className="cg-id-textarea"
            value={mnemonic}
            onChange={(e) => setMnemonic(e.target.value)}
            placeholder="Click “#1 - Generate Mnemonic”, or paste an existing phrase here…"
            rows={4}
          />

          <div className="cg-id-actions">
            <button
              type="button"
              className="cg-id-btn"
              onClick={handleGenerateMnemonic}
            >
              #1 - Generate Mnemonic
            </button>
            <button
              type="button"
              className="cg-id-btn"
              onClick={handleValidateMnemonic}
            >
              #2 - Validate Mnemonic
            </button>
            <button type="button" className="cg-id-btn danger" onClick={handleDestroyMnemonic}>
  #3 - Destroy Mnemonic
</button>
          </div>

          {/* Status line — only shows once there's something to say. */}
          {note && <p className="cg-id-hint">{note}</p>}
        </div>
        {/* ---------- DEBUG INSPECT BOX ---------- */}
        {debugData && (
          <div style={{
            marginTop: '24px',
            padding: '16px',
            backgroundColor: '#111827',
            border: '1px dashed #374151',
            borderRadius: '6px',
            fontFamily: 'monospace',
            fontSize: '12px',
            color: '#9CA3AF'
          }}>
            <div style={{ color: '#F3F4F6', fontWeight: 'bold', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              🛠️ Cryptographic Internal Variables
            </div>
            <div style={{ overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
              <p><strong style={{ color: '#38BDF8' }}>Master Seed Hex:</strong> {debugData.masterSeedHex}</p>
              <hr style={{ border: '0', borderTop: '1px solid #1F2937', margin: '8px 0' }} />
              <p><strong style={{ color: '#34D399' }}>SaltHex:</strong> {debugData.hexSalt}</p>
               <p><strong style={{ color: '#34D399' }}>X25519 Info:</strong> {debugData.info_x25}</p>
              <p><strong style={{ color: '#34D399' }}>Ed25519 Info:</strong> {debugData.info_ed25}</p>
              <p><strong style={{ color: '#34D399' }}>X25519 Pub Key:</strong> {debugData.pk_x25519}</p>
              <p><strong style={{ color: '#34D399' }}>X25519 Sec Key:</strong> {debugData.sk_x25519}</p>
              <p><strong style={{ color: '#34D399' }}>Ed25519 Pub Key:</strong> {debugData.pk_ed25519}</p>
              <p><strong style={{ color: '#34D399' }}>Ed25519 Sec Key:</strong> {debugData.sk_ed25519}</p>
              <hr style={{ border: '0', borderTop: '1px solid #1F2937', margin: '8px 0' }} />
  
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
