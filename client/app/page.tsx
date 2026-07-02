/* ============================================================================
 * BOREALIS ASSISTANT — A simple chat app (front end / what the user sees)
 * ============================================================================
 *
 * WHAT IS THIS FILE?
 *   This is ONE screen of a website: a chat window (like ChatGPT). It is
 *   written in "React", which is a popular toolkit for building web pages.
 *
 * THREE LANGUAGES ARE MIXED TOGETHER HERE — here's the 30-second tour:
 *
 *   1) JavaScript / TypeScript  → the "brain". It decides WHAT happens:
 *        what to do when you click "send", how to talk to the server, etc.
 *        (TypeScript is just JavaScript with extra "type" labels that help
 *         catch mistakes, e.g. "this value must be a number".)
 *
 *   2) HTML (written here as "JSX") → the "skeleton". It describes the
 *        visible PIECES on screen: boxes, text, buttons, the input field.
 *        In React, HTML is written right inside the JavaScript using tags
 *        that look like <div>, <button>, <h1>, etc.
 *
 *   3) CSS → the "paint and layout". It decides how things LOOK: colors,
 *        sizes, spacing, rounded corners, animations. All the CSS for this
 *        screen lives in the big text block named `styles` at the BOTTOM.
 *
 * HOW IT TALKS TO THE SERVER:
 *   It uses a "WebSocket" — think of it as a phone line that stays open so
 *   the browser and the server can send messages back and forth instantly,
 *   instead of hanging up and re-dialing for every message.
 *
 * READING ORDER (top to bottom):
 *   A) Setup & imports
 *   B) The shape of a chat message (a TypeScript "type")
 *   C) The component itself: its memory (state), its connection logic,
 *      and the functions that run when you type/send.
 *   D) The visible layout (the HTML/JSX returned at the end).
 *   E) The CSS styles (the big string at the very bottom).
 * ========================================================================== */


// "use client" tells the website framework (Next.js) that this screen runs in
// the visitor's BROWSER (not pre-built on the server). We need this because the
// chat reacts live to clicks, typing, and incoming messages.
"use client";

// Bring in ("import") the React tools we need:
//   useState  → gives a component "memory" that, when changed, redraws the screen
//   useEffect → runs setup/cleanup code at the right moments (e.g. on first load)
//   useRef    → a private box to remember a value WITHOUT redrawing the screen
import React, { useState, useEffect, useRef } from 'react';
import Link from "next/link";
import { validateMnemonic, mnemonicToSeed } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

/* ----------------------------------------------------------------------------
 * THE SHAPE OF DATA
 * ----------------------------------------------------------------------------
 * Below we describe, in TypeScript, exactly what a chat message looks like.
 * This is like a form template: every message MUST have these fields, and each
 * field has a fixed kind of value. If we ever forget a field or use the wrong
 * kind of value, TypeScript warns us before the app even runs.
 * -------------------------------------------------------------------------- */

// A message can only come from one of two senders: the human ('user') or the
// AI ('assistant'). The "|" means "this OR that" and nothing else is allowed.
type Sender = 'user' | 'assistant';

// The blueprint for a single chat message.
interface ChatMessage {
  seq: number;        // a counter/ID number for ordering messages (0, 1, 2, ...)
  text: string;       // the actual words of the message
  type: string;       // a label for the kind of message (e.g. 'msg')
  sender: Sender;     // who sent it: 'user' or 'assistant' (see Sender above)
  timestamp: string;  // a human-readable time, e.g. "3:42:10 PM"
}


/* ----------------------------------------------------------------------------
 * THE COMPONENT
 * ----------------------------------------------------------------------------
 * A "component" is a reusable chunk of screen. This one, ChatApp, IS the whole
 * chat window. `export default` means "this is the main thing this file
 * provides" so other files can drop <ChatApp /> onto a page.
 *
 * Everything from here to the closing brace describes ONE chat window:
 * first its memory and behavior (JavaScript), then its appearance (the JSX it
 * `return`s near the bottom).
 * -------------------------------------------------------------------------- */
export default function ChatApp() {

  /* ------------------------------------------------------------------------
   * STATE = the component's live memory.
   * Each useState gives us TWO things: the current value, and a function to
   * change it. Whenever we call the "set" function, React automatically
   * redraws the screen to reflect the new value. Pattern:
   *     const [value, setValue] = useState(startingValue);
   * ---------------------------------------------------------------------- */

  // The full list of chat messages shown on screen. Starts empty ([]).
    const [messages, setMessages] = useState<ChatMessage[]>([]);

    // Whatever the user is currently typing in the text box. Starts blank ('').
    const [inputValue, setInputValue] = useState('');

    // true once we're connected to the server, false otherwise (drives the
    // "Online" / "Connecting…" label in the header).
    const [isConnected, setIsConnected] = useState(false);

    // true while we're waiting for the assistant's reply (shows the "…" bubble).
    const [isTyping, setIsTyping] = useState(false);
    


    // ---- Sequence state -------------------------------------------------------
    // c2sSeq : next client→server seq to send. You increment it on each send.
    // lastS2C: highest server→client seq already accepted (a high-water mark).
    //          Starts at -1 so the very first server frame (seq 0) is accepted.
    // Both are reset together inside the socket effect on every (re)connect.
    //
    // PLAIN ENGLISH: every message carries a counter number ("seq"). These two
    // refs remember which numbers we've sent and which we've already received,
    // so we never show the same reply twice or out of order. We use `useRef`
    // (not state) because changing a counter should NOT redraw the screen.
    const c2sSeq = useRef<number>(0);
    const lastS2C = useRef<number>(-1);

    // Persist the single socket instance across renders.
    // (Holds our one open "phone line" to the server so we can reuse it.)
    const socketRef = useRef<WebSocket | null>(null);

    // Auto-scroll anchor + textarea handle + typing-indicator timeout
    // endRef        → an invisible marker at the very bottom of the chat; we
    //                 scroll to it so new messages are always in view.
    // textareaRef   → a direct handle to the typing box so we can resize it.
    // typingTimeout → remembers a pending timer (used to auto-hide "typing…").
    const endRef = useRef<HTMLDivElement | null>(null);
    const textareaRef = useRef<HTMLTextAreaElement | null>(null);
    const typingTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

    /* ------------------------------------------------------------------------
   * AUTO-SCROLL
   * useEffect runs a piece of code AFTER the screen updates. The list in the
   * square brackets at the end ([messages, isTyping]) is the "watch list":
   * this code re-runs every time the messages list OR the typing flag changes.
   * Result: whenever a new message arrives or the "typing…" bubble appears,
   * we smoothly scroll down to it.
   * The "?." means "only do this if endRef actually points to something".
   * ---------------------------------------------------------------------- */
    useEffect(() => {
      endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }, [messages, isTyping]);



    const [hasSavedMnemonic, setHasSavedMnemonic] = useState(false);
    // A small status message under the buttons.

  
    // On open, load whatever is already saved so the lights/textarea reflect it.
    useEffect(() => {

        const savedMnemonic = localStorage.getItem("mnemonic") ?? "";
        

        // 2. Validate it immediately to ensure it wasn't tampered with
        if (savedMnemonic.trim()) {
          const isValid = validateMnemonic(savedMnemonic, wordlist);
          setHasSavedMnemonic(isValid);
        } else {
          setHasSavedMnemonic(false);
        }
    }, []);
  

    const [channelEstablished, setEncChannel] = useState(false)
    const [encrypt, setEncrypt] = useState(true);
    /* ------------------------------------------------------------------------
    * CONNECT TO THE SERVER (runs ONCE when the chat first appears)
    * The empty watch list "[]" at the very bottom means "run this setup a
    * single time, when the component first loads, and never again".
    * ---------------------------------------------------------------------- */
    useEffect(() => {
      // Fresh-session baseline. Both counters reset together on every (re)connect:
      // a new handshake makes the server's s2cSeq restart from 0, so a stale
      // lastS2C left at its old high value would reject the ENTIRE new session.
      // By the time onopen fires ("successful open") these are already at zero.
      c2sSeq.current = 0;   // next c2s seq to send
      lastS2C.current = -1; // highest s2c seq accepted (nothing yet) 

      // Initialize the WebSocket connection once on mount.
      // Replace with your actual secure WebSocket server URL (e.g., wss://...)
      // (This line opens the "phone line" to the server.)
      const wsBase =
        process.env.NEXT_PUBLIC_WS_URL ??
        (typeof window !== 'undefined' && window.location.protocol === 'https:'
          ? `wss://${window.location.host}`
          : 'ws://localhost:8000');
      const ws = new WebSocket(`${wsBase}/ws`);
      socketRef.current = ws; // remember it so other functions can use it later

      // ---- Lifecycle handlers --------------------------------------------------
      // A WebSocket fires named events. We attach a function to each one to say
      // "when THIS happens, run THAT". The four events: open, message, error, close.

      // FIRES WHEN: the connection is successfully opened.
      ws.onopen = () => {
        console.log('WebSocket connection established.'); // log = note in the dev console
        setIsConnected(true); // flip the header to "Online"
      };

      // FIRES WHEN: the server sends us a message.
      ws.onmessage = (event) => {
        try {
          // Messages arrive as plain text in "JSON" format. JSON.parse turns that
          // text back into a usable object we can read fields from (data.text, etc.).
          const data = JSON.parse(event.data);

          // A reply landed, so we can stop showing the typing indicator.
          setIsTyping(false);

          // Frames without a seq can't be ordered or de-duplicated — ignore them.
          // ("return" here means: stop early and do nothing with this message.)
          if (data.seq == null) return;

          // ---- lastS2C high-water mark ------------------------------------
          // Accept a server frame ONLY if its seq is strictly greater than the
          // highest we've already taken. This one check kills duplicates,
          // replays and out-of-order/stale frames, and never lets the mark
          // slide backwards. After a reconnect lastS2C is back at -1, so the
          // new session's seq 0 is accepted instead of rejected as "old".
          if (data.seq <= lastS2C.current) return;

          // Passed the gate → advance the mark to this seq.
          lastS2C.current = data.seq;

          // Build a tidy ChatMessage object from the raw server data.
          // ("??" means "use the thing on the left, but if it's missing, use the
          //  fallback on the right instead" — a safety net against blank fields.)
          const incoming: ChatMessage = {
            // Keep the backend's sequence number so send + echo share the same seq
            seq: data.seq,
            // Capture the 'payload' field from your python backend dictionary
            text: data.text ?? '',
            // Map based on your 'type' field or fallback to 'msg'
            type: data.type != null ? data.type : 'msg', // echoes render left
            sender: 'assistant',
            // Safely capture the passed backend timestamp
            timestamp: data.timestamp ?? new Date().toLocaleTimeString(),
          };

          // Add the new message to the end of the list.
          // Functional update so back-to-back frames in the same tick can't
          // clobber each other.
          // (The "(prev) => [...prev, incoming]" means: take the previous list,
          //  copy all of it, and add the new message at the end.)
          setMessages((prev) => [...prev, incoming]);
        } catch (error) {
          // If the incoming text wasn't valid JSON, don't crash — just log it.
          console.error('Failed to parse incoming message:', error);
        }
      };

      // FIRES WHEN: something goes wrong with the connection.
      ws.onerror = (error) => {
        console.error('WebSocket error observed:', error);
      };

      // FIRES WHEN: the connection closes (server went away, network dropped, etc.).
      ws.onclose = () => {
        console.log('WebSocket connection closed.');
        setIsConnected(false); // flip the header back to "Connecting…"
      };

      // Clean up on unmount.
      // This "return a function" is React's cleanup step: it runs when the chat
      // window is removed from the page. We cancel any pending timer and hang up
      // the phone line so nothing keeps running in the background.
      return () => {
        if (typingTimeout.current) clearTimeout(typingTimeout.current);
        ws.close();
      };
    }, []); // Empty deps → run once


    /* ------------------------------------------------------------------------
    * SENDING A MESSAGE
    * Runs when the user clicks the send button or presses Enter.
    * The optional "e" is the browser "event"; we use it to stop the page from
    * doing its default form behavior (a full page reload), which we don't want.
    * ---------------------------------------------------------------------- */
    const handleSend = (e?: React.FormEvent) => {
      e?.preventDefault(); // stop the page from reloading when the form submits

      const text = inputValue.trim(); // the typed text, with extra spaces removed
      if (!text) return;              // if it's empty, do nothing

      // Read the current c2s seq, send with it, then increment for the next send.
      const currentSeq = c2sSeq.current;

      // Package up everything about this outgoing message.
      const payload: ChatMessage = {
        seq: currentSeq,
        text,
        type: 'msg',
        sender: 'user',
        timestamp: new Date().toLocaleTimeString(), // the current time as text
      };

      // Only send if the phone line is actually open and ready.
      if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
        // Convert our object to JSON text and send it down the wire.
        socketRef.current.send(JSON.stringify(payload));

        // Optimistically render our own message immediately.
        // ("Optimistically" = show it right away without waiting for the server
        //  to confirm, so the chat feels instant.)
        setMessages((prev) => [...prev, payload]);
        setInputValue(''); // clear the typing box

        // Increment the c2s counter only after a successful send.
        c2sSeq.current += 1;

        // Show a typing indicator while we wait for a reply. Clear it on the
        // next inbound message, or fall back to a timeout so it never sticks.
        // (The timeout auto-hides "typing…" after 12 seconds if no reply comes,
        //  so it can't get stuck on screen forever.)
        setIsTyping(true);
        if (typingTimeout.current) clearTimeout(typingTimeout.current);
        typingTimeout.current = setTimeout(() => setIsTyping(false), 12000);

        // Reset the auto-grown textarea back to one line.
        if (textareaRef.current) textareaRef.current.style.height = 'auto';
      } else {
        // The line wasn't open, so we couldn't send. Note it in the dev console.
        console.error('WebSocket is not open. Cannot send message.');
      }
    };


    /* ------------------------------------------------------------------------
    * KEYBOARD SHORTCUTS IN THE TYPING BOX
    * Enter sends, Shift+Enter inserts a newline (ChatGPT-style).
    * ---------------------------------------------------------------------- */
    const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      // If the user pressed Enter WITHOUT holding Shift...
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault(); // ...don't type a newline...
        handleSend();       // ...send the message instead.
      }
      // (If Shift IS held, we do nothing special, so a normal newline is typed.)
    };


    /* ------------------------------------------------------------------------
    * AUTO-GROWING TYPING BOX
    * Runs every time the text in the box changes. It saves the new text, then
    * grows the box's height to fit what was typed — up to a maximum of 160px,
    * after which it stops growing and starts scrolling instead.
    * ---------------------------------------------------------------------- */
    const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
      setInputValue(e.target.value);      // remember the new text
      const el = e.target;                // the textarea element itself
      el.style.height = 'auto';           // shrink first so we can measure cleanly
      // scrollHeight = how tall the text actually needs to be. Math.min caps it
      // at 160 pixels so the box never gets ridiculously tall.
      el.style.height = Math.min(el.scrollHeight, 160) + 'px';
    };


  /* ========================================================================
   * THE VISIBLE LAYOUT (HTML / JSX)
   * ========================================================================
   * Everything inside this `return (...)` is what actually shows on screen.
   * It LOOKS like HTML, but it's "JSX" — HTML written inside JavaScript.
   *
   * Quick guide to the symbols you'll see:
   *   <div>...</div>        a generic box/container
   *   className="..."       attaches a CSS style name (plain HTML uses "class";
   *                         React uses "className"). The styles live at the
   *                         very bottom of this file.
   *   { ... }               an "escape hatch" back into JavaScript — anything
   *                         inside the curly braces is computed by JS, e.g.
   *                         {msg.text} prints the message's text.
   *   {condition && (...)}  "show this part ONLY IF the condition is true".
   *   {list.map(...)}       "for each item in the list, draw this piece" — this
   *                         is how we turn the messages array into rows on screen.
   *   <svg>...</svg>        a small vector drawing (the logos/icons), described
   *                         by math paths rather than a picture file.
   * ====================================================================== */
  return (
    // Outermost wrapper for the whole screen.
    <div className="cg-app">

      {/* The chat window card (the centered rounded panel). */}
      <div className="cg-window">

        {/* ---------- Header ---------- */}
        {/* The top bar: logo, app name, and the Online/Connecting status. */}
        <header className="cg-header">
          <div className="cg-brand">
            {/* The little logo box with a star icon drawn as an SVG. */}
            <div className="cg-logo">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none">
                {/* This "path" is the star shape, described as a set of lines. */}
                <path
                  d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                  fill="#fff"
                />
                {/* Two small dots ("circle") beside the star. */}
                <circle cx="18.5" cy="17.5" r="1.6" fill="#fff" />
                <circle cx="6" cy="16" r="1.1" fill="#fff" />
              </svg>
            </div>

            {/* The app's name and live connection status. */}
            <div className="cg-titles">
              <h1 className="cg-title">Borealis Assistant</h1>
              {/* The status text. The class name switches between 'on' and
                  'off' depending on isConnected, which changes its color.
                  The text itself reads "Online" when connected, else "Connecting…". */}
              <span className={`cg-status ${isConnected ? 'on' : 'off'}`}>
                <span className="cg-dot" /> {/* the little colored status dot */}
                {isConnected ? 'Online' : 'Connecting…'}
              </span>
            </div>
          </div>
          <div className="cg-header-actions">
  {/* The Encrypt switch. Checkbox must come right before .cg-toggle-track. */}
  <label className="cg-toggle" title="Toggle browser-side HPKE encryption">
    <span>Encrypt</span>
<input
  type="checkbox"
  checked={encrypt && channelEstablished}
  disabled={!channelEstablished}
  onChange={(e) => setEncrypt(e.target.checked)}
/>
    <span className="cg-toggle-track"><span className="cg-toggle-thumb" /></span>
    <span className="cg-toggle-state">{encrypt ? 'On' : 'Off'}</span>
  </label>

  <a className="cg-mnemonic-btn" href="/identity">Key Vault</a>
</div>
          
        </header>
        {/* Four chips, each with a red/green dot showing if that key exists. */}
            <div className="cg-keybar">
            <span className="cg-keychip">
                <span className={`cg-light ${hasSavedMnemonic ? "green" : "red"}`} />
                Mnemonic Saved
            </span>
            </div>
        {/* ---------- Transcript ---------- */}
        {/* The scrollable area in the middle that holds the conversation. */}
        <div className="cg-transcript">

          {/* EMPTY STATE: shown only when there are NO messages yet AND the
              assistant isn't typing — a friendly "How can I help?" welcome. */}
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

          {/* THE MESSAGE LIST:
              .map(...) walks through every message and draws one row for each.
              "key" is a unique label React needs to track each row efficiently.
              The row's class includes msg.sender ('user' or 'assistant'), which
              the CSS uses to align user messages right and assistant left. */}
          {messages.map((msg) => (
            <div
              key={`${msg.seq}-${msg.sender}`}
              className={`cg-row ${msg.sender}`}
            >
              {/* The avatar (little icon) next to the bubble. We show a star for
                  the assistant and a person icon for the user. */}
              <div className={`cg-avatar ${msg.sender}`}>
                {msg.sender === 'assistant' ? (
                  // Assistant avatar = star icon
                  <svg viewBox="0 0 24 24" width="16" height="16" fill="none">
                    <path
                      d="M12 2l1.9 4.7L19 8l-4.1 1.3L13 14l-1.4-4.5L7 8l4.6-1.3L12 2z"
                      fill="#fff"
                    />
                  </svg>
                ) : (
                  // User avatar = a head-and-shoulders person icon
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

              {/* The speech bubble: the message text plus its timestamp. */}
              <div className="cg-bubble">
                <div className="cg-text">{msg.text}</div>
                <div className="cg-time">{msg.timestamp}</div>
              </div>
            </div>
          ))}

          {/* TYPING INDICATOR: the animated "…" bubble, shown only while we're
              waiting for the assistant to reply (isTyping is true). */}
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
              {/* Three dots that bounce via CSS animation. */}
              <div className="cg-bubble cg-typing">
                <span className="cg-typing-dot" />
                <span className="cg-typing-dot" />
                <span className="cg-typing-dot" />
              </div>
            </div>
          )}

          {/* Invisible marker at the bottom. The auto-scroll code earlier scrolls
              the view down to THIS element whenever a new message arrives. */}
          <div ref={endRef} />
        </div>

        {/* ---------- Composer ---------- */}
        {/* The bottom area where the user types and sends. It's a "form", so
            pressing Enter / clicking the button triggers onSubmit = handleSend. */}
        <form className="cg-composer" onSubmit={handleSend}>
          <div className="cg-inputwrap">
            {/* The text box.
                  ref          → handle used to auto-resize it.
                  rows={1}     → start one line tall.
                  value        → always shows our remembered inputValue.
                  onChange     → runs handleInput on every keystroke.
                  onKeyDown    → runs handleKeyDown to catch the Enter key.
                  placeholder  → the faint hint text shown when it's empty. */}
            <textarea
              ref={textareaRef}
              rows={1}
              value={inputValue}
              onChange={handleInput}
              onKeyDown={handleKeyDown}
              placeholder="Message Borealis…"
              className="cg-input"
            />

            {/* The send button (an upward arrow icon).
                  type="submit" → submitting the form triggers handleSend.
                  disabled      → greyed-out and unclickable when the box is empty.
                  aria-label    → a description for screen readers (accessibility). */}
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

          {/* Small helper text under the box. <kbd> styles a key name like a
              little keyboard cap. {' '} is just a deliberate single space. */}
          <p className="cg-footnote">
            Borealis can make mistakes. Press <kbd>Enter</kbd> to send ·{' '}
            <kbd>Shift</kbd>+<kbd>Enter</kbd> for a new line.
          </p>
        </form>
      </div>
    </div>
  );
}
