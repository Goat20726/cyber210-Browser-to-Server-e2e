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
    const ws = new WebSocket('ws://localhost:8000/ws');
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
      {/* This injects all our CSS (the big `styles` text at the bottom) into
          the page so the class names above actually have a look. */}
      <style>{styles}</style>

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
        </header>

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


/* ============================================================================
 * THE STYLES (CSS)
 * ============================================================================
 * Everything below is CSS — the rules that control how the screen LOOKS.
 * It's stored as one big block of text (a "template string", wrapped in
 * backticks ` `) and injected into the page by the <style> tag up in the layout.
 *
 * HOW CSS RULES WORK — each rule has two parts:
 *
 *     .cg-title {           ← the SELECTOR: which elements this rule targets.
 *        font-size: 15px;   ← a PROPERTY: value pair. "Make the font 15 pixels."
 *        font-weight: 600;  ← another one. "Make it semi-bold."
 *     }
 *
 *   - A name starting with "." (like .cg-title) matches every element whose
 *     className is "cg-title". That's how the HTML above connects to its look.
 *   - Common properties: color (text color), background (fill behind it),
 *     padding (space INSIDE a box), margin (space OUTSIDE a box),
 *     border-radius (rounded corners), display/flex (how items are arranged),
 *     box-shadow (a soft drop shadow).
 *   - Units: "px" = pixels (screen dots), "%" = percent of the parent's size,
 *     "vh"/"vw" = percent of the viewport's height/width.
 *
 * SPECIAL PIECES YOU'LL SEE BELOW:
 *   --accent: #10a37f;   "CSS variables" — reusable named values (here, colors).
 *                        Defined once at the top, reused everywhere via var(--accent).
 *                        Change it in one place and the whole app updates.
 *   #10a37f              a color in hex code (a teal-green). Format is #RRGGBB.
 *   rgba(0,0,0,.7)       a color with transparency: the last number (.7) is the
 *                        opacity, from 0 (invisible) to 1 (solid).
 *   @keyframes name {}   defines an ANIMATION (e.g. the pulsing dot, bouncing
 *                        typing dots). "animation: pulse 2s infinite" then plays it.
 *   :hover / :disabled   "states" — styles that apply only while hovering with
 *                        the mouse, or while a button is disabled.
 *   @media (max-width…)  "responsive" rules that only apply on small screens
 *                        (e.g. phones), so the layout adapts.
 * ========================================================================== */

const styles = `
  /* The full-screen background. The --xxx lines define reusable colors used
     throughout the app. The "background" stacks two soft colored glows on top
     of the dark base color (--bg) for that subtle gradient effect. */
  .cg-app {
    --accent: #10a37f;
    --accent-2: #1aab8a;
    --bg: #0d0d0f;
    --panel: #1b1b1f;
    --panel-2: #232328;
    --bubble-bot: #2a2a31;
    --text: #ececf1;
    --muted: #9a9aa5;
    min-height: 100vh;            /* at least the full height of the screen */
    display: flex;                /* use flexible box layout... */
    align-items: center;          /* ...centered vertically... */
    justify-content: center;      /* ...and horizontally (so the card is centered) */
    padding: 24px;
    box-sizing: border-box;
    font-family: 'Söhne', ui-sans-serif, system-ui, -apple-system, 'Segoe UI',
      Roboto, Helvetica, Arial, sans-serif;  /* preferred fonts, in order */
    color: var(--text);           /* default text color */
    background:
      radial-gradient(1200px 600px at 15% -10%, rgba(16,163,127,.18), transparent 60%),
      radial-gradient(900px 500px at 110% 10%, rgba(99,102,241,.16), transparent 55%),
      var(--bg);
  }

  /* The chat card itself: a tall rounded panel, centered, with a max width so
     it doesn't stretch too wide on big monitors. */
  .cg-window {
    width: 100%;
    max-width: 760px;             /* never wider than 760px */
    height: min(86vh, 860px);     /* 86% of screen height, but at most 860px */
    display: flex;
    flex-direction: column;       /* stack children top-to-bottom: header, chat, composer */
    background: linear-gradient(180deg, rgba(255,255,255,.02), transparent), var(--panel);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 22px;          /* rounded corners */
    box-shadow: 0 30px 80px -20px rgba(0,0,0,.7), 0 0 0 1px rgba(255,255,255,.02) inset;
    overflow: hidden;             /* clip anything poking outside the rounded corners */
    backdrop-filter: blur(12px);  /* blur whatever is behind the card */
  }

  /* Header */
  /* The top bar holding the logo, title, and status. */
  .cg-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;           /* 14px top/bottom, 18px left/right */
    border-bottom: 1px solid rgba(255,255,255,.07);  /* thin divider line */
    background: rgba(255,255,255,.015);
  }
  .cg-brand { display: flex; align-items: center; gap: 12px; } /* logo + titles in a row */
  .cg-logo {
    width: 38px; height: 38px; border-radius: 12px;
    display: grid; place-items: center;  /* perfectly center the icon inside */
    background: linear-gradient(135deg, var(--accent), #0e8e6f); /* green gradient */
    box-shadow: 0 6px 18px -4px rgba(16,163,127,.6);            /* green glow */
  }
  .cg-titles { display: flex; flex-direction: column; line-height: 1.1; } /* title above status */
  .cg-title { margin: 0; font-size: 15px; font-weight: 600; letter-spacing: .2px; }
  .cg-status {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 11.5px; color: var(--muted); margin-top: 3px;
  }
  .cg-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); } /* grey by default */
  /* When connected (.on), the dot turns green and gently pulses. */
  .cg-status.on .cg-dot {
    background: #2ecc71;
    box-shadow: 0 0 0 0 rgba(46,204,113,.6);
    animation: pulse 2s infinite;   /* play the "pulse" animation forever */
  }
  /* Defines the pulsing-ring animation used by the status dot above. */
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(46,204,113,.55); }
    70%  { box-shadow: 0 0 0 7px rgba(46,204,113,0); }
    100% { box-shadow: 0 0 0 0 rgba(46,204,113,0); }
  }

  /* Transcript */
  /* The scrollable conversation area. "flex: 1" makes it grow to fill all the
     leftover space between the header and the composer. */
  .cg-transcript {
    flex: 1; overflow-y: auto; padding: 22px 18px 8px;   /* scroll vertically when full */
    display: flex; flex-direction: column; gap: 16px;    /* messages stacked with spacing */
    scroll-behavior: smooth;
  }
  /* These style the scrollbar itself (width, color, hover color). */
  .cg-transcript::-webkit-scrollbar { width: 9px; }
  .cg-transcript::-webkit-scrollbar-thumb {
    background: rgba(255,255,255,.12); border-radius: 8px;
  }
  .cg-transcript::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.2); }

  /* Empty state */
  /* The centered "How can I help?" welcome shown before any messages. */
  .cg-empty {
    margin: auto; text-align: center; max-width: 340px;
    animation: fadeUp .5s ease both;   /* fades up into view when it appears */
  }
  .cg-empty-orb {
    width: 68px; height: 68px; margin: 0 auto 18px; border-radius: 20px;
    display: grid; place-items: center;
    background: linear-gradient(135deg, var(--accent), #5b6cf0);
    box-shadow: 0 18px 40px -12px rgba(16,163,127,.55);
    animation: float 4s ease-in-out infinite;  /* gently bobs up and down */
  }
  .cg-empty-title { margin: 0 0 6px; font-size: 20px; font-weight: 600; }
  .cg-empty-sub { margin: 0; color: var(--muted); font-size: 14px; }
  /* The gentle up-and-down bob for the orb above. */
  @keyframes float {
    0%,100% { transform: translateY(0); }
    50%     { transform: translateY(-7px); }
  }

  /* Rows + bubbles */
  /* One row = an avatar + a speech bubble. They animate in when added. */
  .cg-row { display: flex; gap: 11px; align-items: flex-end; animation: msgIn .32s ease both; }
  /* User rows are reversed so the bubble sits on the RIGHT, avatar on the right. */
  .cg-row.user { flex-direction: row-reverse; }
  .cg-avatar {
    flex: 0 0 auto; width: 30px; height: 30px; border-radius: 9px;
    display: grid; place-items: center; margin-bottom: 2px;
  }
  /* Assistant avatar = green gradient; user avatar = purple gradient. */
  .cg-avatar.assistant { background: linear-gradient(135deg, var(--accent), #0e8e6f); }
  .cg-avatar.user { background: linear-gradient(135deg, #6366f1, #8b5cf6); }

  /* The speech bubble shared look (size limit, padding, rounded, wrapping). */
  .cg-bubble {
    max-width: 76%;                 /* bubble never wider than 76% of the row */
    padding: 11px 14px;
    border-radius: 18px;
    font-size: 14.5px; line-height: 1.55;
    word-wrap: break-word; white-space: pre-wrap;  /* keep line breaks, wrap long words */
    box-shadow: 0 2px 10px -4px rgba(0,0,0,.5);
  }
  /* Assistant bubbles: grey, with one corner squared off for a "tail" look. */
  .cg-row.assistant .cg-bubble {
    background: var(--bubble-bot);
    border: 1px solid rgba(255,255,255,.05);
    border-bottom-left-radius: 6px;
  }
  /* User bubbles: green gradient, white text, squared bottom-right corner. */
  .cg-row.user .cg-bubble {
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: #fff;
    border-bottom-right-radius: 6px;
  }
  .cg-text {}   /* (no special styling needed for the text itself) */
  /* The faint little timestamp under each message. */
  .cg-time {
    margin-top: 5px; font-size: 10.5px; opacity: .6;
    text-align: right;
  }
  .cg-row.assistant .cg-time { text-align: left; } /* assistant times align left */

  /* Typing indicator */
  /* The three bouncing dots shown while waiting for a reply. */
  .cg-typing { display: flex; gap: 5px; align-items: center; padding: 14px 16px; }
  .cg-typing-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--muted); animation: blink 1.4s infinite both;
  }
  /* Stagger the 2nd and 3rd dots so they bounce in sequence, not together. */
  .cg-typing-dot:nth-child(2) { animation-delay: .2s; }
  .cg-typing-dot:nth-child(3) { animation-delay: .4s; }
  /* The bounce + fade used by the dots above. */
  @keyframes blink {
    0%, 80%, 100% { opacity: .25; transform: translateY(0); }
    40%           { opacity: 1;  transform: translateY(-3px); }
  }

  /* Composer */
  /* The bottom typing area. */
  .cg-composer { padding: 12px 16px 16px; }
  /* The rounded "pill" that holds the text box and send button side by side. */
  .cg-inputwrap {
    display: flex; align-items: flex-end; gap: 8px;
    background: var(--panel-2);
    border: 1px solid rgba(255,255,255,.09);
    border-radius: 22px;
    padding: 8px 8px 8px 16px;
    transition: border-color .18s, box-shadow .18s;  /* smooth color change on focus */
  }
  /* When the user clicks into the box, highlight the pill with a green ring. */
  .cg-inputwrap:focus-within {
    border-color: rgba(16,163,127,.65);
    box-shadow: 0 0 0 3px rgba(16,163,127,.16);
  }
  /* The text box: transparent, borderless, grows up to 160px tall. */
  .cg-input {
    flex: 1; resize: none; border: none; outline: none; background: transparent;
    color: var(--text); font: inherit; font-size: 14.5px; line-height: 1.5;
    max-height: 160px; padding: 6px 0;
  }
  .cg-input::placeholder { color: var(--muted); }  /* faint hint-text color */

  /* The round send button with the arrow icon. */
  .cg-send {
    flex: 0 0 auto; width: 36px; height: 36px; border: none; border-radius: 50%;
    display: grid; place-items: center; cursor: pointer; color: #fff;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    transition: transform .15s, box-shadow .15s, opacity .15s;  /* smooth hover/click effects */
    box-shadow: 0 6px 16px -4px rgba(16,163,127,.7);
  }
  /* Grow slightly on hover, shrink on click — but only when NOT disabled. */
  .cg-send:hover:not(:disabled) { transform: scale(1.08) translateY(-1px); }
  .cg-send:active:not(:disabled) { transform: scale(.94); }
  /* When the box is empty the button is disabled: faded and grey. */
  .cg-send:disabled {
    opacity: .4; cursor: not-allowed; box-shadow: none;
    background: #3a3a42;
  }

  /* The small helper line beneath the box. */
  .cg-footnote {
    margin: 10px 4px 0; text-align: center; font-size: 11px; color: var(--muted);
  }
  /* Styles the <kbd> tags so key names (Enter, Shift) look like keyboard caps. */
  .cg-footnote kbd {
    background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.12);
    border-radius: 5px; padding: 1px 5px; font-size: 10px; font-family: inherit;
  }

  /* Two animations: messages slide up as they appear; the empty state fades up. */
  @keyframes msgIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
  @keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }

  /* RESPONSIVE: on narrow screens (phones, 640px wide or less), make the chat
     fill the whole screen edge-to-edge with no rounded corners or margins. */
  @media (max-width: 640px) {
    .cg-app { padding: 0; }
    .cg-window { height: 100vh; max-width: 100%; border-radius: 0; border: none; }
    .cg-bubble { max-width: 82%; }
  }
`;
