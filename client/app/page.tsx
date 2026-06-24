"use client";
import React, { useState, useEffect, useRef } from 'react';

type Sender = 'user' | 'assistant';
interface ChatMessage {
  seq: number;
  text: string;
  type: string;
  sender: Sender;
  timestamp: string;
}



export default function ChatApp() {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isConnected, setIsConnected] = useState(false);
  const [isTyping, setIsTyping] = useState(false);

  const seqRef = useRef<number>(1); 
  // Persist the single socket instance across renders
  const socketRef = useRef<WebSocket | null>(null);
  // Always read the latest message state inside the socket listener
  const messagesRef = useRef<ChatMessage[]>([]);
  // Auto-scroll anchor + textarea handle + typing-indicator timeout
  const endRef = useRef<HTMLDivElement | null>(null);
  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const typingTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Keep messagesRef in sync with the state
  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  // Smoothly scroll to the newest message / typing indicator
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isTyping]);

  useEffect(() => {
    // 1. Initialize the WebSocket connection once on mount.
    // Replace with your actual secure WebSocket server URL (e.g., wss://...)
    const ws = new WebSocket('ws://localhost:8000/ws');
    socketRef.current = ws;

    // 2. Lifecycle handlers
    ws.onopen = () => {
      console.log('WebSocket connection established.');
      setIsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        // A reply landed, so we can stop showing the typing indicator.
        setIsTyping(false);

        // Echo-server safety: if we already optimistically rendered this
        // message (same seq), skip it instead of duplicating the bubble.
        if (data.seq && messagesRef.current.some((m) => m.seq === data.seq)) {
          return;
        }

          const incoming: ChatMessage = {
          // Coerce the sequence number to a string to match your ID type
          seq: data.seq,
          // Capture the 'payload' field from your python backend dictionary
          text: data.payload ?? data.text ?? '',              // payload → text
          // Map based on your 'type' field or fallback to assistant
          type: data.type != null ? data.type : 'msg',                                // echoes render left
          sender: data.sender != null ? data.sender : 'assistant',  
          // Safely capture the passed backend timestamp
          timestamp: data.timestamp ?? new Date().toLocaleTimeString(),
        };
        seqRef.current += 1;

        setMessages([...messagesRef.current, incoming]);
      } catch (error) {
        console.error('Failed to parse incoming message:', error);
      }
    };

    ws.onerror = (error) => {
      console.error('WebSocket error observed:', error);
    };

    ws.onclose = () => {
      console.log('WebSocket connection closed.');
      setIsConnected(false);
    };

    // 3. Clean up on unmount
    return () => {
      if (typingTimeout.current) clearTimeout(typingTimeout.current);
      ws.close();
    };
  }, []); // Empty deps → run once

  const handleSend = (e?: React.FormEvent) => {
    e?.preventDefault();
    const text = inputValue.trim();
    if (!text) return;
    const currentSeq = seqRef.current;

    const payload: ChatMessage = {
      seq: currentSeq,
      text,
      type: 'msg',
      sender: 'user',
      timestamp: new Date().toLocaleTimeString(),
    };

    if (socketRef.current && socketRef.current.readyState === WebSocket.OPEN) {
      socketRef.current.send(JSON.stringify(payload));

      // Optimistically render our own message immediately.
      setMessages((prev) => [...prev, payload]);
      setInputValue('');
      seqRef.current += 1;
      // Show a typing indicator while we wait for a reply. Clear it on the
      // next inbound message, or fall back to a timeout so it never sticks.
      setIsTyping(true);
      if (typingTimeout.current) clearTimeout(typingTimeout.current);
      typingTimeout.current = setTimeout(() => setIsTyping(false), 12000);

      // Reset the auto-grown textarea back to one line.
      if (textareaRef.current) textareaRef.current.style.height = 'auto';
    } else {
      console.error('WebSocket is not open. Cannot send message.');
    }
  };

  // Enter sends, Shift+Enter inserts a newline (ChatGPT-style).
  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Auto-grow the textarea up to a max height as the user types.
  const handleInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputValue(e.target.value);
    const el = e.target;
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
  };

  return (
    <div className="cg-app">
      <style>{styles}</style>

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
        </header>

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
            <div key={msg.seq} className={`cg-row ${msg.sender}`}>
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
              <div className="cg-bubble">
                <div className="cg-text">{msg.text}</div>
                <div className="cg-time">{msg.timestamp}</div>
              </div>
            </div>
          ))}

          {/* Typing indicator */}
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

const styles = `
  .cg-app {
    --accent: #10a37f;
    --accent-2: #1aab8a;
    --bg: #0d0d0f;
    --panel: #1b1b1f;
    --panel-2: #232328;
    --bubble-bot: #2a2a31;
    --text: #ececf1;
    --muted: #9a9aa5;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    box-sizing: border-box;
    font-family: 'Söhne', ui-sans-serif, system-ui, -apple-system, 'Segoe UI',
      Roboto, Helvetica, Arial, sans-serif;
    color: var(--text);
    background:
      radial-gradient(1200px 600px at 15% -10%, rgba(16,163,127,.18), transparent 60%),
      radial-gradient(900px 500px at 110% 10%, rgba(99,102,241,.16), transparent 55%),
      var(--bg);
  }

  .cg-window {
    width: 100%;
    max-width: 760px;
    height: min(86vh, 860px);
    display: flex;
    flex-direction: column;
    background: linear-gradient(180deg, rgba(255,255,255,.02), transparent), var(--panel);
    border: 1px solid rgba(255,255,255,.08);
    border-radius: 22px;
    box-shadow: 0 30px 80px -20px rgba(0,0,0,.7), 0 0 0 1px rgba(255,255,255,.02) inset;
    overflow: hidden;
    backdrop-filter: blur(12px);
  }

  /* Header */
  .cg-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid rgba(255,255,255,.07);
    background: rgba(255,255,255,.015);
  }
  .cg-brand { display: flex; align-items: center; gap: 12px; }
  .cg-logo {
    width: 38px; height: 38px; border-radius: 12px;
    display: grid; place-items: center;
    background: linear-gradient(135deg, var(--accent), #0e8e6f);
    box-shadow: 0 6px 18px -4px rgba(16,163,127,.6);
  }
  .cg-titles { display: flex; flex-direction: column; line-height: 1.1; }
  .cg-title { margin: 0; font-size: 15px; font-weight: 600; letter-spacing: .2px; }
  .cg-status {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 11.5px; color: var(--muted); margin-top: 3px;
  }
  .cg-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
  .cg-status.on .cg-dot {
    background: #2ecc71;
    box-shadow: 0 0 0 0 rgba(46,204,113,.6);
    animation: pulse 2s infinite;
  }
  @keyframes pulse {
    0%   { box-shadow: 0 0 0 0 rgba(46,204,113,.55); }
    70%  { box-shadow: 0 0 0 7px rgba(46,204,113,0); }
    100% { box-shadow: 0 0 0 0 rgba(46,204,113,0); }
  }

  /* Transcript */
  .cg-transcript {
    flex: 1; overflow-y: auto; padding: 22px 18px 8px;
    display: flex; flex-direction: column; gap: 16px;
    scroll-behavior: smooth;
  }
  .cg-transcript::-webkit-scrollbar { width: 9px; }
  .cg-transcript::-webkit-scrollbar-thumb {
    background: rgba(255,255,255,.12); border-radius: 8px;
  }
  .cg-transcript::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,.2); }

  /* Empty state */
  .cg-empty {
    margin: auto; text-align: center; max-width: 340px;
    animation: fadeUp .5s ease both;
  }
  .cg-empty-orb {
    width: 68px; height: 68px; margin: 0 auto 18px; border-radius: 20px;
    display: grid; place-items: center;
    background: linear-gradient(135deg, var(--accent), #5b6cf0);
    box-shadow: 0 18px 40px -12px rgba(16,163,127,.55);
    animation: float 4s ease-in-out infinite;
  }
  .cg-empty-title { margin: 0 0 6px; font-size: 20px; font-weight: 600; }
  .cg-empty-sub { margin: 0; color: var(--muted); font-size: 14px; }
  @keyframes float {
    0%,100% { transform: translateY(0); }
    50%     { transform: translateY(-7px); }
  }

  /* Rows + bubbles */
  .cg-row { display: flex; gap: 11px; align-items: flex-end; animation: msgIn .32s ease both; }
  .cg-row.user { flex-direction: row-reverse; }
  .cg-avatar {
    flex: 0 0 auto; width: 30px; height: 30px; border-radius: 9px;
    display: grid; place-items: center; margin-bottom: 2px;
  }
  .cg-avatar.assistant { background: linear-gradient(135deg, var(--accent), #0e8e6f); }
  .cg-avatar.user { background: linear-gradient(135deg, #6366f1, #8b5cf6); }

  .cg-bubble {
    max-width: 76%;
    padding: 11px 14px;
    border-radius: 18px;
    font-size: 14.5px; line-height: 1.55;
    word-wrap: break-word; white-space: pre-wrap;
    box-shadow: 0 2px 10px -4px rgba(0,0,0,.5);
  }
  .cg-row.assistant .cg-bubble {
    background: var(--bubble-bot);
    border: 1px solid rgba(255,255,255,.05);
    border-bottom-left-radius: 6px;
  }
  .cg-row.user .cg-bubble {
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    color: #fff;
    border-bottom-right-radius: 6px;
  }
  .cg-text {}
  .cg-time {
    margin-top: 5px; font-size: 10.5px; opacity: .6;
    text-align: right;
  }
  .cg-row.assistant .cg-time { text-align: left; }

  /* Typing indicator */
  .cg-typing { display: flex; gap: 5px; align-items: center; padding: 14px 16px; }
  .cg-typing-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--muted); animation: blink 1.4s infinite both;
  }
  .cg-typing-dot:nth-child(2) { animation-delay: .2s; }
  .cg-typing-dot:nth-child(3) { animation-delay: .4s; }
  @keyframes blink {
    0%, 80%, 100% { opacity: .25; transform: translateY(0); }
    40%           { opacity: 1;  transform: translateY(-3px); }
  }

  /* Composer */
  .cg-composer { padding: 12px 16px 16px; }
  .cg-inputwrap {
    display: flex; align-items: flex-end; gap: 8px;
    background: var(--panel-2);
    border: 1px solid rgba(255,255,255,.09);
    border-radius: 22px;
    padding: 8px 8px 8px 16px;
    transition: border-color .18s, box-shadow .18s;
  }
  .cg-inputwrap:focus-within {
    border-color: rgba(16,163,127,.65);
    box-shadow: 0 0 0 3px rgba(16,163,127,.16);
  }
  .cg-input {
    flex: 1; resize: none; border: none; outline: none; background: transparent;
    color: var(--text); font: inherit; font-size: 14.5px; line-height: 1.5;
    max-height: 160px; padding: 6px 0;
  }
  .cg-input::placeholder { color: var(--muted); }

  .cg-send {
    flex: 0 0 auto; width: 36px; height: 36px; border: none; border-radius: 50%;
    display: grid; place-items: center; cursor: pointer; color: #fff;
    background: linear-gradient(135deg, var(--accent), var(--accent-2));
    transition: transform .15s, box-shadow .15s, opacity .15s;
    box-shadow: 0 6px 16px -4px rgba(16,163,127,.7);
  }
  .cg-send:hover:not(:disabled) { transform: scale(1.08) translateY(-1px); }
  .cg-send:active:not(:disabled) { transform: scale(.94); }
  .cg-send:disabled {
    opacity: .4; cursor: not-allowed; box-shadow: none;
    background: #3a3a42;
  }

  .cg-footnote {
    margin: 10px 4px 0; text-align: center; font-size: 11px; color: var(--muted);
  }
  .cg-footnote kbd {
    background: rgba(255,255,255,.08); border: 1px solid rgba(255,255,255,.12);
    border-radius: 5px; padding: 1px 5px; font-size: 10px; font-family: inherit;
  }

  @keyframes msgIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
  @keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: none; } }

  @media (max-width: 640px) {
    .cg-app { padding: 0; }
    .cg-window { height: 100vh; max-width: 100%; border-radius: 0; border: none; }
    .cg-bubble { max-width: 82%; }
  }
`;