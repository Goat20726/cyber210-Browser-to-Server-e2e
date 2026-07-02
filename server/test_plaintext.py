"""Tests E2E OFF path: plaintext messages in the team's JSON wire format."""
import asyncio, json
from datetime import datetime, timezone
import websockets

URI = "ws://localhost:8000/ws"

async def main():
    async with websockets.connect(URI) as ws:
        for i, text in enumerate(["hello server", "this is a test prompt", "ECHO test #3"]):
            msg = {"type": "msg", "seq": i, "text": text,
                   "sender": "user", "timestamp": datetime.now(timezone.utc).isoformat()}
            await ws.send(json.dumps(msg))
            reply = json.loads(await ws.recv())
            print(f"sent: {text!r:35} -> received: {reply['text']!r}")
            assert reply["text"] == f"{text} (Echo)", f"Mismatch: {reply}"
            assert reply["sender"] == "assistant"
            assert reply["type"] == "msg"
    print("\n✅ All plaintext (E2E OFF) round trips succeeded on /ws.")

if __name__ == "__main__":
    asyncio.run(main())
