from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse # <-- Imported here
import json
from itertools import count

app = FastAPI()


# Example 1: Standard HTTP GET route using JSONResponse
@app.get("/api/status")
async def get_status():
    # Useful for manually setting status codes or custom headers
    return JSONResponse(
        status_code=200,
        content={"status": "online", "websocket_route": "/ws"}
    )
@app.get("/api/health")
async def get_health():
    # Useful for manually setting status codes or custom headers
    return JSONResponse(
        status_code=200,
        content={"status": "ok"}
    )

# Your existing WebSocket code stays exactly the same
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    print("Client connected")

    try:
        while True:
            message_data = await websocket.receive_json()
            
            echo_data = {
                "seq" : message_data.get('seq') + 1,
                "text": f"{message_data.get('text')} (Echo)",
                'sender': "assistant",
                "type": "msg",                
                "timestamp": message_data.get("timestamp")
            }
            await websocket.send_json(echo_data)
    except WebSocketDisconnect:
        print("Client disconnected gracefully")
    except Exception as e:
        print(f"An error occurred: {e}")
