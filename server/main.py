from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
import time

app = FastAPI()

@app.get("/health", status_code=status.HTTP_200_OK)
async def health_check():
    return {
        
        "ok": True
        
    }
