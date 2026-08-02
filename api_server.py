from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from scan_notice import score_notice
import uvicorn

app = FastAPI(
    title="CSPS Forensic Analysis API",
    description="Enterprise API for multi-vector impersonation detection and IOC extraction.",
    version="1.0.0"
)

# Allow the frontend HTML file to make requests to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    sender_email: str
    body_text: str
    raw_headers: str = ""

@app.post("/api/v1/scan")
def analyze_notice_endpoint(request: ScanRequest):
    result = score_notice(
        sender_email=request.sender_email,
        body_text=request.body_text,
        raw_headers=request.raw_headers
    )
    return {
        "status": "success",
        "analysis": result
    }

if __name__ == "__main__":
    print("Starting CSPS Enterprise API on port 8000...")
    uvicorn.run(app, host="127.0.0.1", port=8000)
