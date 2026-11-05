import os
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import Dict, Any

# Hamare core forensic modules jo humne test kiye the
from .parser import extract_basic_info, parse_received_headers, get_earliest_reliable_ip
from .dns_auth import verify_spf, verify_dkim, verify_dmarc, verify_alignment
from .geoip import get_ip_geolocation
from .classifier import analyze_body_content
from .scoring import compute_fraud_risk_score

app = FastAPI(
    title="AI Email Threat Detection & Forensic Intelligence Platform",
    description="Automated forensic analysis for email spoofing, origin geolocation, and phishing risk scoring.",
    version="1.0.0"
)

# CORS Middleware taaki frontend backend se safely communicate kar sake
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Frontend folder ka path define karte hain
frontend_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
)

def run_email_analysis_pipeline(raw_email: str) -> Dict[str, Any]:
    """
    Core business logic jo pure email pipeline ko run karti hai
    aur structured response dictionary return karti hai.
    """
    raw_bytes = raw_email.encode("utf-8", errors="ignore")

    # 1. Header Extraction
    header_info = extract_basic_info(raw_email)

    # 2. Hop Tracing & Earliest Public IP
    hops = parse_received_headers(raw_email)
    origin_ip = get_earliest_reliable_ip(hops)

    # 3. Geolocation & Threat Intel
    geo_results = get_ip_geolocation(origin_ip)

    # 4. DNS Authentication Checks
    sender_domain = header_info.get("sender_domain", "")
    return_path = header_info.get("return_path", "")

    spf_res = verify_spf(sender_domain, origin_ip)
    dkim_res = verify_dkim(raw_bytes)
    dmarc_res = verify_dmarc(sender_domain)
    alignment_res = verify_alignment(sender_domain, return_path, raw_bytes)

    dns_results = {
        "spf": spf_res,
        "dkim": dkim_res,
        "dmarc": dmarc_res
    }

    # 5. Body & Link NLP Scanning
    content_results = analyze_body_content(raw_email, sender_domain)

    # 6. Fraud Risk Score Computation
    scoring_result = compute_fraud_risk_score(
        dns_results=dns_results,
        alignment_results=alignment_res,
        content_results=content_results,
        geo_results=geo_results,
        header_info=header_info
    )

    return {
        "subject": header_info.get("subject", "(No Subject)"),
        "sender": header_info.get("from", "Unknown"),
        "sender_domain": sender_domain,
        "recipient": header_info.get("to", ""),
        "date": header_info.get("date", ""),
        "reply_to": header_info.get("reply_to", ""),
        "return_path": return_path,
        "risk_score": scoring_result["score"],
        "verdict": scoring_result["verdict"],
        "score_breakdown": scoring_result["breakdown"],
        "origin_geo": geo_results,
        "hops": hops,
        "dns": dns_results,
        "alignment": alignment_res,
        "content_analysis": content_results,
        "raw_headers": raw_email
    }


# Root route: Frontend index.html serve karega (jab hum frontend banayenge)
@app.get("/")
async def read_index():
    index_path = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "Email Forensic Platform Backend is running. Open /docs to test APIs!"}


# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "email-threat-platform",
        "version": "1.0.0"
    }


# Route 1: Raw email text analyze karne ke liye
@app.post("/api/analyze/raw")
async def analyze_raw_email(raw_content: str = Form(...)):
    if not raw_content.strip():
        raise HTTPException(status_code=400, detail="Email content cannot be empty.")
    try:
        return run_email_analysis_pipeline(raw_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# Route 2: .eml file upload karke analyze karne ke liye
@app.post("/api/analyze/file")
async def analyze_file_email(file: UploadFile = File(...)):
    try:
        content_bytes = await file.read()
        raw_content = content_bytes.decode("utf-8", errors="ignore")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to read file: {str(e)}")

    if not raw_content.strip():
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        return run_email_analysis_pipeline(raw_content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


# Static files mount karte hain (CSS / JS)
if os.path.exists(frontend_dir):
    app.mount("/frontend", StaticFiles(directory=frontend_dir), name="frontend")
