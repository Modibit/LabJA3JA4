"""
FastAPI Backend for TLS Fingerprint Lab.
Provides real-time JA3 and JA4 calculation, PCAP inspection,
sample PCAP downloads, and tshark environment status.
"""

import shutil
import subprocess
import sys
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.fingerprint import compute_ja3, compute_ja4
from app.tls_parser import parse_pcap_bytes
from app.sample_pcaps import (
    SAMPLE_PROFILES,
    generate_sample_pcap_bytes
)

app = FastAPI(
    title="TLS Fingerprint Lab API",
    description="Backend engine for JA3 & JA4 educational analysis",
    version="1.0.0"
)

# Enable CORS for local dev & classroom offline use
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------------------

class JA3Request(BaseModel):
    version: int = Field(771, description="TLS Version as decimal (e.g. 771 for 0x0303)")
    ciphers: List[int] = Field(..., description="List of cipher suite numbers")
    extensions: List[int] = Field(..., description="List of extension numbers")
    curves: Optional[List[int]] = Field(default=[], description="Supported groups")
    point_formats: Optional[List[int]] = Field(default=[], description="EC point formats")

class JA4Request(BaseModel):
    protocol: str = Field("t", description="Protocol: 't' for TCP, 'q' for QUIC, 'd' for DTLS")
    version: int = Field(771, description="TLS Version (e.g. 771 or 0x0303)")
    has_sni: bool = Field(True, description="Whether SNI is present")
    sni_is_ip: bool = Field(False, description="Whether SNI is an IP address")
    ciphers: List[int] = Field(..., description="List of cipher suites")
    extensions: List[int] = Field(..., description="List of extensions")
    alpn_protocols: Optional[List[str]] = Field(default=[], description="ALPN protocols list")
    signature_algorithms: Optional[List[int]] = Field(default=[], description="Signature algorithms")
    supported_versions: Optional[List[int]] = Field(default=[], description="Supported versions extension")

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "app": "TLS Fingerprint Lab"}

@app.get("/api/system/status")
def system_status():
    """
    Check if tshark / wireshark is installed and report system environment.
    """
    tshark_path = shutil.which("tshark")
    tshark_version = None
    if tshark_path:
        try:
            out = subprocess.check_output([tshark_path, "-v"], text=True, stderr=subprocess.STDOUT)
            tshark_version = out.splitlines()[0] if out else None
        except Exception as e:
            tshark_version = f"Error reading version: {e}"

    return {
        "status": "ok",
        "python_version": sys.version,
        "tshark_installed": bool(tshark_path),
        "tshark_path": tshark_path,
        "tshark_version": tshark_version,
        "native_pcap_parser": True,
        "offline_ready": True
    }

@app.post("/api/ja3/compute")
def api_compute_ja3(req: JA3Request):
    raw, md5_hash, meta = compute_ja3(
        version=req.version,
        ciphers=req.ciphers,
        extensions=req.extensions,
        curves=req.curves,
        point_formats=req.point_formats
    )
    return {
        "raw": raw,
        "md5": md5_hash,
        "meta": meta
    }

@app.post("/api/ja4/compute")
def api_compute_ja4(req: JA4Request):
    full_ja4, details = compute_ja4(
        protocol=req.protocol,
        version=req.version,
        has_sni=req.has_sni,
        sni_is_ip=req.sni_is_ip,
        ciphers=req.ciphers,
        extensions=req.extensions,
        alpn_protocols=req.alpn_protocols,
        signature_algorithms=req.signature_algorithms,
        supported_versions=req.supported_versions
    )
    return {
        "ja4": full_ja4,
        "details": details
    }

@app.get("/api/pcap/samples")
def list_samples():
    """
    List all pre-bundled educational PCAP captures.
    """
    samples = []
    for key, data in SAMPLE_PROFILES.items():
        samples.append({
            "id": key,
            "title": data["title"],
            "client_name": data["client_name"],
            "description": data["description"],
            "sni": data["sni"],
            "alpn": data["alpn"],
            "ciphers_count": len(data["ciphers"]),
            "extensions_count": len(data["extensions"]),
            "download_url": f"/api/pcap/samples/{key}/download",
            "analyze_url": f"/api/pcap/samples/{key}/analyze"
        })
    return {"samples": samples}

@app.get("/api/pcap/samples/{sample_id}/download")
def download_sample(sample_id: str):
    """
    Download authentic binary PCAP capture file.
    """
    if sample_id not in SAMPLE_PROFILES:
        raise HTTPException(status_code=404, detail="فایل نمونه مورد نظر یافت نشد.")

    pcap_bytes = generate_sample_pcap_bytes(sample_id)
    return Response(
        content=pcap_bytes,
        media_type="application/vnd.tcpdump.pcap",
        headers={"Content-Disposition": f'attachment; filename="{sample_id}"'}
    )

@app.get("/api/pcap/samples/{sample_id}/analyze")
def analyze_sample(sample_id: str):
    """
    Directly analyze a bundled sample PCAP.
    """
    if sample_id not in SAMPLE_PROFILES:
        raise HTTPException(status_code=404, detail="فایل نمونه مورد نظر یافت نشد.")

    pcap_bytes = generate_sample_pcap_bytes(sample_id)
    packets = parse_pcap_bytes(pcap_bytes)
    return {
        "success": True,
        "sample_id": sample_id,
        "count": len(packets),
        "packets": packets
    }

@app.post("/api/pcap/analyze")
async def analyze_uploaded_pcap(file: UploadFile = File(...)):
    """
    Upload and parse user .pcap or .pcapng file.
    Extracts TLS ClientHello packets and calculates JA3 & JA4.
    """
    filename = file.filename or "upload.pcap"
    contents = await file.read()

    if len(contents) < 24:
        return {
            "success": False,
            "error": "اندازه فایل ارسالی بسیار کوچک است یا قالب معتبر PCAP ندارد.",
            "packets": []
        }

    try:
        packets = parse_pcap_bytes(contents)
    except Exception as e:
        return {
            "success": False,
            "error": f"خطا در پردازش باینری بسته: {str(e)}",
            "packets": []
        }

    if not packets:
        return {
            "success": True,
            "count": 0,
            "warning": "فایل تجزیه شد اما هیچ بسته حاوی TLS ClientHello (دست‌دهی اولیه) در آن شناسایی نشد.",
            "packets": []
        }

    return {
        "success": True,
        "filename": filename,
        "file_size": len(contents),
        "count": len(packets),
        "packets": packets
    }
