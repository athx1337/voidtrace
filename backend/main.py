"""
VOIDTRACE — IP Intelligence Tool
FastAPI backend — single endpoint, all modules run in parallel
"""

import asyncio
import os
import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv
import socket
import re

load_dotenv()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY")
OTX_KEY = os.getenv("OTX_API_KEY")
GREYNOISE_KEY = os.getenv("GREYNOISE_KEY")

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="VOIDTRACE — IP Intelligence API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def is_valid_ip(ip: str) -> bool:
    pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if not re.match(pattern, ip):
        return False
    parts = ip.split(".")
    return all(0 <= int(p) <= 255 for p in parts)


class LookupRequest(BaseModel):
    ip: str


@app.get("/api/ping")
async def ping():
    return {"status": "online", "tool": "VOIDTRACE", "version": "1.0"}


@app.post("/api/lookup")
@limiter.limit("20/minute")
async def lookup(request: Request, body: LookupRequest):
    ip = body.ip.strip()

    if not is_valid_ip(ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    # Run all modules concurrently
    geo, flags, shodan, abuse, otx, greynoise, rdns = await asyncio.gather(
        _geo(ip),
        _flags(ip),
        _shodan(ip),
        _abuseipdb(ip),
        _otx(ip),
        _greynoise(ip),
        asyncio.to_thread(_rdns, ip),
        return_exceptions=False,
    )

    # Verdict logic
    flagged = 0
    if abuse.get("abuse_score", 0) > 25:
        flagged += 1
    if otx.get("pulse_count", 0) > 0:
        flagged += 1
    if greynoise.get("classification") == "malicious":
        flagged += 1
    if abuse.get("is_tor"):
        flagged += 1

    if flagged >= 2:
        verdict = "MALICIOUS"
    elif flagged == 1:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return {
        "ip": ip,
        "geo": geo,
        "flags": flags,
        "shodan": shodan,
        "abuse": abuse,
        "otx": otx,
        "greynoise": greynoise,
        "rdns": rdns,
        "verdict": verdict,
        "flagged_signals": flagged,
    }


# ── Modules ──────────────────────────────────────────────

async def _geo(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "country,countryCode,regionName,city,isp,org,as,query,hosting,proxy,mobile"}
            )
            d = r.json()
            return {
                "available": True,
                "country": d.get("country"),
                "country_code": d.get("countryCode"),
                "region": d.get("regionName"),
                "city": d.get("city"),
                "isp": d.get("isp"),
                "org": d.get("org"),
                "asn": d.get("as"),
                "is_hosting": d.get("hosting", False),
                "is_proxy": d.get("proxy", False),
                "is_mobile": d.get("mobile", False),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _flags(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(f"https://api.ipapi.is?q={ip}")
            d = r.json()
            return {
                "available": True,
                "is_datacenter": d.get("is_datacenter", False),
                "is_tor": d.get("is_tor", False),
                "is_vpn": d.get("is_vpn", False),
                "is_proxy": d.get("is_proxy", False),
                "is_abuser": d.get("is_abuser", False),
                "company": d.get("company", {}).get("name"),
                "asn_name": d.get("asn", {}).get("org"),
                "asn_number": d.get("asn", {}).get("asn"),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _shodan(ip: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(f"https://internetdb.shodan.io/{ip}")
            if r.status_code == 404:
                return {"available": True, "ports": [], "vulns": [], "cpes": [], "tags": [], "hostnames": []}
            d = r.json()
            return {
                "available": True,
                "ports": d.get("ports", []),
                "vulns": d.get("vulns", []),
                "cpes": d.get("cpes", []),
                "tags": d.get("tags", []),
                "hostnames": d.get("hostnames", []),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_KEY:
        return {"available": False, "reason": "ABUSEIPDB_KEY not set"}
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
            d = r.json().get("data", {})
            return {
                "available": True,
                "abuse_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "last_reported": d.get("lastReportedAt"),
                "is_tor": d.get("isTor", False),
                "usage_type": d.get("usageType", ""),
                "isp": d.get("isp", ""),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _otx(ip: str) -> dict:
    if not OTX_KEY:
        return {"available": False, "reason": "OTX_API_KEY not set"}
    try:
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_KEY},
            )
            d = r.json()
            pulse_count = d.get("pulse_info", {}).get("count", 0)
            pulses = d.get("pulse_info", {}).get("pulses", [])
            malware = list({
                p.get("malware_families", [{}])[0].get("display_name", "")
                for p in pulses if p.get("malware_families")
            })
            tags = list({tag for p in pulses for tag in p.get("tags", [])})[:6]
            return {
                "available": True,
                "pulse_count": pulse_count,
                "malware_families": [m for m in malware if m],
                "tags": tags,
                "flagged": pulse_count > 0,
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


async def _greynoise(ip: str) -> dict:
    try:
        headers = {"key": GREYNOISE_KEY} if GREYNOISE_KEY else {}
        async with httpx.AsyncClient(timeout=6) as client:
            r = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers=headers,
            )
            if r.status_code == 404:
                return {"available": True, "noise": False, "riot": False, "classification": "unknown", "name": None}
            d = r.json()
            return {
                "available": True,
                "noise": d.get("noise", False),
                "riot": d.get("riot", False),
                "classification": d.get("classification", "unknown"),
                "name": d.get("name"),
            }
    except Exception as e:
        return {"available": False, "error": str(e)}


def _rdns(ip: str) -> dict:
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return {"available": True, "hostname": hostname}
    except Exception:
        return {"available": True, "hostname": None}
