from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator
from supabase import Client, create_client

from analyzer import UnsafeTargetError, analyze_url
from gemini_client import get_ai_explanation

load_dotenv()

MAX_URL_LENGTH = 2048
HISTORY_LIMIT = 20

class ConsequenceStep(BaseModel):
    step: str
    description: str
    risk: str

class ThreatAssessmentItem(BaseModel):
    status: bool
    details: str = ""

class ScanReport(BaseModel):
    id: str
    url: str
    domain: str
    trust_score: int = Field(ge=0, le=100)
    risk_level: str
    domain_age_days: Optional[int]
    registrar: str
    https_enabled: bool
    suspicious_patterns: list[str]
    ghost_summary: str
    ghost_summary_en: str
    ai_explanation: str
    recommendations: list[str]
    consequences: list[ConsequenceStep]
    created_at: str
    crawled_page_content: Optional[dict[str, Any]] = None
    scorecard: Optional[dict[str, Any]] = None
    threat_assessment: Optional[dict[str, Any]] = None

class ScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=MAX_URL_LENGTH)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("URL cannot be empty.")
        return normalized

def get_cors_origins() -> list[str]:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    return [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]

app = FastAPI(title="GhostNet Backend", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)

supabase_client: Optional[Client] = None
supabase_url = os.getenv("SUPABASE_URL")
supabase_key = os.getenv("SUPABASE_KEY")

if supabase_url and supabase_key:
    try:
        supabase_client = create_client(supabase_url, supabase_key)
    except Exception:
        supabase_client = None

in_memory_scans: list[dict[str, Any]] = []
in_memory_lock = Lock()

def store_in_memory(report: dict[str, Any]) -> None:
    with in_memory_lock:
        in_memory_scans.insert(0, report)
        del in_memory_scans[HISTORY_LIMIT:]

def build_storage_row(report: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": report["id"],
        "url": report["url"],
        "domain": report["domain"],
        "trust_score": report["trust_score"],
        "risk_level": report["risk_level"],
        "domain_age_days": report["domain_age_days"],
        "registrar": report["registrar"],
        "https_enabled": report["https_enabled"],
        "suspicious_patterns": report["suspicious_patterns"],
        "ghost_summary": report["ghost_summary"],
        "ghost_summary_en": report["ghost_summary_en"],
        "ai_explanation": report["ai_explanation"],
        "recommendations": report["recommendations"],
        "consequences": report["consequences"],
        "crawled_page_content": report.get("crawled_page_content"),
        "scorecard": report.get("scorecard"),
        "threat_assessment": report.get("threat_assessment"),
        "created_at": report["created_at"],
    }

def row_to_report(row: dict[str, Any]) -> dict[str, Any]:
    return ScanReport.model_validate(
        {
            "id": str(row.get("id")),
            "url": row.get("url", ""),
            "domain": row.get("domain", ""),
            "trust_score": row.get("trust_score", 0),
            "risk_level": row.get("risk_level", "Medium Risk"),
            "domain_age_days": row.get("domain_age_days"),
            "registrar": row.get("registrar") or "Unknown",
            "https_enabled": bool(row.get("https_enabled")),
            "suspicious_patterns": row.get("suspicious_patterns") or [],
            "ghost_summary": row.get("ghost_summary") or "",
            "ghost_summary_en": row.get("ghost_summary_en") or "",
            "ai_explanation": row.get("ai_explanation") or "",
            "recommendations": row.get("recommendations") or [],
            "consequences": row.get("consequences") or [],
            "created_at": row.get("created_at") or datetime.now(timezone.utc).isoformat(),
            "crawled_page_content": row.get("crawled_page_content"),
            "scorecard": row.get("scorecard"),
            "threat_assessment": row.get("threat_assessment"),
        }
    ).model_dump()

async def save_report(report: dict[str, Any]) -> None:
    if not supabase_client:
        store_in_memory(report)
        return
    try:
        supabase_client.table("scans").insert(build_storage_row(report)).execute()
    except Exception:
        store_in_memory(report)

@app.get("/", response_class=HTMLResponse)
async def read_root() -> HTMLResponse:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if not os.path.isfile(template_path):
        raise HTTPException(status_code=404, detail="GhostNet template is unavailable.")
    with open(template_path, "r", encoding="utf-8") as template_file:
        return HTMLResponse(content=template_file.read())

@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "database": "supabase" if supabase_client else "memory"}

@app.post("/api/scan", response_model=ScanReport)
async def scan_website(request: ScanRequest) -> ScanReport:
    try:
        analysis = await analyze_url(request.url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(status_code=502, detail="Website analysis failed before a report could be generated.")

    try:
        ai_response = await get_ai_explanation(analysis)
    except Exception:
        ai_response = {}

    report = ScanReport(
        id=str(uuid.uuid4()),
        url=analysis["url"],
        domain=analysis["domain"],
        trust_score=int(ai_response.get("trust_score", analysis["base_trust_score"])),
        risk_level=str(ai_response.get("risk_level", "Medium Risk")),
        domain_age_days=analysis.get("domain_age_days"),
        registrar=analysis.get("registrar", "Unknown"),
        https_enabled=bool(analysis.get("https_enabled")),
        suspicious_patterns=list(analysis.get("suspicious_patterns", [])),
        ghost_summary=str(ai_response.get("ghost_summary", "")),
        ghost_summary_en=str(ai_response.get("ghost_summary_en", "")),
        ai_explanation=str(ai_response.get("ai_explanation", "")),
        recommendations=list(ai_response.get("recommendations", [])),
        consequences=[ConsequenceStep.model_validate(item) for item in ai_response.get("consequences", [])],
        created_at=datetime.now(timezone.utc).isoformat(),
        crawled_page_content=analysis.get("crawled_page_content"),
        scorecard=analysis.get("scorecard"),
        threat_assessment=ai_response.get("threat_assessment"),
    )
    await save_report(report.model_dump())
    return report

@app.get("/api/history", response_model=list[ScanReport])
async def get_history() -> list[ScanReport]:
    if supabase_client:
        try:
            response = (
                supabase_client.table("scans")
                .select("*")
                .order("created_at", desc=True)
                .limit(HISTORY_LIMIT)
                .execute()
            )
            return [ScanReport.model_validate(row_to_report(row)) for row in (response.data or [])]
        except Exception:
            pass
    with in_memory_lock:
        return [ScanReport.model_validate(item) for item in in_memory_scans[:HISTORY_LIMIT]]

@app.middleware("http")
async def request_size_limit(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > 32_768:
                return HTMLResponse(content="Request body too large.", status_code=413)
        except ValueError:
            return HTMLResponse(content="Invalid content length.", status_code=400)
    return await call_next(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=int(os.getenv("PORT", "8000")))
