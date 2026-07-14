"""
AEGIS BACKEND — Health & Utility Endpoints
Add these routes to main.py (already has the core threat routes)
"""

# Add this to your main.py imports:
# from fastapi.responses import JSONResponse
# import time

# ── Health check ──────────────────────────────────────────────────────────────

# @app.get("/health", tags=["System"])
# async def health():
#     """Used by Docker, load balancers, and the Android app to verify connectivity."""
#     try:
#         async with db_pool.acquire() as conn:
#             await conn.fetchval("SELECT 1")
#         db_ok = True
#     except Exception:
#         db_ok = False
#
#     return JSONResponse({
#         "status":    "ok" if db_ok else "degraded",
#         "db":        "ok" if db_ok else "error",
#         "timestamp": int(time.time()),
#         "version":   "1.0.0"
#     }, status_code=200 if db_ok else 503)


# ── Paste this complete updated main.py if you want the health endpoint ───────

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from io import BytesIO
import asyncpg, os, json, time, uvicorn
import google.generativeai as genai

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

app = FastAPI(title="Aegis Threat Intelligence API", version="1.0.0")

app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["*"], allow_headers=["*"])

DATABASE_URL    = os.getenv("DATABASE_URL", "postgresql://aegis:aegispass@localhost/aegisdb")
GEMINI_API_KEY  = os.getenv("GEMINI_API_KEY", "")
REPORTS_DIR     = os.getenv("REPORTS_DIR", "/app/reports")
POLICE_THRESHOLD  = int(os.getenv("POLICE_THRESHOLD",   "100"))
COMMUNITY_MINIMUM = 3
os.makedirs(REPORTS_DIR, exist_ok=True)

db_pool: asyncpg.Pool = None

@app.on_event("startup")
async def startup():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=3, max_size=20)
    print("[Aegis] Backend started.")

@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()

# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
async def health():
    try:
        async with db_pool.acquire() as conn:
            await conn.fetchval("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False
    return JSONResponse({
        "status": "ok" if db_ok else "degraded",
        "db":     "ok" if db_ok else "error",
        "ts":     int(time.time()),
        "version": "1.0.0"
    }, status_code=200 if db_ok else 503)

# ── Models ────────────────────────────────────────────────────────────────────

class ThreatReport(BaseModel):
    threat_hash: str
    threat_type: str
    severity:    int = Field(..., ge=1, le=5)
    device_id:   str
    region:      str = "IN"
    metadata:    Optional[Dict[str, Any]] = {}

class BatchCheckRequest(BaseModel):
    hashes: List[str] = Field(..., max_items=200)

class AIAssistantQuery(BaseModel):
    question:       str
    language:       str = "en"
    threat_context: Optional[Dict] = {}

# ── Threat endpoints ──────────────────────────────────────────────────────────

@app.post("/v1/threats/report", tags=["Threats"])
async def report_threat(report: ThreatReport, bg: BackgroundTasks):
    async with db_pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id, report_count FROM threats WHERE hash=$1", report.threat_hash)
        if existing:
            await conn.execute("""
                UPDATE threats
                SET report_count=report_count+1, last_seen=NOW(), severity=GREATEST(severity,$2)
                WHERE hash=$1
            """, report.threat_hash, report.severity)
            new_count = existing["report_count"] + 1
        else:
            await conn.execute("""
                INSERT INTO threats(hash,type,severity,first_seen,last_seen,report_count,metadata,region)
                VALUES($1,$2,$3,NOW(),NOW(),1,$4,$5)
            """, report.threat_hash, report.threat_type,
                report.severity, json.dumps(report.metadata), report.region)
            new_count = 1
        try:
            await conn.execute("""
                INSERT INTO threat_events(hash,device_id,timestamp)
                VALUES($1,$2,NOW())
                ON CONFLICT(hash,device_id) DO UPDATE SET timestamp=NOW()
            """, report.threat_hash, report.device_id)
        except Exception:
            pass
        if new_count == POLICE_THRESHOLD:
            bg.add_task(generate_police_report)
    return {"status":"ok","hash":report.threat_hash,"report_count":new_count}

@app.post("/v1/threats/batch-check", tags=["Threats"])
async def batch_check(req: BatchCheckRequest):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT hash,severity,report_count,type FROM threats
            WHERE hash=ANY($1) AND report_count>=$2
        """, req.hashes, COMMUNITY_MINIMUM)
        results = {h: {"is_threat": False} for h in req.hashes}
        for r in rows:
            results[r["hash"]] = {
                "is_threat":    True,
                "severity":     r["severity"],
                "report_count": r["report_count"],
                "type":         r["type"]
            }
    return results

@app.get("/v1/threats/recent", tags=["Threats"])
async def recent_threats(limit: int = 500, threat_type: Optional[str] = None,
                         min_severity: int = 1):
    async with db_pool.acquire() as conn:
        if threat_type:
            rows = await conn.fetch("""
                SELECT hash,type,severity,report_count,first_seen FROM threats
                WHERE type=$1 AND report_count>=$2 AND severity>=$3
                ORDER BY last_seen DESC LIMIT $4
            """, threat_type, COMMUNITY_MINIMUM, min_severity, limit)
        else:
            rows = await conn.fetch("""
                SELECT hash,type,severity,report_count,first_seen FROM threats
                WHERE report_count>=$1 AND severity>=$2
                ORDER BY last_seen DESC LIMIT $3
            """, COMMUNITY_MINIMUM, min_severity, limit)
    return [dict(r) for r in rows]

@app.get("/v1/dashboard/stats", tags=["Dashboard"])
async def stats():
    async with db_pool.acquire() as conn:
        s = await conn.fetchrow("""
            SELECT
                COUNT(*)                                                  AS total_threats,
                COUNT(*) FILTER(WHERE first_seen>NOW()-'24h'::interval)   AS threats_24h,
                COUNT(*) FILTER(WHERE first_seen>NOW()-'7d'::interval)    AS threats_7d,
                COUNT(*) FILTER(WHERE severity>=4)                        AS critical,
                COALESCE(SUM(report_count),0)                             AS total_reports,
                COUNT(*) FILTER(WHERE police_reported)                    AS police_reported,
                COUNT(DISTINCT region)                                    AS regions
            FROM threats
        """)
        by_type = await conn.fetch("""
            SELECT type, COUNT(*) AS count FROM threats
            WHERE report_count>=$1 GROUP BY type ORDER BY count DESC
        """, COMMUNITY_MINIMUM)
    return {**dict(s), "by_type": {r["type"]: r["count"] for r in by_type}}

@app.get("/v1/dashboard/trend", tags=["Dashboard"])
async def trend(days: int = 7):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT date_trunc('hour',first_seen) AS hour, COUNT(*) AS count
            FROM threats WHERE first_seen>NOW()-($1||' days')::interval
            GROUP BY 1 ORDER BY 1
        """, str(days))
    return [dict(r) for r in rows]

@app.post("/v1/assistant/ask", tags=["Assistant"])
async def ask(query: AIAssistantQuery):
    if not GEMINI_API_KEY:
        raise HTTPException(503, "AI assistant not configured — set GEMINI_API_KEY")
    genai.configure(api_key=GEMINI_API_KEY)
    system = f"""You are Aegis, an expert mobile security assistant. Help users understand
and respond to Android security threats. Be concise (under 200 words). Use plain language.
Always respond in language: {query.language}.
{f"Recent device threat context: {json.dumps(query.threat_context)}" if query.threat_context else ""}"""
    model = genai.GenerativeModel('gemini-1.5-pro', system_instruction=system)
    resp = model.generate_content(query.question)
    return {"answer": resp.text, "language": query.language}

@app.get("/v1/reports/list", tags=["Reports"])
async def list_reports():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id,report_path,threat_count,generated_at,status FROM police_reports ORDER BY generated_at DESC LIMIT 20")
    return [dict(r) for r in rows]

@app.post("/v1/reports/generate-now", tags=["Reports"])
async def gen_report_now(bg: BackgroundTasks):
    bg.add_task(generate_police_report)
    return {"status": "Report generation queued"}

# ── Police report generator ───────────────────────────────────────────────────

async def generate_police_report():
    async with db_pool.acquire() as conn:
        threats = await conn.fetch("""
            SELECT hash,type,severity,report_count,first_seen,last_seen,region
            FROM threats WHERE report_count>=$1 AND severity>=3 AND NOT police_reported
            ORDER BY report_count DESC LIMIT 100
        """, POLICE_THRESHOLD)
        if not threats:
            return
        stats = await conn.fetchrow(
            "SELECT SUM(report_count) AS total, COUNT(DISTINCT region) AS regions FROM threats WHERE hash=ANY($1)",
            [t["hash"] for t in threats]
        )

    ts   = datetime.utcnow()
    name = f"AEGIS_CERT_{ts.strftime('%Y%m%d_%H%M%S')}.pdf"
    path = os.path.join(REPORTS_DIR, name)

    doc      = SimpleDocTemplate(path, pagesize=A4, rightMargin=40, leftMargin=40,
                                  topMargin=60, bottomMargin=40)
    styles   = getSampleStyleSheet()
    content  = []
    sev_map  = {5:"EMERGENCY",4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW"}

    content.append(Paragraph("AEGIS CYBERSECURITY THREAT INTELLIGENCE REPORT", styles["Title"]))
    content.append(Paragraph("FOR OFFICIAL USE — CERT-In / Cyber Crime Division", styles["Italic"]))
    content.append(Spacer(1,12))
    content.append(Paragraph("Executive Summary", styles["Heading1"]))
    content.append(Paragraph(
        f"The Aegis CTI Network identified <b>{len(threats)}</b> high-severity threats across "
        f"<b>{stats['regions']}</b> regions, confirmed by <b>{stats['total']:,}</b> device reports.",
        styles["Normal"]))
    content.append(Spacer(1,16))

    rows = [["#","Type","Severity","Reports","First Seen","Hash (truncated)"]]
    for i, t in enumerate(threats, 1):
        rows.append([str(i), t["type"], sev_map.get(t["severity"],"?"),
                     str(t["report_count"]), t["first_seen"].strftime("%Y-%m-%d"),
                     t["hash"][:20]+"..."])

    tbl = Table(rows, colWidths=[25,70,80,60,90,175])
    tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1a1245")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,-1),9),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#F8F8F8")]),
        ("GRID",(0,0),(-1,-1),0.25,colors.HexColor("#CCCCCC")),
        ("PADDING",(0,0),(-1,-1),5),
    ]))
    content.append(tbl)
    content.append(Spacer(1,16))
    content.append(Paragraph(
        "Privacy notice: Only SHA-256 hashes are stored. No raw URLs, phone numbers, "
        "or user data appear in this report.", styles["Italic"]))
    doc.build(content)

    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE threats SET police_reported=TRUE WHERE hash=ANY($1)",
            [t["hash"] for t in threats])
        await conn.execute(
            "INSERT INTO police_reports(report_path,threat_count,generated_at) VALUES($1,$2,NOW())",
            path, len(threats))
    print(f"[Aegis] Police report: {path}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
