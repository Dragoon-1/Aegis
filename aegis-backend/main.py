"""
AEGIS THREAT INTELLIGENCE BACKEND
FastAPI + PostgreSQL backend for the Aegis Android Security System.

Responsibilities:
  1. Receive anonymized threat reports from all Aegis devices
  2. Aggregate patterns — when many users report the same threat, escalate
  3. Generate PDF reports for cyber police / CERT-In automatically
  4. Sync blocklists to devices (blockchain supplements this)
  5. Power the AI assistant (proxies Claude API with security context)
  6. Serve threat analytics dashboard
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from io import BytesIO
import asyncpg
import os
import hashlib
import json
import google.generativeai as genai
import uvicorn

# ── ReportLab for PDF generation ─────────────────────────────────────────────
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from web3 import Web3
from eth_account import Account
app = FastAPI(
    title="Aegis Threat Intelligence API",
    description="Backend for Aegis Android Security — collective threat intelligence",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://aegis:aegispass@localhost/aegisdb")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
REPORTS_DIR = "/app/reports"
POLYGON_PRIVATE_KEY = os.getenv("POLYGON_PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.getenv("CONTRACT_ADDRESS", "")
POLYGON_RPC_URL = os.getenv("POLYGON_RPC_URL", "https://rpc-amoy.polygon.technology/")
os.makedirs(REPORTS_DIR, exist_ok=True)

w3 = Web3(Web3.HTTPProvider(POLYGON_RPC_URL))

# Minimal ABI required to call reportThreat-------------------------------------------------------------------------
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType": "bytes32", "name": "threatHash", "type": "bytes32"},
            {"internalType": "uint8", "name": "category", "type": "uint8"},
            {"internalType": "uint8", "name": "severity", "type": "uint8"},
            {"internalType": "string", "name": "metadata", "type": "string"}
        ],
        "name": "reportThreat",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

contract = None
if CONTRACT_ADDRESS:
    contract = w3.eth.contract(address=w3.to_checksum_address(CONTRACT_ADDRESS), abi=CONTRACT_ABI)
# Thresholds for escalation
POLICE_THRESHOLD  = 100   # Unique device reports before police alert
COMMUNITY_MINIMUM = 5    # Minimum reports before threat is shared to network
MASS_ATTACK_LIMIT = 50  # Reports/hour = mass attack declaration




def post_threat_to_blockchain(threat_hash: str, threat_type: str, severity: int):
    if not POLYGON_PRIVATE_KEY or not contract:
        print("[Blockchain] Missing private key or contract address. Skipping.")
        return
        
    try:
        account = Account.from_key(POLYGON_PRIVATE_KEY)
        
        # Map Android threat types to contract categories
        TYPE_TO_CATEGORY = {
            "RANSOMWARE_ATTEMPT": 5, "RANSOMWARE_CONFIRMED": 5,
            "MALICIOUS_URL": 0, "SMS_PHISHING": 1, 
            "NETWORK_THREAT": 3, "DANGEROUS_APP": 4, 
            "PERMISSION_ABUSE": 4, "MALICIOUS_OVERLAY": 0
        }
        category = TYPE_TO_CATEGORY.get(threat_type, 0)
        
        # Convert hex string to 32 bytes
        hash_bytes = bytes.fromhex(threat_hash.replace('0x', ''))
        
        # 1. Get Nonce
        nonce = w3.eth.get_transaction_count(account.address)
        
        # 2. Build Transaction
        tx = contract.functions.reportThreat(
            hash_bytes,
            category,
            severity,
            "Aegis Backend Report"
        ).build_transaction({
            'chainId': 80002, # 80002 is Polygon Amoy Testnet
            'gas': 300000,
            'maxFeePerGas': w3.eth.gas_price,
            'maxPriorityFeePerGas': w3.eth.gas_price,
            'nonce': nonce,
        })
        
        # 3. Sign & Send
        signed_tx = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        print(f"[Blockchain] SUCCESS! Tx Hash: https://amoy.polygonscan.com/tx/{w3.to_hex(tx_hash)}")
        
    except Exception as e:
        print(f"[Blockchain Error]: {e}")

# ── Startup / Shutdown ────────────────────────────────────────────────────────

db_pool: asyncpg.Pool = None

@app.on_event("startup")
async def startup():
    global db_pool
    db_pool = await asyncpg.create_pool(DATABASE_URL, min_size=3, max_size=20)
    print(f"[Aegis] Backend started. DB connected.")

@app.on_event("shutdown")
async def shutdown():
    if db_pool:
        await db_pool.close()

# ── Request / Response Models ─────────────────────────────────────────────────

class ThreatReport(BaseModel):
    threat_hash:  str = Field(..., description="SHA-256 of the threat indicator")
    threat_type:  str = Field(..., description="URL | PHONE | FILE_HASH | IP | APP")
    severity:     int = Field(..., ge=1, le=5)
    device_id:    str = Field(..., description="SHA-256 of anonymous device fingerprint")
    region:       str = Field(default="IN", description="ISO 3166-1 alpha-2 country code")
    metadata:     Optional[Dict[str, Any]] = {}

class BatchCheckRequest(BaseModel):
    hashes: List[str] = Field(..., max_items=200)

class BlocklistSyncRequest(BaseModel):
    device_id:        str
    last_sync_cursor: Optional[int] = 0

class AIAssistantQuery(BaseModel):
    question:   str
    language:   str = "en"
    threat_context: Optional[Dict] = {}

# ── Core Threat Endpoints ─────────────────────────────────────────────────────

@app.post("/v1/threats/report", tags=["Threat Intelligence"])
async def report_threat(report: ThreatReport, bg: BackgroundTasks):
    """
    Receive an anonymized threat report from an Aegis device.

    The device hashes the raw threat indicator before sending — we never see
    the actual URL, phone number, or file contents. Only the SHA-256 hash.
    """
    async with db_pool.acquire() as conn:
        existing = await conn.fetchrow(
            "SELECT id, report_count FROM threats WHERE hash = $1",
            report.threat_hash
        )

        if existing:
            await conn.execute("""
                UPDATE threats
                SET report_count = report_count + 1,
                    last_seen    = NOW(),
                    severity     = GREATEST(severity, $2)
                WHERE hash = $1
            """, report.threat_hash, report.severity)
            new_count = existing["report_count"] + 1
        else:
            await conn.execute("""
                INSERT INTO threats
                    (hash, type, severity, first_seen, last_seen, report_count, metadata, region)
                VALUES ($1, $2, $3, NOW(), NOW(), 1, $4, $5)
            """, report.threat_hash, report.threat_type,
                report.severity, json.dumps(report.metadata), report.region)
            new_count = 1

        # Log individual device report (for deduplication)
        await conn.execute("""
            INSERT INTO threat_events (hash, device_id, timestamp)
            VALUES ($1, $2, NOW())
            ON CONFLICT (hash, device_id) DO UPDATE SET timestamp = NOW()
        """, report.threat_hash, report.device_id)

        # Trigger police report check if threshold crossed
        if new_count == POLICE_THRESHOLD:
            bg.add_task(generate_police_report_for_threat, report.threat_hash)

        bg.add_task(post_threat_to_blockchain,report.threat_hash,report.threat_type,report.severity)
    return {"status": "ok", "hash": report.threat_hash, "report_count": new_count}


@app.post("/v1/threats/batch-check", tags=["Threat Intelligence"])
async def batch_check_threats(req: BatchCheckRequest):
    """
    Check multiple threat hashes in one request.
    Used by the VPN service to verify DNS queries, and by SMS filter for URLs.
    Only returns threats confirmed by at least COMMUNITY_MINIMUM devices.
    """
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT hash, severity, report_count, type
            FROM threats
            WHERE hash = ANY($1) AND report_count >= $2
        """, req.hashes, COMMUNITY_MINIMUM)

        results = {h: {"is_threat": False} for h in req.hashes}
        for row in rows:
            results[row["hash"]] = {
                "is_threat":    True,
                "severity":     row["severity"],
                "report_count": row["report_count"],
                "type":         row["type"]
            }
        return results


@app.get("/v1/threats/recent", tags=["Threat Intelligence"])
async def get_recent_threats(
    limit:        int = 500,
    threat_type:  Optional[str] = None,
    min_severity: int = 1
):
    """
    Get recent confirmed threats for device blocklist sync.
    Devices call this on startup and every 6 hours.
    """
    async with db_pool.acquire() as conn:
        if threat_type:
            rows = await conn.fetch("""
                SELECT hash, type, severity, report_count, first_seen
                FROM threats
                WHERE type = $1 AND report_count >= $2 AND severity >= $3
                ORDER BY last_seen DESC LIMIT $4
            """, threat_type, COMMUNITY_MINIMUM, min_severity, limit)
        else:
            rows = await conn.fetch("""
                SELECT hash, type, severity, report_count, first_seen
                FROM threats
                WHERE report_count >= $1 AND severity >= $2
                ORDER BY last_seen DESC LIMIT $3
            """, COMMUNITY_MINIMUM, min_severity, limit)

        return [dict(row) for row in rows]


# ── Dashboard Stats ───────────────────────────────────────────────────────────

@app.get("/v1/dashboard/stats", tags=["Dashboard"])
async def get_stats():
    """Real-time threat statistics for the in-app dashboard."""
    async with db_pool.acquire() as conn:
        stats = await conn.fetchrow("""
            SELECT
                COUNT(*)                                              AS total_threats,
                COUNT(*) FILTER (WHERE first_seen > NOW() - '24h'::interval)  AS threats_24h,
                COUNT(*) FILTER (WHERE first_seen > NOW() - '7d'::interval)   AS threats_7d,
                COUNT(*) FILTER (WHERE severity = 5)                AS critical,
                COUNT(*) FILTER (WHERE severity = 4)                AS high,
                COALESCE(SUM(report_count), 0)                      AS total_reports,
                COUNT(*) FILTER (WHERE police_reported)             AS police_reported_count,
                COUNT(DISTINCT region)                              AS regions_affected
            FROM threats
        """)

        type_breakdown = await conn.fetch("""
            SELECT type, COUNT(*) AS count
            FROM threats WHERE report_count >= $1
            GROUP BY type ORDER BY count DESC
        """, COMMUNITY_MINIMUM)

        return {
            **dict(stats),
            "by_type": {r["type"]: r["count"] for r in type_breakdown}
        }


@app.get("/v1/dashboard/trend", tags=["Dashboard"])
async def get_trend(days: int = 7):
    """Hourly threat trend for the last N days — powers the chart in-app."""
    async with db_pool.acquire() as conn:
        rows = await conn.fetch("""
            SELECT
                date_trunc('hour', first_seen) AS hour,
                COUNT(*)                        AS count,
                AVG(severity)::NUMERIC(4,2)    AS avg_severity
            FROM threats
            WHERE first_seen > NOW() - ($1 || ' days')::interval
            GROUP BY 1 ORDER BY 1
        """, str(days))
        return [dict(r) for r in rows]


# ── AI Security Assistant ─────────────────────────────────────────────────────

@app.post("/v1/assistant/ask", tags=["AI Assistant"])
async def ask_assistant(query: AIAssistantQuery):
    """
    Proxy user security questions to Gemini with threat context injected.
    The device can optionally pass recent threat events for context-aware answers.
    Language-aware: responds in the user's detected language.
    """
    if not GEMINI_API_KEY:
        raise HTTPException(503, "AI assistant not configured")

    genai.configure(api_key=GEMINI_API_KEY)

    # Build system prompt with security expertise + language instruction
    system_prompt = f"""You are Aegis, an expert mobile security assistant built into the
Aegis Android Security app. You help users understand and respond to security threats on
their Android devices.

Your expertise covers: ransomware, SMS phishing (smishing), malicious apps, Android
permissions abuse, VPN security, clickjacking attacks, and general mobile cybersecurity.

ALWAYS respond in language: {query.language}. If the language is not English, translate
your entire response including technical terms (but keep technical terms in their original
English form with translation in parentheses).

Keep responses concise (under 200 words unless asked for more). Use clear, non-technical
language for regular users. Be specific — don't give generic advice.

{f"Recent threat context from user's device: {json.dumps(query.threat_context)}" if query.threat_context else ""}
"""

    model = genai.GenerativeModel('gemini-2.5-flash', system_instruction=system_prompt)
    response = model.generate_content(query.question)

    return {
        "answer":   response.text,
        "language": query.language,
        "tokens":   0
    }


# ── Police Report Generation ──────────────────────────────────────────────────

async def generate_police_report_for_threat(trigger_hash: str):
    """
    Called automatically when a threat crosses the POLICE_THRESHOLD.
    Generates a professional PDF report formatted for CERT-In / cyber police.
    """
    async with db_pool.acquire() as conn:
        # Gather all high-severity unreported threats
        threats = await conn.fetch("""
            SELECT hash, type, severity, report_count, first_seen,
                   last_seen, region, metadata
            FROM threats
            WHERE report_count >= $1
              AND severity >= 3
              AND NOT police_reported
            ORDER BY report_count DESC
            LIMIT 100
        """, POLICE_THRESHOLD)

        if not threats:
            return

        # Get overall stats
        stats = await conn.fetchrow("""
            SELECT SUM(report_count) AS total_devices_affected,
                   COUNT(DISTINCT region) AS regions
            FROM threats WHERE hash = ANY($1)
        """, [t["hash"] for t in threats])

    timestamp   = datetime.utcnow()
    report_name = f"AEGIS_CERT_REPORT_{timestamp.strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = os.path.join(REPORTS_DIR, report_name)

    # ── Build PDF ────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        report_path,
        pagesize=A4,
        rightMargin=40, leftMargin=40,
        topMargin=60,   bottomMargin=40
    )
    styles  = getSampleStyleSheet()
    content = []

    # Title
    title_style = styles["Title"]
    content.append(Paragraph("AEGIS CYBERSECURITY THREAT INTELLIGENCE REPORT", title_style))
    content.append(Paragraph("FOR OFFICIAL USE — CERT-In / Cyber Crime Division", styles["Italic"]))
    content.append(Spacer(1, 12))

    # Executive Summary
    content.append(Paragraph("Executive Summary", styles["Heading1"]))
    content.append(Paragraph(f"""
        The Aegis Collective Threat Intelligence Network has identified <b>{len(threats)}</b>
        high-severity threats affecting users across <b>{stats['regions']}</b> regions.
        These threats have been independently confirmed by a combined
        <b>{stats['total_devices_affected']:,}</b> device reports.
        Immediate action is recommended to block these indicators at the ISP/DNS level.
    """, styles["Normal"]))
    content.append(Spacer(1, 12))

    # Metadata
    content.append(Paragraph("Report Metadata", styles["Heading2"]))
    meta_data = [
        ["Generated", timestamp.strftime("%Y-%m-%d %H:%M UTC")],
        ["Report ID", f"AEGIS-{timestamp.strftime('%Y%m%d-%H%M%S')}"],
        ["Threats Covered", str(len(threats))],
        ["Devices Affected", f"{stats['total_devices_affected']:,}"],
        ["Regions Affected", str(stats["regions"])],
        ["Source", "Aegis Collective Threat Intelligence (Privacy-Preserving)"],
    ]
    meta_table = Table(meta_data, colWidths=[150, 350])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEEDFE")),
        ("TEXTCOLOR",  (0, 0), (0, -1), colors.HexColor("#534AB7")),
        ("FONTNAME",   (0, 0), (0, -1), "Helvetica-Bold"),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.grey),
        ("PADDING",    (0, 0), (-1, -1), 6),
    ]))
    content.append(meta_table)
    content.append(Spacer(1, 20))

    # Threat Table
    content.append(Paragraph("Confirmed Threat Indicators", styles["Heading1"]))
    content.append(Paragraph(
        "Note: Only SHA-256 hashes of threat indicators are stored. "
        "Raw URLs/phone numbers are NOT stored to protect user privacy.",
        styles["Italic"]
    ))
    content.append(Spacer(1, 8))

    severity_labels = {5: "EMERGENCY", 4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}
    threat_rows = [["#", "Type", "Severity", "Reports", "First Seen", "Hash (truncated)"]]

    for i, t in enumerate(threats, 1):
        threat_rows.append([
            str(i),
            t["type"],
            severity_labels.get(t["severity"], str(t["severity"])),
            str(t["report_count"]),
            t["first_seen"].strftime("%Y-%m-%d"),
            t["hash"][:20] + "..."
        ])

    threat_table = Table(threat_rows, colWidths=[25, 70, 80, 60, 90, 175])
    threat_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8F8F8")]),
        ("GRID",       (0, 0), (-1, -1), 0.25, colors.HexColor("#CCCCCC")),
        ("PADDING",    (0, 0), (-1, -1), 5),
    ]))
    content.append(threat_table)
    content.append(Spacer(1, 20))

    # Footer
    content.append(Paragraph(
        "This report was generated automatically by the Aegis Threat Intelligence Platform. "
        "Threat data is collected through privacy-preserving hash-based reporting from "
        "community devices. No personally identifiable information is collected or stored.",
        styles["Italic"]
    ))

    doc.build(content)

    # Mark threats as police-reported in DB
    async with db_pool.acquire() as conn:
        await conn.execute("""
            UPDATE threats SET police_reported = TRUE
            WHERE hash = ANY($1)
        """, [t["hash"] for t in threats])

        await conn.execute("""
            INSERT INTO police_reports (report_path, threat_count, generated_at)
            VALUES ($1, $2, NOW())
        """, report_path, len(threats))

    print(f"[Aegis] Police report generated: {report_path} ({len(threats)} threats)")
    return report_path


@app.get("/v1/reports/list", tags=["Reports"])
async def list_reports():
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id, report_path, threat_count, generated_at, status FROM police_reports ORDER BY generated_at DESC LIMIT 20"
        )
        return [dict(r) for r in rows]


@app.post("/v1/reports/generate-now", tags=["Reports"])
async def generate_report_now(bg: BackgroundTasks):
    """Manually trigger a police report generation."""
    bg.add_task(generate_police_report_for_threat, "manual")
    return {"status": "Report generation queued"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
