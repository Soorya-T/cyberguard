"""
CyberGuard Email Threat Intelligence API.
"""

import logging
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import delete

from app.schemas.email_schema import EmailAnalysisResponse, EmailInput
from app.services.email_analysis_service import get_email_analysis_service

# Database imports
from app.core.database import engine, SessionLocal, Base
from app.models.analysis_model import AnalysisRecord


# ===============================
# Logging
# ===============================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ===============================
# Create DB tables
# ===============================

Base.metadata.create_all(bind=engine)


# ===============================
# FastAPI App
# ===============================

app = FastAPI(
    title="CyberGuard Email Threat Intelligence API",
    version="3.0",
    description="Production-ready email phishing detection and threat analysis API with persistence layer",
    docs_url="/docs",
    redoc_url="/redoc",
)


# ===============================
# ✅ CORS CONFIG (IMPORTANT)
# ===============================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===============================
# Global Exception Handler
# ===============================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "An internal error occurred.",
            "status": "error",
        },
    )


# ===============================
# Health
# ===============================

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "cyberguard-api"}


# ===============================
# Analyze Email
# ===============================

@app.post(
    "/analyze",
    response_model=EmailAnalysisResponse,
    summary="Analyze email for threats",
)
def analyze(data: EmailInput) -> EmailAnalysisResponse:
    logger.info(f"Received analysis request for sender: {data.sender}")

    service = get_email_analysis_service()
    response = service.analyze(data)

    verdict = "Unknown"
    severity = "UNKNOWN"

    if response.report and isinstance(response.report, dict):
        verdict = response.report.get("verdict", verdict)
        severity = response.report.get("severity", severity)

    db = None
    try:
        db = SessionLocal()

        record = AnalysisRecord(
            sender=data.sender,
            subject=data.subject,
            risk_score=response.risk_score,
            verdict=verdict,
            pdf_location=response.pdf_location,
        )

        # Save severity only if model supports it
        if hasattr(record, "severity"):
            setattr(record, "severity", severity)

        db.add(record)
        db.commit()
        db.refresh(record)

        logger.info(f"Saved report id={record.id}")

    except Exception as e:
        logger.error(f"Database save failed: {e}", exc_info=True)

    finally:
        if db:
            db.close()

    return response


# ===============================
# Report History
# ===============================

@app.get("/reports/history")
def get_report_history():
    db = SessionLocal()
    try:
        return db.query(AnalysisRecord).order_by(AnalysisRecord.id.desc()).all()
    finally:
        db.close()


# ===============================
# Get Single Report
# ===============================

@app.get("/reports/{report_id}")
def get_single_report(report_id: int):
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == report_id).first()

        if not record:
            raise HTTPException(status_code=404, detail="Report not found")

        return record
    finally:
        db.close()


# ===============================
# Delete All Reports
# ===============================

@app.delete("/reports/clear")
def clear_reports():
    db = SessionLocal()
    try:
        result = db.execute(delete(AnalysisRecord))
        db.commit()
        deleted = result.rowcount or 0
        return {"status": "ok", "deleted": deleted}
    finally:
        db.close()


# ===============================
# Delete Single Report
# ===============================

@app.delete("/reports/{report_id}")
def delete_report(report_id: int):
    db = SessionLocal()
    try:
        record = db.query(AnalysisRecord).filter(AnalysisRecord.id == report_id).first()

        if not record:
            raise HTTPException(status_code=404, detail="Report not found")

        db.delete(record)
        db.commit()

        return {"status": "ok", "deleted_id": report_id}
    finally:
        db.close()