"""
Report Routes
============

Handles PDF report generation for incidents.
Protected endpoint (JWT required).
"""

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from io import BytesIO

from app.db.session import get_db
from app.reports.report_services import generate_incident_report
from app.core.dependencies.auth import get_current_active_user
from app.models.user import User

router = APIRouter()


@router.get(
    "/reports/incidents/{incident_id}",
    summary="Download Incident Report (PDF)",
    description="Generates and downloads a PDF report for a specific incident.",
)
def download_incident_report(
    incident_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
):
    pdf_bytes = generate_incident_report(db, incident_id)

    return StreamingResponse(
        BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=incident_{incident_id}.pdf"
        },
    )