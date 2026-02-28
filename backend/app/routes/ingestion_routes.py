from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from datetime import datetime, UTC
from uuid import UUID
import logging

from app.schemas.ocsf.email_event import EmailEvent
from app.models.incident import Incident
from app.db.session import get_db
from app.services.pod_b_client import analyze_with_pod_b

router = APIRouter()
logger = logging.getLogger(__name__)

# Default tenant ID for testing
DEFAULT_TENANT_ID = UUID("00000000-0000-0000-0000-000000000000")


@router.post("/ingest")
async def ingest_event(
    event: EmailEvent,
    db: Session = Depends(get_db)
):
    # Use default tenant for now
    tenant_id = DEFAULT_TENANT_ID
    
    # 1️⃣ Store initial incident with default tenant
    incident = Incident(
        tenant_id=tenant_id,
        src_user=event.src_user,
        dst_user=event.dst_user,
        subject=event.subject,
        ip_address=event.ip_address,
        status="OPEN"
    )

    db.add(incident)
    db.commit()
    db.refresh(incident)

    # 2️⃣ Call Pod B with graceful error handling
    pod_b_success = False
    try:
        result = await analyze_with_pod_b(event.model_dump())
        
        # 3️⃣ Store verdict
        incident.risk_score = result.get("risk_score")
        incident.classification = result.get("classification")
        incident.explanation = result.get("explanation")
        incident.status = "REVIEW"
        incident.processed_at = datetime.now(UTC)
        pod_b_success = True
        
    except Exception as e:
        # Pod B failed - log error but don't crash
        # Incident remains in OPEN status with no risk score
        logger.error(
            "Pod B analysis failed - incident saved with default values",
            extra={
                "incident_id": str(incident.id),
                "error": str(e)
            }
        )
        incident.status = "PENDING_ANALYSIS"

    db.commit()

    return {
        "incident_id": incident.id,
        "status": incident.status,
        "pod_b_analyzed": pod_b_success
    }