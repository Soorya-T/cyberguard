from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, UTC

from app.db.session import get_db
from app.models.incident import Incident
from app.core.enums import IncidentStatus
from app.services.lifecycle_service import validate_transition
from app.core.dependencies.auth import get_current_user
from app.models.user import User

router = APIRouter()


@router.patch("/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: int,
    new_status: IncidentStatus,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Tenant-safe fetch
    incident = db.query(Incident).filter(
        Incident.id == incident_id,
        Incident.tenant_id == current_user.tenant_id,
    ).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Validate lifecycle transition
    validate_transition(incident.status, new_status)

    now = datetime.now(UTC)

    # -----------------------------
    # Lifecycle Timestamp Handling
    # -----------------------------

    # When incident is first detected
    if new_status == IncidentStatus.DETECTED and not incident.detected_at:
        incident.detected_at = now

    # When analyst takes ownership
    if new_status == IncidentStatus.ASSIGNED and not incident.assigned_at:
        incident.assigned_at = now

    # When incident is resolved
    if new_status == IncidentStatus.CLOSED and not incident.resolved_at:
        incident.resolved_at = now

    # Update status
    incident.status = new_status

    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident.id,
        "new_status": incident.status,
    }


@router.get("/incidents")
def get_incidents(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    incidents = db.query(Incident).filter(
        Incident.tenant_id == current_user.tenant_id,
    ).all()

    return incidents