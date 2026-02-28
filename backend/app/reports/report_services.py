from sqlalchemy.orm import Session
from fastapi import HTTPException
from weasyprint import HTML
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
from datetime import datetime, UTC

from app.models.incident import Incident
from app.models.organization import Organization
from app.services.sla_service import calculate_sla_metrics


TEMPLATE_DIR = Path(__file__).parent / "templates"

env = Environment(
    loader=FileSystemLoader(TEMPLATE_DIR),
    autoescape=select_autoescape(["html", "xml"]),
)


def generate_incident_report(db: Session, incident_id: str) -> bytes:
    incident = db.query(Incident).filter(Incident.id == incident_id).first()

    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    organization = (
        db.query(Organization)
        .filter(Organization.id == incident.tenant_id)
        .first()
    )

    detection_latency = None
    analyst_response_time = None
    closure_duration = None

    if incident.processed_at:
        detection_latency = (
            incident.processed_at - incident.created_at
        ).total_seconds()

    if incident.first_response_at and incident.processed_at:
        analyst_response_time = (
            incident.first_response_at - incident.processed_at
        ).total_seconds()

    if incident.closed_at:
        closure_duration = (
            incident.closed_at - incident.created_at
        ).total_seconds()

    sla_metrics = calculate_sla_metrics(incident)

    template = env.get_template("incident_report.html")

    html_content = template.render(
        organization_name=organization.name if organization else "Unknown",
        incident=incident,
        detection_latency=detection_latency,
        analyst_response_time=analyst_response_time,
        closure_duration=closure_duration,
        sla_metrics=sla_metrics,
        generated_at=datetime.now(UTC),
    )

    pdf = HTML(string=html_content).write_pdf()

    return pdf