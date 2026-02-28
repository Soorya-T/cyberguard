from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import timedelta

from app.models.incident import Incident


# ==========================================
# SUMMARY METRICS
# ==========================================

def generate_summary_metrics(db: Session, tenant_id: int):

    total_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.tenant_id == tenant_id)
        .scalar()
    )

    open_incidents = (
        db.query(func.count(Incident.id))
        .filter(
            Incident.tenant_id == tenant_id,
            Incident.status != "CLOSED"
        )
        .scalar()
    )

    closed_incidents = (
        db.query(func.count(Incident.id))
        .filter(
            Incident.tenant_id == tenant_id,
            Incident.status == "CLOSED"
        )
        .scalar()
    )

    return {
        "total_incidents": total_incidents or 0,
        "open_incidents": open_incidents or 0,
        "closed_incidents": closed_incidents or 0,
    }


# ==========================================
# SLA + LIFECYCLE METRICS
# ==========================================

def generate_sla_metrics(db: Session, tenant_id: int):

    incidents = (
        db.query(Incident)
        .filter(Incident.tenant_id == tenant_id)
        .all()
    )

    total = len(incidents)

    if total == 0:
        return {
            "average_detection_latency_seconds": 0,
            "average_response_time_seconds": 0,
            "average_resolution_time_seconds": 0,
            "sla_compliance_rate_percent": 100.0,
        }

    detection_latencies = []
    response_times = []
    resolution_times = []
    sla_met = 0

    for incident in incidents:

        # Detection Latency: processed_at - created_at
        if incident.processed_at and incident.created_at:
            latency = (
                incident.processed_at - incident.created_at
            ).total_seconds()
            detection_latencies.append(max(latency, 0))

        # Response Time: first_response_at - processed_at (or created_at if no processed_at)
        if incident.first_response_at:
            start_time = incident.processed_at if incident.processed_at else incident.created_at
            response = (
                incident.first_response_at - start_time
            ).total_seconds()
            response_times.append(max(response, 0))

        # Resolution Time: closed_at - created_at (closure duration)
        if incident.closed_at and incident.created_at:
            resolution = (
                incident.closed_at - incident.created_at
            ).total_seconds()
            resolution_times.append(max(resolution, 0))

        # SLA Compliance (resolved within 24 hours)
        if incident.closed_at and incident.created_at:
            if (incident.closed_at - incident.created_at) <= timedelta(hours=24):
                sla_met += 1

    def avg(values):
        return sum(values) / len(values) if values else 0

    return {
        "average_detection_latency_seconds": avg(detection_latencies),
        "average_response_time_seconds": avg(response_times),
        "average_resolution_time_seconds": avg(resolution_times),
        "sla_compliance_rate_percent": (sla_met / total) * 100 if total else 100.0,
    }