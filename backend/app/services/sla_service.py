"""
SLA Service Module
==================

Provides SLA breach detection for security events.
"""

from datetime import datetime, UTC


def check_sla_breach(event) -> None:
    """
    Check if a security event has breached its SLA deadline.

    If the event is still open/in-review and the current time exceeds
    sla_due_at, mark it as breached.

    Args:
        event: A SecurityEvent ORM instance with sla_due_at and sla_breached fields.
    """
    if event.sla_breached:
        return

    # Support both enum (event.status.value) and plain string status
    status = event.status.value if hasattr(event.status, "value") else event.status

    if status in ("OPEN", "REVIEW") and event.sla_due_at:
        if datetime.now(UTC) > event.sla_due_at:
            event.sla_breached = True


def calculate_sla_metrics(incident) -> dict:
    """
    Calculate SLA metrics for an incident report.

    Args:
        incident: An Incident ORM instance.

    Returns:
        Dictionary containing SLA-related metrics.
    """
    from datetime import timedelta

    metrics = {
        "sla_met": True,
        "sla_remaining_hours": None,
        "priority": getattr(incident, "risk_score", None),
    }

    # Calculate time since creation
    if incident.created_at:
        elapsed = datetime.now(UTC) - incident.created_at
        elapsed_hours = elapsed.total_seconds() / 3600

        # Define SLA thresholds based on risk score/priority
        sla_thresholds = {
            "critical": 4,    # 4 hours for critical
            "high": 24,       # 24 hours for high
            "medium": 72,     # 72 hours for medium
            "low": 168,       # 168 hours (1 week) for low
        }

        # Determine priority based on risk score
        risk_score = getattr(incident, "risk_score", None)
        if risk_score is not None:
            if risk_score >= 80:
                threshold = sla_thresholds["critical"]
            elif risk_score >= 60:
                threshold = sla_thresholds["high"]
            elif risk_score >= 40:
                threshold = sla_thresholds["medium"]
            else:
                threshold = sla_thresholds["low"]
        else:
            threshold = sla_thresholds["medium"]  # Default threshold

        remaining = threshold - elapsed_hours
        metrics["sla_remaining_hours"] = max(0, remaining)
        metrics["sla_threshold_hours"] = threshold
        metrics["elapsed_hours"] = elapsed_hours

        # Check if SLA is breached
        if remaining < 0:
            metrics["sla_met"] = False

    return metrics
