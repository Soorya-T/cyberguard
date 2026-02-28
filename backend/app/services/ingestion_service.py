"""
Ingestion Service Module
========================

Provides helper utilities for creating security events with SLA deadlines.
"""

from datetime import datetime
from app.core.sla import calculate_sla_due
from app.core.enums import IncidentStatus
from app.models.security_event import SecurityEvent


def create_security_event(tenant_id: str, risk_score: int, severity: str) -> SecurityEvent:
    """
    Create a new SecurityEvent with SLA deadline calculated from severity.

    Args:
        tenant_id: The tenant/organization UUID.
        risk_score: Numeric risk score for the event.
        severity: Severity level (e.g. LOW, MEDIUM, HIGH, CRITICAL).

    Returns:
        A SecurityEvent instance (not yet persisted).
    """
    event = SecurityEvent(
        tenant_id=tenant_id,
        risk_score=risk_score,
        severity=severity,
        status=IncidentStatus.OPEN,
        sla_due_at=calculate_sla_due(severity),
    )
    return event
