from datetime import datetime, timedelta, UTC

SLA_HOURS = {
    "LOW": 48,
    "MEDIUM": 24,
    "HIGH": 8,
    "CRITICAL": 2,
}

def calculate_sla_due(severity: str):
    hours = SLA_HOURS.get(severity, 24)
    return datetime.now(UTC) + timedelta(hours=hours)