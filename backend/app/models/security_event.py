from sqlalchemy import Column, DateTime, Boolean, Enum
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, UTC
from app.core.enums import IncidentStatus
from app.db.base import Base


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(UUID(as_uuid=True), primary_key=True)
    tenant_id = Column(UUID(as_uuid=True), index=True)

    # Lifecycle
    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)

    # Metrics foundation
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))

    # SLA fields
    sla_due_at = Column(DateTime, nullable=False)
    first_response_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    sla_breached = Column(Boolean, default=False)
