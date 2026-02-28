from sqlalchemy import Column, String, Integer, DateTime, Text, Enum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from app.db.base import Base
from app.core.enums import IncidentStatus
import uuid
from datetime import datetime, UTC


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True),
        ForeignKey('organizations.id', ondelete='CASCADE'),
        index=True,
        nullable=False
    )

    src_user = Column(String, nullable=False)
    dst_user = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)

    status = Column(Enum(IncidentStatus), default=IncidentStatus.OPEN)

    risk_score = Column(Integer, nullable=True)
    classification = Column(String, nullable=True)
    explanation = Column(Text, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    processed_at = Column(DateTime, nullable=True)

    # Lifecycle timestamps
    first_response_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
