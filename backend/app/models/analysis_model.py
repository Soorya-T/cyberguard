from datetime import datetime, UTC

from sqlalchemy import Column, Integer, String, Float, DateTime

from app.core.database import Base


class AnalysisRecord(Base):
    __tablename__ = "analysis_records"

    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, nullable=False)
    subject = Column(String, nullable=False)
    risk_score = Column(Float, nullable=False)
    verdict = Column(String, nullable=False)
    pdf_location = Column(String, nullable=True)

    # ✅ timezone-aware + no utcnow() warning
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )