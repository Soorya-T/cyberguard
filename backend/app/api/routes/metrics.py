from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.metrics_service import (
    generate_summary_metrics,
    generate_sla_metrics
)
from app.core.dependencies.auth import get_current_user
from app.models.user import User

router = APIRouter(prefix="/metrics", tags=["Metrics"])


@router.get("/summary")
def get_summary_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return generate_summary_metrics(
        db=db,
        tenant_id=current_user.tenant_id
    )


@router.get("/sla")
def get_sla_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return generate_sla_metrics(
        db=db,
        tenant_id=current_user.tenant_id
    )