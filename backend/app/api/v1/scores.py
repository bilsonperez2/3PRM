import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.risk_score import RiskScore
from app.schemas.risk_score import RiskScoreRead

router = APIRouter(prefix="/vendors", tags=["scores"])


@router.get("/{vendor_id}/scores", response_model=list[RiskScoreRead])
def list_scores(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[RiskScore]:
    get_vendor_or_404(db, vendor_id)
    return list(
        db.scalars(
            select(RiskScore)
            .where(RiskScore.vendor_id == vendor_id)
            .order_by(RiskScore.calculated_at.desc())
        )
    )
