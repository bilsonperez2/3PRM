import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetRead

router = APIRouter(prefix="/vendors", tags=["assets"])


@router.get("/{vendor_id}/assets", response_model=list[AssetRead])
def list_assets(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Asset]:
    get_vendor_or_404(db, vendor_id)
    return list(
        db.scalars(
            select(Asset).where(Asset.vendor_id == vendor_id).order_by(Asset.first_seen.desc())
        )
    )
