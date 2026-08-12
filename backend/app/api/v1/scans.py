import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.scan import Scan
from app.schemas.scan import ScanRead

router = APIRouter(prefix="/vendors", tags=["scans"])


@router.get("/{vendor_id}/scans", response_model=list[ScanRead])
def list_scans(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Scan]:
    get_vendor_or_404(db, vendor_id)
    return list(
        db.scalars(
            select(Scan).where(Scan.vendor_id == vendor_id).order_by(Scan.started_at.desc())
        )
    )
