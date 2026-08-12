import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.vendor import Vendor


def get_vendor_or_404(db: Session, vendor_id: uuid.UUID) -> Vendor:
    vendor = db.get(Vendor, vendor_id)
    if vendor is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vendor not found")
    return vendor
