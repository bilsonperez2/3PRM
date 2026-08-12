"""Brand protection / typosquat monitoring for 4Wall's own domain(s) —
deliberately separate from /vendors (see app/models/vendor.py:is_internal_brand
for why). Reuses the Vendor row and all of its scan/asset/finding/score
machinery under the hood; only the create/list surface is simplified and
scoped to is_internal_brand=True.
"""

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.api.v1.vendors import start_initial_scan
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.vendor import Vendor
from app.schemas.vendor import OrganizationDomainCreate, VendorRead

router = APIRouter(prefix="/organization", tags=["organization"])


@router.get("", response_model=list[VendorRead])
def list_organization_domains(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[Vendor]:
    return list(
        db.scalars(
            select(Vendor).where(Vendor.is_internal_brand.is_(True)).order_by(Vendor.name)
        )
    )


@router.post("", response_model=VendorRead, status_code=status.HTTP_201_CREATED)
def create_organization_domain(
    payload: OrganizationDomainCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Vendor:
    vendor = Vendor(
        name=payload.name,
        primary_domain=payload.primary_domain,
        is_internal_brand=True,
    )
    db.add(vendor)
    db.commit()
    db.refresh(vendor)
    start_initial_scan(db, vendor)
    return vendor


@router.get("/{vendor_id}", response_model=VendorRead)
def get_organization_domain(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Vendor:
    return get_vendor_or_404(db, vendor_id)
