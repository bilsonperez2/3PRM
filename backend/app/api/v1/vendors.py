import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.core.logging import get_logger
from app.core.security import CurrentUser, Role, get_current_user, require_role
from app.db.session import get_db
from app.models.enums import ScanMode, ScanStatus
from app.models.finding import Finding
from app.models.governance import GovernanceProfile
from app.models.risk_score import RiskScore
from app.models.scan import Scan
from app.models.vendor import Vendor
from app.providers.news_provider import NewsProvider
from app.schemas.executive_summary import ExecutiveSummary
from app.schemas.governance import GovernanceProfileRead, GovernanceProfileUpdate
from app.schemas.news import NewsMention
from app.schemas.scan import ScanCreateRequest, ScanRead
from app.schemas.vendor import VendorCreate, VendorListItem, VendorRead, VendorUpdate
from app.services.executive_summary import build_executive_summary
from app.services.scan_orchestrator import ScanAuthorizationError, ScanRateLimitError, start_scan

router = APIRouter(prefix="/vendors", tags=["vendors"])
logger = get_logger(__name__)


def start_initial_scan(db: Session, vendor: Vendor) -> None:
    """A brand-new vendor (or Organization entry) should get a baseline
    passive scan immediately rather than sitting with empty Assets/Findings/
    Score History until someone remembers to click "Run passive scan."

    Always passive — this never requests authorized_active, so
    ScanAuthorizationError can't legitimately fire here regardless of the
    vendor's active_scan_authorized flag. Best-effort: any failure (including
    a Celery/Redis broker hiccup) is logged, never raised, since the vendor
    record itself already exists and a scan can always be triggered manually
    afterward — creation succeeding must not depend on scanning succeeding.
    """
    try:
        start_scan(db, vendor, ScanCreateRequest(scan_type="initial_passive", mode=ScanMode.PASSIVE))
    except Exception:
        logger.exception("initial passive scan could not be started for new vendor %s", vendor.id)


@router.post("", response_model=VendorRead, status_code=status.HTTP_201_CREATED)
def create_vendor(
    payload: VendorCreate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Vendor:
    vendor = Vendor(**payload.model_dump())
    db.add(vendor)
    db.commit()
    db.refresh(vendor)
    start_initial_scan(db, vendor)
    return vendor


@router.get("", response_model=list[VendorListItem])
def list_vendors(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[VendorListItem]:
    # Rows representing 4Wall's own brand (is_internal_brand=True) are managed
    # through /organization instead — they're not third-party vendors and
    # must never show up here or in vendor-oriented dashboard counts.
    vendors = list(
        db.scalars(
            select(Vendor).where(Vendor.is_internal_brand.is_(False)).order_by(Vendor.name)
        )
    )

    # One grouped query for every vendor's latest completed scan, rather than
    # a per-row lookup. Only COMPLETED scans count — a queued or failed scan
    # doesn't mean the vendor was actually assessed.
    last_scan_by_vendor = dict(
        db.execute(
            select(Scan.vendor_id, func.max(Scan.completed_at))
            .where(Scan.status == ScanStatus.COMPLETED)
            .group_by(Scan.vendor_id)
        ).all()
    )

    return [
        VendorListItem(
            **VendorRead.model_validate(vendor).model_dump(),
            last_scanned_at=last_scan_by_vendor.get(vendor.id),
        )
        for vendor in vendors
    ]


@router.get("/{vendor_id}", response_model=VendorRead)
def get_vendor(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Vendor:
    return get_vendor_or_404(db, vendor_id)


@router.put("/{vendor_id}", response_model=VendorRead)
def update_vendor(
    vendor_id: uuid.UUID,
    payload: VendorUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Vendor:
    vendor = get_vendor_or_404(db, vendor_id)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(vendor, field, value)
    db.commit()
    db.refresh(vendor)
    return vendor


@router.delete("/{vendor_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vendor(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(require_role(Role.ADMIN)),
) -> None:
    vendor = get_vendor_or_404(db, vendor_id)
    db.delete(vendor)
    db.commit()


@router.post("/{vendor_id}/scan", response_model=ScanRead, status_code=status.HTTP_202_ACCEPTED)
def create_scan(
    vendor_id: uuid.UUID,
    payload: ScanCreateRequest,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Scan:
    vendor = get_vendor_or_404(db, vendor_id)
    try:
        scan = start_scan(db, vendor, payload)
    except ScanAuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except ScanRateLimitError as exc:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=str(exc)) from exc
    return scan


@router.get("/{vendor_id}/executive-summary", response_model=ExecutiveSummary)
def get_executive_summary(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ExecutiveSummary:
    vendor = get_vendor_or_404(db, vendor_id)
    latest_score = db.scalar(
        select(RiskScore)
        .where(RiskScore.vendor_id == vendor_id)
        .order_by(RiskScore.calculated_at.desc())
        .limit(1)
    )
    findings = list(db.scalars(select(Finding).where(Finding.vendor_id == vendor_id)))
    return build_executive_summary(vendor, latest_score, findings)


@router.get("/{vendor_id}/news", response_model=list[NewsMention])
async def get_vendor_news(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[NewsMention]:
    vendor = get_vendor_or_404(db, vendor_id)
    items = await NewsProvider().find_mentions(vendor.name)
    return [
        NewsMention(
            title=item.title,
            link=item.link,
            source=item.source,
            published_at=item.published_at,
            description=item.description,
        )
        for item in items
    ]


@router.get("/{vendor_id}/governance", response_model=GovernanceProfileRead)
def get_governance(
    vendor_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> GovernanceProfile:
    vendor = get_vendor_or_404(db, vendor_id)
    if vendor.governance_profile is None:
        profile = GovernanceProfile(vendor_id=vendor.id)
        db.add(profile)
        db.commit()
        db.refresh(profile)
        return profile
    return vendor.governance_profile


@router.put("/{vendor_id}/governance", response_model=GovernanceProfileRead)
def update_governance(
    vendor_id: uuid.UUID,
    payload: GovernanceProfileUpdate,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> GovernanceProfile:
    vendor = get_vendor_or_404(db, vendor_id)
    profile = vendor.governance_profile
    if profile is None:
        profile = GovernanceProfile(vendor_id=vendor.id)
        db.add(profile)
    for field, value in payload.model_dump().items():
        setattr(profile, field, value)
    db.commit()
    db.refresh(profile)
    return profile
