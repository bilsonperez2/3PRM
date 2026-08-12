"""Scan orchestration.

This is the single place that decides whether a scan may run. Both the
authorization gate and the rate limit are enforced here — server-side,
independent of anything the frontend/caller sends — so no future API route can
accidentally bypass them.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.enums import ScanMode, ScanStatus
from app.models.scan import Scan
from app.models.vendor import Vendor
from app.schemas.scan import ScanCreateRequest


class ScanAuthorizationError(Exception):
    """Raised when an authorized_active scan is requested for a vendor that has
    not been explicitly authorized for active scanning."""


class ScanRateLimitError(Exception):
    """Raised when a vendor was scanned too recently."""


def start_scan(db: Session, vendor: Vendor, request: ScanCreateRequest) -> Scan:
    if request.mode == ScanMode.AUTHORIZED_ACTIVE and not vendor.active_scan_authorized:
        raise ScanAuthorizationError(
            f"Vendor {vendor.id} is not authorized for active scanning. "
            "Set active_scan_authorized=true on the vendor record first."
        )

    settings = get_settings()
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=settings.scan_min_interval_minutes)
    recent_scan = db.scalar(
        select(Scan)
        .where(Scan.vendor_id == vendor.id, Scan.started_at.is_not(None), Scan.started_at >= cutoff)
        .order_by(Scan.started_at.desc())
        .limit(1)
    )
    if recent_scan is not None:
        raise ScanRateLimitError(
            f"Vendor {vendor.id} was scanned at {recent_scan.started_at.isoformat()}; "
            f"minimum interval between scans is {settings.scan_min_interval_minutes} minutes."
        )

    scan = Scan(
        vendor_id=vendor.id,
        scan_type=request.scan_type,
        mode=request.mode,
        status=ScanStatus.QUEUED,
        started_at=datetime.now(timezone.utc),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Imported here (not at module scope) to avoid importing Celery/the broker
    # connection for code paths that only construct a Scan without enqueuing,
    # e.g. unit tests exercising the authorization/rate-limit checks directly.
    from app.workers.tasks import run_scan

    run_scan.delay(str(scan.id))
    return scan
