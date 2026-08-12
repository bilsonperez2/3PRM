"""Vendor availability endpoints backing the Status page.

Combines two independent signals per vendor:
  1. Our own reachability probes (uptime_checks) — what we observed.
  2. The vendor's own published status page, where machine-readable — what
     they report about themselves.

They answer different questions and are shown side by side rather than merged:
a healthy root domain with a vendor-reported API outage is exactly the case
worth surfacing, and averaging the two would hide it.
"""

import asyncio
import uuid
from dataclasses import asdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_vendor_or_404
from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.vendor import Vendor
from app.providers.vendor_status_provider import VendorStatusProvider
from app.schemas.uptime import VendorReportedStatus, VendorUptime
from app.services.uptime import vendor_daily_uptime, vendor_incidents, vendor_uptime_summary

router = APIRouter(tags=["uptime"])


async def _fetch_reported_statuses(vendors: list[Vendor]) -> dict[uuid.UUID, VendorReportedStatus | None]:
    """Fetches every vendor's published status concurrently. Best-effort — a
    vendor whose page can't be read just gets None, which the UI renders as
    'not machine-readable' rather than as a problem."""
    provider = VendorStatusProvider()
    targets = [v for v in vendors if v.status_page_url]
    if not targets:
        return {}

    async def _one(vendor: Vendor):
        try:
            return vendor.id, await provider.fetch(vendor.status_page_url)
        except Exception:
            return vendor.id, None

    results = await asyncio.gather(*(_one(v) for v in targets))
    # asdict (not vars) because the provider returns nested dataclasses for
    # components/incidents — asdict converts the whole tree to plain dicts,
    # which is what Pydantic validates from without needing from_attributes.
    return {
        vendor_id: VendorReportedStatus(**asdict(status)) if status is not None else None
        for vendor_id, status in results
    }


def _build(
    db: Session,
    vendor: Vendor,
    days: int,
    reported: VendorReportedStatus | None,
) -> VendorUptime:
    summary = vendor_uptime_summary(db, vendor.id, days)
    return VendorUptime(
        vendor_id=vendor.id,
        vendor_name=vendor.name,
        primary_domain=vendor.primary_domain,
        is_internal_brand=vendor.is_internal_brand,
        status_page_url=vendor.status_page_url,
        daily=vendor_daily_uptime(db, vendor.id, days),
        incidents=vendor_incidents(db, vendor.id, days),
        reported_status=reported,
        **summary,
    )


@router.get("/status", response_model=list[VendorUptime])
async def get_status(
    days: int = Query(30, ge=1, le=90),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[VendorUptime]:
    """Availability across every monitored domain, vendors and Organization
    entries alike — knowing our own site is down matters as much as a
    vendor's."""
    vendors = list(db.scalars(select(Vendor).order_by(Vendor.name)))
    reported = await _fetch_reported_statuses(vendors)
    return [_build(db, vendor, days, reported.get(vendor.id)) for vendor in vendors]


@router.get("/vendors/{vendor_id}/uptime", response_model=VendorUptime)
async def get_vendor_uptime(
    vendor_id: uuid.UUID,
    days: int = Query(30, ge=1, le=90),
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> VendorUptime:
    vendor = get_vendor_or_404(db, vendor_id)
    reported = await _fetch_reported_statuses([vendor])
    return _build(db, vendor, days, reported.get(vendor.id))
