import asyncio
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import CurrentUser, get_current_user
from app.db.session import get_db
from app.models.enums import Criticality, FindingSeverity, FindingStatus, RiskTier
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.vendor import Vendor
from app.providers.news_provider import NewsProvider, parse_published_at
from app.schemas.dashboard import DashboardSummary, FindingSeverityCounts, RiskTierCounts
from app.schemas.news import VendorNewsMention

router = APIRouter(tags=["dashboard"])

_RECENT_WINDOW = timedelta(days=7)


@router.get("/dashboard", response_model=DashboardSummary)
def get_dashboard(
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DashboardSummary:
    recent_cutoff = datetime.now(timezone.utc) - _RECENT_WINDOW

    # 4Wall's own brand-monitoring entries (Vendor.is_internal_brand=True,
    # managed through /organization) are not third-party vendors and must
    # never be counted in vendor-oriented dashboard aggregates.
    vendor_ids = select(Vendor.id).where(Vendor.is_internal_brand.is_(False))

    vendor_count = (
        db.scalar(
            select(func.count()).select_from(Vendor).where(Vendor.is_internal_brand.is_(False))
        )
        or 0
    )
    critical_vendor_count = (
        db.scalar(
            select(func.count())
            .select_from(Vendor)
            .where(Vendor.is_internal_brand.is_(False), Vendor.criticality == Criticality.CRITICAL)
        )
        or 0
    )
    high_risk_vendor_count = (
        db.scalar(
            select(func.count())
            .select_from(Vendor)
            .where(
                Vendor.is_internal_brand.is_(False),
                Vendor.risk_tier.in_([RiskTier.HIGH, RiskTier.CRITICAL]),
            )
        )
        or 0
    )
    vendors_with_new_findings = (
        db.scalar(
            select(func.count(func.distinct(Finding.vendor_id))).where(
                Finding.detected_at >= recent_cutoff, Finding.vendor_id.in_(vendor_ids)
            )
        )
        or 0
    )
    vendors_with_kev_findings = (
        db.scalar(
            select(func.count(func.distinct(Finding.vendor_id))).where(
                Finding.finding_type.ilike("%kev%"),
                Finding.status != FindingStatus.FALSE_POSITIVE,
                Finding.vendor_id.in_(vendor_ids),
            )
        )
        or 0
    )
    vendors_with_typosquatting_findings = (
        db.scalar(
            select(func.count(func.distinct(Finding.vendor_id))).where(
                Finding.finding_type.ilike("%typosquat%"),
                Finding.status != FindingStatus.FALSE_POSITIVE,
                Finding.vendor_id.in_(vendor_ids),
            )
        )
        or 0
    )
    open_critical_findings = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.severity == FindingSeverity.CRITICAL,
                Finding.status == FindingStatus.OPEN,
                Finding.vendor_id.in_(vendor_ids),
            )
        )
        or 0
    )
    open_high_findings = (
        db.scalar(
            select(func.count())
            .select_from(Finding)
            .where(
                Finding.severity == FindingSeverity.HIGH,
                Finding.status == FindingStatus.OPEN,
                Finding.vendor_id.in_(vendor_ids),
            )
        )
        or 0
    )
    recent_scan_count = (
        db.scalar(
            select(func.count())
            .select_from(Scan)
            .where(Scan.started_at >= recent_cutoff, Scan.vendor_id.in_(vendor_ids))
        )
        or 0
    )

    tier_counts = {tier.value: 0 for tier in RiskTier}
    for tier, count in db.execute(
        select(Vendor.risk_tier, func.count())
        .where(Vendor.is_internal_brand.is_(False))
        .group_by(Vendor.risk_tier)
    ):
        tier_counts[tier.value] = count

    severity_counts = {severity.value: 0 for severity in FindingSeverity}
    for severity, count in db.execute(
        select(Finding.severity, func.count())
        .where(Finding.status == FindingStatus.OPEN, Finding.vendor_id.in_(vendor_ids))
        .group_by(Finding.severity)
    ):
        severity_counts[severity.value] = count

    return DashboardSummary(
        vendor_count=vendor_count,
        critical_vendor_count=critical_vendor_count,
        high_risk_vendor_count=high_risk_vendor_count,
        vendors_with_new_findings=vendors_with_new_findings,
        vendors_with_kev_findings=vendors_with_kev_findings,
        vendors_with_typosquatting_findings=vendors_with_typosquatting_findings,
        open_critical_findings=open_critical_findings,
        open_high_findings=open_high_findings,
        recent_scan_count=recent_scan_count,
        vendor_risk_tier_counts=RiskTierCounts(**tier_counts),
        open_finding_severity_counts=FindingSeverityCounts(**severity_counts),
    )


@router.get("/dashboard/news", response_model=list[VendorNewsMention])
async def get_dashboard_news(
    days: int = 14,
    db: Session = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[VendorNewsMention]:
    """Recent news across every third-party vendor (not Organization entries —
    same is_internal_brand exclusion as every other dashboard aggregate).
    Search/filtering is handled client-side once this list is fetched, since
    the fetch itself (RSS + Google News per vendor) is the expensive part."""
    vendors = list(db.scalars(select(Vendor).where(Vendor.is_internal_brand.is_(False))))
    since = datetime.now(timezone.utc) - timedelta(days=days)

    provider = NewsProvider()
    results = await asyncio.gather(
        *(provider.find_mentions(vendor.name, limit=15, since=since) for vendor in vendors)
    )

    mentions = [
        VendorNewsMention(
            vendor_id=vendor.id,
            vendor_name=vendor.name,
            title=item.title,
            link=item.link,
            source=item.source,
            published_at=item.published_at,
            description=item.description,
        )
        for vendor, items in zip(vendors, results)
        for item in items
    ]
    # Each vendor's own list was already sorted; merging vendors interleaves
    # them, so the combined list needs its own recency sort.
    mentions.sort(
        key=lambda m: parse_published_at(m.published_at) or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )
    return mentions
