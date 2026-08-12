import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_, select

from app.core.config import get_settings
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.models.enums import ScanMode, ScanStatus
from app.models.scan import Scan
from app.models.vendor import Vendor
from app.schemas.scan import ScanCreateRequest
from app.services.risk_engine.config import NoActiveScoringConfigError
from app.services.risk_engine.scorer import score_vendor
from app.services.scan_ingest import gather_intelligence, upsert_assets, upsert_findings
from app.services.scan_orchestrator import ScanRateLimitError, start_scan
from app.services.uptime import all_vendor_domains, probe_all, prune_old_checks, record_results
from app.workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="scans.run_scan")
def run_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            logger.warning("run_scan: scan %s not found", scan_id)
            return

        vendor = db.get(Vendor, scan.vendor_id)
        if vendor is None:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error("run_scan: vendor %s not found for scan %s", scan.vendor_id, scan_id)
            return

        scan.status = ScanStatus.RUNNING
        db.commit()

        # Phase 6 (authorized active-scan providers — Nmap/Naabu/Nuclei) doesn't
        # exist yet, so every scan, passive or authorized_active, currently runs
        # the same passive provider set. That's intentional: it's safe by
        # construction, never accidentally active, regardless of `mode`, until
        # an active provider is actually implemented and gated.
        intel = asyncio.run(
            gather_intelligence(vendor.primary_domain, include_typosquat=vendor.is_internal_brand)
        )

        upsert_assets(db, vendor.id, intel.assets)
        upsert_findings(
            db, vendor.id, intel.findings, web_checked_hostnames=intel.web_checked_hostnames
        )

        # A missing/inactive scoring config shouldn't fail a scan that already
        # produced valid Assets/Findings — log it and complete the scan
        # unscored rather than raising. See alembic/versions/
        # 0002_seed_risk_scoring_config.py for how the default config gets in.
        risk_score = None
        try:
            risk_score = score_vendor(db, vendor.id)
        except NoActiveScoringConfigError:
            logger.warning(
                "scan %s: no active risk_scoring_config — vendor %s left unscored this run",
                scan_id,
                vendor.id,
            )

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.findings_count = len(intel.findings)
        scan.scan_metadata = {
            "rdap": intel.rdap,
            "provider_errors": intel.provider_errors,
            "assets_discovered": len(intel.assets),
            "risk_score": risk_score.score if risk_score else None,
        }
        db.commit()
        logger.info(
            "scan %s completed (mode=%s): %s assets, %s findings, %s provider errors, score=%s",
            scan_id,
            scan.mode.value,
            len(intel.assets),
            len(intel.findings),
            len(intel.provider_errors),
            risk_score.score if risk_score else "n/a",
        )
    except Exception:
        db.rollback()
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan is not None:
            scan.status = ScanStatus.FAILED
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
        logger.exception("scan %s failed", scan_id)
        raise
    finally:
        db.close()


@celery_app.task(name="scans.enqueue_due_scans")
def enqueue_due_scans() -> None:
    """Periodic scheduler tick: enqueue a small batch of vendors whose last
    completed scan has gone stale.

    Deliberately *not* "fire everything once a week." A single weekly burst
    would start every vendor's scan simultaneously, and each scan makes
    upwards of 200 outbound requests to shared third-party sources (crt.sh,
    Shodan, public DNS). Ten vendors at once is a couple of thousand requests
    in a few seconds — enough to get rate-limited or temporarily blocked by
    exactly the free sources this platform depends on.

    Instead this runs frequently and enqueues at most scheduler_batch_size
    vendors per tick, so the weekly workload trickles out over hours. It is
    also self-healing: a vendor that fails or is skipped is simply still due
    on the next tick.
    """
    settings = get_settings()
    db = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(days=settings.scan_interval_days)

        # Latest completed scan per vendor. Only COMPLETED counts — a failed
        # or still-queued scan doesn't mean the vendor was assessed.
        last_completed = (
            select(Scan.vendor_id, func.max(Scan.completed_at).label("last_completed_at"))
            .where(Scan.status == ScanStatus.COMPLETED)
            .group_by(Scan.vendor_id)
            .subquery()
        )

        # Vendors already mid-scan are skipped so a slow scan can't cause the
        # scheduler to pile duplicate work on top of it.
        in_flight = select(Scan.vendor_id).where(
            Scan.status.in_([ScanStatus.QUEUED, ScanStatus.RUNNING])
        )

        due_vendors = list(
            db.scalars(
                select(Vendor)
                .outerjoin(last_completed, Vendor.id == last_completed.c.vendor_id)
                .where(
                    Vendor.id.not_in(in_flight),
                    or_(
                        last_completed.c.last_completed_at.is_(None),
                        last_completed.c.last_completed_at < cutoff,
                    ),
                )
                # Never-scanned first, then longest-stale — so nothing can be
                # starved by a batch cap.
                .order_by(last_completed.c.last_completed_at.asc().nullsfirst())
                .limit(settings.scheduler_batch_size)
            )
        )

        if not due_vendors:
            logger.info("scheduler: no vendors due for a scan")
            return

        for vendor in due_vendors:
            try:
                scan = start_scan(
                    db,
                    vendor,
                    ScanCreateRequest(scan_type="scheduled_passive", mode=ScanMode.PASSIVE),
                )
                logger.info(
                    "scheduler: queued scan %s for %s (%s)", scan.id, vendor.name, vendor.primary_domain
                )
            except ScanRateLimitError:
                # Someone scanned this vendor manually moments ago; it'll be
                # picked up on a later tick if it's still stale.
                logger.info("scheduler: %s scanned too recently, skipping", vendor.name)
            except Exception:
                logger.exception("scheduler: could not queue scan for %s", vendor.name)
    finally:
        db.close()


@celery_app.task(name="uptime.run_checks")
def run_uptime_checks() -> None:
    """Probe every vendor's primary domain and record the result.

    Unlike scans, this runs against all vendors at once — each probe is a
    single HEAD request, so even a few dozen vendors is a trivial burst, and
    staggering them would smear the timestamps and make the uptime maths
    less comparable across vendors.
    """
    settings = get_settings()
    db = SessionLocal()
    try:
        targets = all_vendor_domains(db)
        if not targets:
            return

        results = asyncio.run(probe_all(targets))
        record_results(db, results)

        down = [r for r in results if not r.reachable]
        logger.info(
            "uptime: probed %s vendor(s), %s unreachable%s",
            len(results),
            len(down),
            f" ({', '.join(str(r.vendor_id) for r in down)})" if down else "",
        )

        # Pruning is cheap and idempotent, so it rides along with the probe
        # rather than needing its own schedule entry.
        removed = prune_old_checks(db, settings.uptime_retention_days)
        if removed:
            logger.info("uptime: pruned %s check(s) past retention", removed)
    finally:
        db.close()
