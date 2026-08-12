"""Vendor availability monitoring.

Probes each vendor's primary domain on a schedule and derives uptime
percentages and outage history from the stored checks.

A note on what this is and isn't: this measures whether the vendor's site
answered *us*, from one network location, at one moment. It is not a
substitute for the vendor's own status page, and a blip here can be our
egress, a CDN edge, or transient rate limiting rather than a real outage.
Treat sustained multi-check failures as signal and isolated single failures
as noise — which is why the incident view groups consecutive failures rather
than listing every failed check.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.uptime import UptimeCheck
from app.models.vendor import Vendor

logger = get_logger(__name__)

_PROBE_TIMEOUT_SECONDS = 15
_PROBE_CONCURRENCY = 10
_USER_AGENT = "Mozilla/5.0 (compatible; TPRM-Platform/1.0; +internal availability monitoring)"

# An isolated failed check is usually noise (transient DNS, a CDN edge, our
# own egress). Only a run of at least this many consecutive failures is
# surfaced as an incident.
MIN_CONSECUTIVE_FAILURES_FOR_INCIDENT = 2


@dataclass
class ProbeResult:
    vendor_id: uuid.UUID
    reachable: bool
    status_code: int | None = None
    response_time_ms: int | None = None
    error: str | None = None


async def probe_vendor(vendor_id: uuid.UUID, domain: str) -> ProbeResult:
    """Single availability probe. HEAD first because it's the lightest
    request that still proves the server is answering; some servers reject
    HEAD, so a 405 falls back to GET rather than being recorded as an outage.
    """
    url = f"https://{domain}"
    started = time.monotonic()
    try:
        async with httpx.AsyncClient(
            timeout=_PROBE_TIMEOUT_SECONDS,
            follow_redirects=True,
            headers={"User-Agent": _USER_AGENT},
        ) as client:
            response = await client.head(url)
            if response.status_code == 405:
                response = await client.get(url)

        elapsed_ms = int((time.monotonic() - started) * 1000)
        # 5xx means the server is up but broken — that's an availability
        # problem from a user's perspective, so it counts as unreachable.
        # 4xx (403 from a WAF, 404 on the bare root) still proves the host is
        # serving, so it counts as reachable.
        reachable = response.status_code < 500
        return ProbeResult(
            vendor_id=vendor_id,
            reachable=reachable,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            error=None if reachable else f"HTTP {response.status_code}",
        )
    except httpx.HTTPError as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        return ProbeResult(
            vendor_id=vendor_id,
            reachable=False,
            response_time_ms=elapsed_ms,
            error=type(exc).__name__,
        )


async def probe_all(vendors: list[tuple[uuid.UUID, str]]) -> list[ProbeResult]:
    semaphore = asyncio.Semaphore(_PROBE_CONCURRENCY)

    async def _one(vendor_id, domain):
        async with semaphore:
            return await probe_vendor(vendor_id, domain)

    return list(await asyncio.gather(*(_one(v, d) for v, d in vendors)))


def record_results(db: Session, results: list[ProbeResult]) -> None:
    now = datetime.now(timezone.utc)
    for result in results:
        db.add(
            UptimeCheck(
                vendor_id=result.vendor_id,
                checked_at=now,
                reachable=result.reachable,
                status_code=result.status_code,
                response_time_ms=result.response_time_ms,
                error=result.error,
            )
        )
    db.commit()


def prune_old_checks(db: Session, retention_days: int) -> int:
    """Uptime checks are the fastest-growing table in the schema; without
    pruning they'd grow unbounded. Returns the number of rows removed."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    deleted = (
        db.query(UptimeCheck).filter(UptimeCheck.checked_at < cutoff).delete(synchronize_session=False)
    )
    db.commit()
    return deleted


def vendor_uptime_summary(db: Session, vendor_id: uuid.UUID, days: int) -> dict:
    """Uptime percentage, latest state, and average response time over the
    window — computed as a single aggregate rather than pulling every row."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    total, up_count, avg_ms = db.execute(
        select(
            func.count(),
            func.count().filter(UptimeCheck.reachable.is_(True)),
            func.avg(UptimeCheck.response_time_ms).filter(UptimeCheck.reachable.is_(True)),
        ).where(UptimeCheck.vendor_id == vendor_id, UptimeCheck.checked_at >= since)
    ).one()

    latest = db.scalar(
        select(UptimeCheck)
        .where(UptimeCheck.vendor_id == vendor_id)
        .order_by(UptimeCheck.checked_at.desc())
        .limit(1)
    )

    return {
        "checks": total or 0,
        # None rather than 0% when nothing has been recorded yet — "no data"
        # and "completely down" must not look identical.
        "uptime_percent": round(100.0 * up_count / total, 2) if total else None,
        "avg_response_time_ms": int(avg_ms) if avg_ms is not None else None,
        "currently_reachable": latest.reachable if latest else None,
        "last_checked_at": latest.checked_at if latest else None,
    }


def vendor_daily_uptime(db: Session, vendor_id: uuid.UUID, days: int) -> list[dict]:
    """Per-day uptime percentage, for the availability bar strip."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.execute(
        select(
            func.date(UptimeCheck.checked_at).label("day"),
            func.count(),
            func.count().filter(UptimeCheck.reachable.is_(True)),
        )
        .where(UptimeCheck.vendor_id == vendor_id, UptimeCheck.checked_at >= since)
        .group_by(func.date(UptimeCheck.checked_at))
        .order_by(func.date(UptimeCheck.checked_at))
    ).all()

    return [
        {
            "day": day.isoformat() if isinstance(day, date) else str(day),
            "checks": total,
            "uptime_percent": round(100.0 * up / total, 2) if total else None,
        }
        for day, total, up in rows
    ]


def vendor_incidents(db: Session, vendor_id: uuid.UUID, days: int) -> list[dict]:
    """Groups consecutive failed checks into incidents.

    Only failed rows are fetched — outages should be rare, so this stays small
    even though the underlying table is large. Runs shorter than
    MIN_CONSECUTIVE_FAILURES_FOR_INCIDENT are dropped as noise.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    failures = list(
        db.scalars(
            select(UptimeCheck)
            .where(
                UptimeCheck.vendor_id == vendor_id,
                UptimeCheck.checked_at >= since,
                UptimeCheck.reachable.is_(False),
            )
            .order_by(UptimeCheck.checked_at)
        )
    )
    if not failures:
        return []

    # Consecutive means "no successful check in between", which is equivalent
    # to failures separated by less than the polling interval plus slack. The
    # interval isn't known here, so gaps are grouped by a generous threshold.
    max_gap = timedelta(minutes=30)

    incidents: list[dict] = []
    run = [failures[0]]
    for check in failures[1:]:
        if check.checked_at - run[-1].checked_at <= max_gap:
            run.append(check)
        else:
            incidents.append(_incident_from_run(run))
            run = [check]
    incidents.append(_incident_from_run(run))

    return [
        i for i in incidents if i["failed_checks"] >= MIN_CONSECUTIVE_FAILURES_FOR_INCIDENT
    ][::-1]


def _incident_from_run(run: list[UptimeCheck]) -> dict:
    return {
        "started_at": run[0].checked_at,
        "ended_at": run[-1].checked_at,
        "duration_minutes": max(
            1, int((run[-1].checked_at - run[0].checked_at).total_seconds() // 60)
        ),
        "failed_checks": len(run),
        "error": run[0].error,
    }


def all_vendor_domains(db: Session) -> list[tuple[uuid.UUID, str]]:
    """Every vendor including Organization entries — knowing our own site is
    down matters at least as much as knowing a vendor's is."""
    return [(v.id, v.primary_domain) for v in db.scalars(select(Vendor))]
