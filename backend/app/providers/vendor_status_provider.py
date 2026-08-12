"""Reads a vendor's own published status page, when it runs on a platform
with a machine-readable API.

Two platforms are supported because between them they cover most hosted status
pages, and both expose documented public JSON with no API key:

  - Atlassian Statuspage: {base}/api/v2/summary.json
  - Instatus:             {base}/summary.json

Everything is normalised to one small vocabulary so the UI doesn't need to
know which platform a vendor uses. A vendor on any other platform (Better
Stack, a bespoke trust-page product, a JS-rendered page) simply returns None
and the UI falls back to linking out — we never guess at a status we couldn't
actually read.

This is the vendor's *own* reported health, which is more authoritative than
this platform's reachability probe: it can distinguish a degraded API from a
healthy marketing site, which an HTTP probe of the root domain cannot.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.core.logging import get_logger
from app.providers.http_utils import ProviderFetchError, fetch_json

logger = get_logger(__name__)

# Status pages are updated by humans during incidents, so a short cache is
# plenty and keeps repeated page loads from re-fetching every vendor.
_CACHE_TTL_SECONDS = 120
_cache: dict[str, tuple[float, "VendorReportedStatus | None"]] = {}

# Normalised indicators, worst-last. The UI colours from these rather than
# from any platform's native vocabulary.
INDICATOR_OPERATIONAL = "operational"
INDICATOR_MAINTENANCE = "maintenance"
INDICATOR_DEGRADED = "degraded"
INDICATOR_PARTIAL_OUTAGE = "partial_outage"
INDICATOR_MAJOR_OUTAGE = "major_outage"

# Statuspage's page-level indicator -> ours.
_STATUSPAGE_INDICATORS = {
    "none": INDICATOR_OPERATIONAL,
    "maintenance": INDICATOR_MAINTENANCE,
    "minor": INDICATOR_DEGRADED,
    "major": INDICATOR_PARTIAL_OUTAGE,
    "critical": INDICATOR_MAJOR_OUTAGE,
}

# Statuspage's per-component status -> ours.
_STATUSPAGE_COMPONENTS = {
    "operational": INDICATOR_OPERATIONAL,
    "under_maintenance": INDICATOR_MAINTENANCE,
    "degraded_performance": INDICATOR_DEGRADED,
    "partial_outage": INDICATOR_PARTIAL_OUTAGE,
    "major_outage": INDICATOR_MAJOR_OUTAGE,
}

_INSTATUS_INDICATORS = {
    "UP": INDICATOR_OPERATIONAL,
    "HASISSUES": INDICATOR_DEGRADED,
    "UNDERMAINTENANCE": INDICATOR_MAINTENANCE,
}


@dataclass
class StatusComponent:
    name: str
    indicator: str


@dataclass
class StatusIncident:
    name: str
    impact: str | None
    status: str | None
    started_at: str | None
    url: str | None


@dataclass
class VendorReportedStatus:
    indicator: str
    description: str
    platform: str
    components: list[StatusComponent] = field(default_factory=list)
    active_incidents: list[StatusIncident] = field(default_factory=list)
    fetched_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def _candidate_endpoints(status_page_url: str) -> list[tuple[str, str]]:
    """Returns (platform, url) pairs to try in order.

    A recorded status page URL might be a bare host (status.vendor.com) or
    include a path (trustpage.vendor.com/status/). The API can live at either
    the given path or the host root, so both are tried.
    """
    trimmed = status_page_url.rstrip("/")
    parsed = urlparse(trimmed)
    root = f"{parsed.scheme}://{parsed.netloc}"

    bases: list[str] = [trimmed]
    if root != trimmed:
        bases.append(root)

    candidates: list[tuple[str, str]] = []
    for base in bases:
        candidates.append(("statuspage", f"{base}/api/v2/summary.json"))
    for base in bases:
        candidates.append(("instatus", f"{base}/summary.json"))
    return candidates


def _parse_statuspage(payload: dict) -> VendorReportedStatus | None:
    status = payload.get("status")
    if not isinstance(status, dict) or "indicator" not in status:
        return None

    components = [
        StatusComponent(
            name=component.get("name", "unknown"),
            indicator=_STATUSPAGE_COMPONENTS.get(component.get("status", ""), INDICATOR_OPERATIONAL),
        )
        for component in payload.get("components", []) or []
        # Group containers duplicate their children's names in the list.
        if isinstance(component, dict) and not component.get("group")
    ]

    incidents = [
        StatusIncident(
            name=incident.get("name", "Incident"),
            impact=incident.get("impact"),
            status=incident.get("status"),
            started_at=incident.get("created_at"),
            url=incident.get("shortlink"),
        )
        for incident in payload.get("incidents", []) or []
        if isinstance(incident, dict)
    ]

    return VendorReportedStatus(
        indicator=_STATUSPAGE_INDICATORS.get(status.get("indicator", ""), INDICATOR_OPERATIONAL),
        description=status.get("description") or "Status reported",
        platform="statuspage",
        components=components,
        active_incidents=incidents,
    )


def _parse_instatus(payload: dict) -> VendorReportedStatus | None:
    page = payload.get("page")
    if not isinstance(page, dict) or "status" not in page:
        return None

    raw = str(page.get("status", "")).upper()
    indicator = _INSTATUS_INDICATORS.get(raw)
    if indicator is None:
        return None

    incidents = [
        StatusIncident(
            name=incident.get("name", "Incident"),
            impact=incident.get("impact"),
            status=incident.get("status"),
            started_at=incident.get("started"),
            url=incident.get("url"),
        )
        for incident in payload.get("activeIncidents", []) or []
        if isinstance(incident, dict)
    ]

    return VendorReportedStatus(
        indicator=indicator,
        description={
            INDICATOR_OPERATIONAL: "All Systems Operational",
            INDICATOR_DEGRADED: "Some systems are experiencing issues",
            INDICATOR_MAINTENANCE: "Under maintenance",
        }.get(indicator, "Status reported"),
        platform="instatus",
        active_incidents=incidents,
    )


class VendorStatusProvider:
    """Standalone, like RDAPProvider — it enriches a vendor record rather than
    discovering assets or evaluating a security check."""

    name = "vendor_status"

    async def fetch(self, status_page_url: str) -> VendorReportedStatus | None:
        now = time.time()
        cached = _cache.get(status_page_url)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]

        result: VendorReportedStatus | None = None
        for platform, url in _candidate_endpoints(status_page_url):
            try:
                # retries=0: this is a best-effort enrichment on a page load,
                # and most candidate URLs are expected to 404 (a vendor is on
                # at most one platform). Retrying misses would just slow the
                # page down.
                payload = await fetch_json(url, retries=0)
            except ProviderFetchError:
                continue

            if not isinstance(payload, dict):
                continue

            parsed = _parse_statuspage(payload) if platform == "statuspage" else _parse_instatus(payload)
            if parsed is not None:
                result = parsed
                logger.info("vendor status: %s parsed as %s", status_page_url, platform)
                break

        if result is None:
            logger.info(
                "vendor status: %s has no recognised machine-readable API", status_page_url
            )

        _cache[status_page_url] = (now, result)
        return result
