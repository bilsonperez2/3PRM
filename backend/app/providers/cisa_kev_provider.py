"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The single most reliable public vulnerability source in this stack — one JSON
fetch, no API key, no rate limiting observed in prior OSINT dashboard use.
It answers a narrow but high-value question: "is this CVE known to be
actively exploited in the wild right now?"

Used as a cross-reference rather than a discovery source: something else
(Shodan InternetDB) tells us which CVEs are associated with a host, and this
tells us which of those CISA considers actively exploited — which is the
difference between "a vulnerability exists somewhere in this software" and
"attackers are using this today."
"""

import time

from app.core.logging import get_logger
from app.providers.http_utils import ProviderFetchError, fetch_json

logger = get_logger(__name__)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# The catalog is a single ~1MB document updated at most daily, so it's cached
# process-wide and shared across every vendor/asset lookup in a scan run.
_CACHE_TTL_SECONDS = 6 * 60 * 60
_cache: dict[str, tuple[float, dict[str, dict]]] = {}


async def get_kev_catalog() -> dict[str, dict]:
    """Returns {CVE_ID: kev_entry}. Empty dict if the fetch fails — callers
    must treat that as "couldn't check KEV," not "no CVEs are exploited."
    """
    now = time.time()
    cached = _cache.get("catalog")
    if cached and now - cached[0] < _CACHE_TTL_SECONDS:
        return cached[1]

    try:
        data = await fetch_json(_KEV_URL, retries=1)
    except ProviderFetchError:
        logger.warning("CISA KEV catalog fetch failed — KEV cross-reference unavailable this run")
        return {}

    if not isinstance(data, dict):
        return {}

    catalog = {
        entry["cveID"]: entry
        for entry in data.get("vulnerabilities", [])
        if entry.get("cveID")
    }
    _cache["catalog"] = (now, catalog)
    logger.info("CISA KEV catalog loaded: %s entries", len(catalog))
    return catalog
