"""Shared HTTP helper for provider adapters.

Applies one retry policy uniformly: try once, and on failure retry exactly
once more, then give up. This matches the crt.sh lesson from the prior OSINT
dashboard prototype (erratic public services need a timeout and a single
retry, not aggressive re-querying, and "no response" must be treated as
inconclusive rather than a negative result) — applied here to every provider
that makes outbound HTTP calls, not just crt.sh.
"""

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class ProviderFetchError(Exception):
    """Raised when a provider's outbound HTTP call could not get a usable
    response after retrying. Callers must treat this as inconclusive — e.g.
    "crt.sh didn't respond," never "this domain has no subdomains."
    """


async def fetch_json(
    url: str,
    *,
    retries: int = 1,
    headers: dict | None = None,
    params: dict | None = None,
):
    settings = get_settings()
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            # follow_redirects=True: RDAP in particular is built around
            # redirecting from a bootstrap aggregator (rdap.org) to the
            # authoritative registry's own RDAP server (e.g. rdap.verisign.com)
            # — without this, every RDAP lookup fails on the 3xx response
            # itself (httpx's raise_for_status() treats an unfollowed redirect
            # as an error) rather than actually reaching the data.
            async with httpx.AsyncClient(
                timeout=settings.scan_timeout_seconds, follow_redirects=True
            ) as client:
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()
                return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            last_exc = exc
            logger.warning(
                "fetch_json attempt %s/%s failed for %s: %s", attempt + 1, retries + 1, url, exc
            )
    raise ProviderFetchError(f"Failed to fetch {url} after {retries + 1} attempt(s)") from last_exc


async def fetch_text(
    url: str,
    *,
    retries: int = 1,
    headers: dict | None = None,
    params: dict | None = None,
) -> str:
    """Same shape as fetch_json but returns the raw response body — for
    non-JSON sources like RSS/Atom feeds."""
    settings = get_settings()
    last_exc: Exception | None = None
    for attempt in range(retries + 1):
        try:
            async with httpx.AsyncClient(
                timeout=settings.scan_timeout_seconds, follow_redirects=True
            ) as client:
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()
                return response.text
        except httpx.HTTPError as exc:
            last_exc = exc
            logger.warning(
                "fetch_text attempt %s/%s failed for %s: %s", attempt + 1, retries + 1, url, exc
            )
    raise ProviderFetchError(f"Failed to fetch {url} after {retries + 1} attempt(s)") from last_exc
