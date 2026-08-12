from app.core.logging import get_logger
from app.providers.base import CertificateTransparencyProvider, Confidence, DiscoveredAsset
from app.providers.http_utils import ProviderFetchError, fetch_json

logger = get_logger(__name__)


class CrtShProvider(CertificateTransparencyProvider):
    """Certificate Transparency subdomain discovery via crt.sh.

    crt.sh is a free, single-maintainer service that is genuinely erratic —
    identical queries can take 1-8s, hang 25s+, or return a spurious 404/502
    instead of JSON, all within a few requests of each other (observed
    firsthand in the prior OSINT dashboard prototype). `fetch_json`'s
    timeout+single-retry handles the transient case; when it still fails, this
    returns an empty list and logs a warning — that's "crt.sh didn't respond,"
    not "this domain has no subdomains," and callers must not conflate the two.
    """

    name = "crtsh"

    async def discover(self, domain: str) -> list[DiscoveredAsset]:
        # Pass the "%" wildcard through httpx's own query-param encoding rather
        # than hand-building "%25" into the URL string — removes any ambiguity
        # about whether it'd get double-encoded on the wire.
        try:
            data = await fetch_json(
                "https://crt.sh/", retries=1, params={"q": f"%.{domain}", "output": "json"}
            )
        except ProviderFetchError:
            logger.warning(
                "crt.sh lookup for %s was inconclusive (no response after retry)", domain
            )
            return []

        if not isinstance(data, list):
            return []

        hostnames: dict[str, dict] = {}
        for entry in data:
            name_value = entry.get("name_value", "")
            timestamp = entry.get("entry_timestamp")
            for candidate in name_value.split("\n"):
                candidate = candidate.strip().lower().rstrip(".")
                if not candidate:
                    continue
                if candidate != domain and not candidate.endswith(f".{domain}"):
                    continue
                record = hostnames.get(candidate)
                if record is None:
                    hostnames[candidate] = {
                        "wildcard": candidate.startswith("*."),
                        "first_seen_cert": timestamp,
                        "issuer": entry.get("issuer_name"),
                    }
                elif timestamp and record["first_seen_cert"] and timestamp < record["first_seen_cert"]:
                    record["first_seen_cert"] = timestamp

        return [
            DiscoveredAsset(
                hostname=hostname,
                ip_address=None,
                asset_type="subdomain",
                source="crtsh",
                # A cert existing for this name is decent evidence it's related to
                # the domain, but doesn't confirm it currently resolves or is
                # live — MEDIUM, not CONFIRMED/HIGH, until corroborated.
                ownership_confidence=Confidence.MEDIUM,
                metadata=meta,
            )
            for hostname, meta in hostnames.items()
        ]
