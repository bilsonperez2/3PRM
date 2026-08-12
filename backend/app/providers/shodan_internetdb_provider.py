"""Shodan InternetDB — free, keyless, passive port/service/CVE lookup by IP.

This reads Shodan's *existing index* of what it has already observed on the
public internet. It never connects to vendor infrastructure itself, which is
what keeps it inside passive mode. That also sets its confidence ceiling:
Shodan's data reflects whenever it last scanned that host, so it can be stale,
incomplete, or reflect a shared/reassigned IP.

Because of that, nothing here is ever reported as CONFIRMED. A CVE listed
against an IP means "Shodan associated this CVE with software it believed was
running here," not "this vendor is definitely vulnerable" — the spec is
explicit that an identified version must not be treated as confirmed
vulnerable without validation, and validating would require active scanning,
which is deliberately out of scope.
"""

from dataclasses import dataclass

from app.core.logging import get_logger
from app.providers.http_utils import ProviderFetchError, fetch_json

logger = get_logger(__name__)

_INTERNETDB_URL = "https://internetdb.shodan.io"

# Ports where public exposure is notable enough to flag on its own, separate
# from any CVE. Remote-access and database services that generally should not
# be openly reachable from the internet.
_NOTABLE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    445: "SMB",
    1433: "Microsoft SQL Server",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


@dataclass
class InternetDBResult:
    ip: str
    ports: list[int]
    cves: list[str]
    hostnames: list[str]
    tags: list[str]


class ShodanInternetDBProvider:
    """Standalone (not one of the scanning ABCs) — it's an IP-keyed lookup
    whose results feed both Finding generation and asset enrichment, same
    pattern as RDAPProvider."""

    name = "shodan_internetdb"

    async def lookup(self, ip_address: str) -> InternetDBResult | None:
        try:
            data = await fetch_json(f"{_INTERNETDB_URL}/{ip_address}", retries=1)
        except ProviderFetchError:
            # InternetDB returns 404 for IPs it has never indexed, which
            # fetch_json surfaces as a fetch error. That's "no data," not a
            # failure worth escalating — and definitely not "no exposure."
            logger.info("Shodan InternetDB has no record for %s", ip_address)
            return None

        if not isinstance(data, dict):
            return None

        return InternetDBResult(
            ip=ip_address,
            ports=data.get("ports", []) or [],
            cves=data.get("vulns", []) or [],
            hostnames=data.get("hostnames", []) or [],
            tags=data.get("tags", []) or [],
        )


def notable_port_label(port: int) -> str | None:
    return _NOTABLE_PORTS.get(port)
