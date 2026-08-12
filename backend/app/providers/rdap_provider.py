from app.core.logging import get_logger
from app.providers.http_utils import ProviderFetchError, fetch_json

logger = get_logger(__name__)


class RDAPProvider:
    """RDAP (WHOIS successor) lookups for registrar/registration-date evidence,
    via rdap.org's bootstrap aggregator so we don't need per-registry endpoint
    logic. Used both for a vendor's own domain (informational context on a
    scan) and, in Phase 4, for typosquat-candidate enrichment.

    Not an AssetDiscoveryProvider subclass — RDAP doesn't discover new
    hostnames, so it's kept as a small standalone client used directly by
    other code rather than through the provider ABC hierarchy.
    """

    name = "rdap"

    async def lookup(self, domain: str) -> dict | None:
        url = f"https://rdap.org/domain/{domain}"
        try:
            data = await fetch_json(url, retries=1)
        except ProviderFetchError:
            logger.warning("RDAP lookup for %s was inconclusive (no response)", domain)
            return None

        if not isinstance(data, dict):
            return None

        registrar = None
        for entity in data.get("entities", []):
            if "registrar" not in entity.get("roles", []):
                continue
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field and field[0] == "fn":
                        registrar = field[3]
                        break
            if registrar:
                break

        events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}

        return {
            "registrar": registrar,
            "registration_date": events.get("registration"),
            "last_changed_date": events.get("last changed"),
            "expiration_date": events.get("expiration"),
            "status": data.get("status", []),
        }
