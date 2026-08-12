"""Passive DNS/email-security evaluation via Google's DNS-over-HTTPS resolver
(dns.google) — plain HTTPS GET requests, no subprocess calls, same approach
already validated in the prior OSINT dashboard prototype for the Brand
Protection / Domain-IP tabs.
"""

from app.core.logging import get_logger
from app.providers.base import Confidence, DiscoveredAsset, DNSIntelligenceProvider, RawFinding
from app.providers.http_utils import ProviderFetchError, fetch_json

logger = get_logger(__name__)

_DOH_URL = "https://dns.google/resolve"

_RECORD_TYPES = {"A": 1, "AAAA": 28, "CNAME": 5, "MX": 15, "NS": 2, "TXT": 16}

# The DNS/email checks evaluated here — used by scan_ingest to know which
# still-open findings can be auto-remediated when a later scan no longer
# detects the same condition.
DNS_CHECK_FINDING_TYPES = {
    "spf_missing",
    "spf_permissive",
    "dmarc_missing",
    "dmarc_policy_none",
    "mta_sts_missing",
    "tls_rpt_missing",
    "mx_missing",
}


async def _resolve(name: str, record_type: str, *, retries: int = 1) -> list[str]:
    type_code = _RECORD_TYPES[record_type]
    url = f"{_DOH_URL}?name={name}&type={record_type}"
    try:
        data = await fetch_json(url, retries=retries)
    except ProviderFetchError:
        logger.warning("DNS %s lookup for %s was inconclusive (no response)", record_type, name)
        return []
    if not isinstance(data, dict):
        return []
    answers = data.get("Answer", [])
    return [a["data"] for a in answers if a.get("type") == type_code]


def _strip_quotes(txt: str) -> str:
    return txt.strip('"')


class DNSProvider(DNSIntelligenceProvider):
    name = "dns"

    async def evaluate(self, domain: str) -> list[RawFinding]:
        findings: list[RawFinding] = []

        txt_records = [_strip_quotes(t) for t in await _resolve(domain, "TXT")]
        mx_records = await _resolve(domain, "MX")
        dmarc_txt = [_strip_quotes(t) for t in await _resolve(f"_dmarc.{domain}", "TXT")]
        mta_sts_txt = [_strip_quotes(t) for t in await _resolve(f"_mta-sts.{domain}", "TXT")]
        tls_rpt_txt = [_strip_quotes(t) for t in await _resolve(f"_smtp._tls.{domain}", "TXT")]

        spf_records = [t for t in txt_records if t.lower().startswith("v=spf1")]
        findings.extend(evaluate_spf(domain, spf_records))
        findings.extend(evaluate_dmarc(domain, dmarc_txt))

        if not mta_sts_txt:
            findings.append(
                RawFinding(
                    finding_type="mta_sts_missing",
                    title="MTA-STS not configured",
                    description=(
                        f"No MTA-STS policy TXT record found at _mta-sts.{domain}. MTA-STS "
                        "lets a domain require TLS for inbound mail, preventing downgrade/"
                        "interception attacks against SMTP delivery."
                    ),
                    severity="low",
                    confidence=Confidence.CONFIRMED,
                    evidence={"query": f"_mta-sts.{domain} TXT", "result": "no record found"},
                    remediation="Publish an MTA-STS policy and its supporting TXT record.",
                )
            )

        if not tls_rpt_txt:
            findings.append(
                RawFinding(
                    finding_type="tls_rpt_missing",
                    title="TLS-RPT not configured",
                    description=(
                        f"No TLS-RPT TXT record found at _smtp._tls.{domain}. Without it, "
                        "the domain owner receives no reports of TLS delivery failures for "
                        "inbound mail."
                    ),
                    severity="info",
                    confidence=Confidence.CONFIRMED,
                    evidence={"query": f"_smtp._tls.{domain} TXT", "result": "no record found"},
                    remediation="Publish a TLS-RPT TXT record with a reporting address.",
                )
            )

        if not mx_records:
            findings.append(
                RawFinding(
                    finding_type="mx_missing",
                    title="No mail exchanger (MX) records found",
                    description=f"{domain} has no MX records — it cannot receive email directly.",
                    severity="info",
                    confidence=Confidence.CONFIRMED,
                    evidence={"query": f"{domain} MX", "result": "no records found"},
                    remediation=None,
                )
            )

        return findings

    async def collect_assets(self, domain: str) -> list[DiscoveredAsset]:
        """Mail servers and nameservers are internet-facing infrastructure in
        their own right, worth inventorying as Assets — not just data used to
        derive Findings. Not part of the DNSIntelligenceProvider ABC contract
        (which is evaluate() -> findings only); the scan ingestion service
        calls this directly alongside evaluate().
        """
        assets: list[DiscoveredAsset] = []
        for record in await _resolve(domain, "MX"):
            hostname = record.split(" ")[-1].rstrip(".").lower()
            if not hostname:
                continue
            assets.append(
                DiscoveredAsset(
                    hostname=hostname,
                    ip_address=None,
                    asset_type="mail_server",
                    source="dns",
                    ownership_confidence=Confidence.MEDIUM,
                    metadata={"record": record, "record_type": "MX"},
                )
            )
        for record in await _resolve(domain, "NS"):
            hostname = record.rstrip(".").lower()
            if not hostname:
                continue
            assets.append(
                DiscoveredAsset(
                    hostname=hostname,
                    ip_address=None,
                    asset_type="nameserver",
                    source="dns",
                    ownership_confidence=Confidence.MEDIUM,
                    metadata={"record": record, "record_type": "NS"},
                )
            )
        return assets


async def resolve_ips(hostname: str, *, retries: int = 0) -> list[str]:
    """A-record lookup for a single hostname. Used to attach IPs to
    discovered assets (which previously only ever carried a hostname) and to
    build the IP set that passive port/CVE intelligence is keyed on.

    Defaults to retries=0 because this is called once per discovered
    subdomain — potentially dozens per scan — so per-request volume matters
    more than catching every transient blip, same reasoning as the typosquat
    sweep.
    """
    return await _resolve(hostname, "A", retries=retries)


def evaluate_spf(domain: str, spf_records: list[str]) -> list[RawFinding]:
    """Pure logic, split out from evaluate() so it's unit-testable without any
    network access — feed it a list of already-resolved TXT record strings."""
    if not spf_records:
        return [
            RawFinding(
                finding_type="spf_missing",
                title="SPF record not configured",
                description=(
                    f"No SPF TXT record found for {domain}. Without SPF, receiving mail "
                    "servers have no way to verify that mail claiming to be from this "
                    "domain was sent from an authorized source."
                ),
                severity="medium",
                confidence=Confidence.CONFIRMED,
                evidence={"query": f"{domain} TXT", "result": "no v=spf1 record found"},
                remediation="Publish an SPF TXT record listing authorized sending sources.",
            )
        ]

    findings = []
    for record in spf_records:
        if record.lower().rstrip().endswith("+all"):
            findings.append(
                RawFinding(
                    finding_type="spf_permissive",
                    title="SPF record allows any sender (+all)",
                    description=(
                        f"The SPF record for {domain} ends in '+all', which permits mail "
                        "from any source to pass SPF — equivalent to not having SPF at all."
                    ),
                    severity="high",
                    confidence=Confidence.CONFIRMED,
                    evidence={"record": record},
                    remediation="Change the SPF qualifier to '-all' (fail) or '~all' (softfail).",
                )
            )
    return findings


def evaluate_dmarc(domain: str, dmarc_txt: list[str]) -> list[RawFinding]:
    """Pure logic, split out from evaluate() so it's unit-testable without any
    network access — feed it a list of already-resolved _dmarc TXT records."""
    records = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    if not records:
        return [
            RawFinding(
                finding_type="dmarc_missing",
                title="DMARC record not configured",
                description=(
                    f"No DMARC TXT record found at _dmarc.{domain}. Without DMARC, there "
                    "is no enforced policy for mail that fails SPF/DKIM alignment, and no "
                    "visibility into spoofing attempts."
                ),
                severity="high",
                confidence=Confidence.CONFIRMED,
                evidence={"query": f"_dmarc.{domain} TXT", "result": "no v=DMARC1 record found"},
                remediation="Publish a DMARC record starting at p=quarantine or p=reject.",
            )
        ]

    record = records[0]
    policy = None
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            policy = part.split("=", 1)[1].strip().lower()
            break

    if policy == "none":
        return [
            RawFinding(
                finding_type="dmarc_policy_none",
                title="DMARC policy set to 'none' (monitor only)",
                description=(
                    f"The DMARC record for {domain} has p=none, meaning failing mail is "
                    "delivered normally with no enforcement — DMARC is only in monitoring "
                    "mode."
                ),
                severity="medium",
                confidence=Confidence.CONFIRMED,
                evidence={"record": record, "policy": policy},
                remediation=(
                    "Move the DMARC policy to p=quarantine or p=reject once reports are "
                    "reviewed."
                ),
            )
        ]
    return []
