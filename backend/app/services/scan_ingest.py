"""Turns provider output into persisted Assets/Findings for a scan run.

Kept separate from app.workers.tasks so this logic is testable and reusable
independent of Celery.
"""

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.asset import Asset
from app.models.enums import FindingConfidence, FindingSeverity, FindingStatus, OwnershipConfidence
from app.models.finding import Finding
from app.providers.base import Confidence, DiscoveredAsset, RawFinding
from app.providers.cisa_kev_provider import get_kev_catalog
from app.providers.crtsh_provider import CrtShProvider
from app.providers.dns_provider import DNS_CHECK_FINDING_TYPES, DNSProvider, resolve_ips
from app.providers.rdap_provider import RDAPProvider
from app.providers.shodan_internetdb_provider import ShodanInternetDBProvider, notable_port_label
from app.providers.subfinder_provider import SubfinderProvider
from app.providers.typosquat_provider import TyposquatProvider
from app.providers.web_provider import (
    WEB_CHECK_FINDING_TYPES,
    WEB_CHECKABLE_ASSET_TYPES,
    WebSecurityProvider,
)

logger = get_logger(__name__)

# Vulnerability intelligence is IP-keyed, so every discovered hostname needs
# an A-record lookup and then a Shodan lookup per unique IP. Both are capped:
# a vendor with hundreds of CT-log subdomains would otherwise turn one scan
# into hundreds of outbound requests. What gets dropped is logged, never
# silently truncated.
_MAX_HOSTS_TO_RESOLVE = 75
_MAX_IPS_TO_ENRICH = 50
_ENRICHMENT_CONCURRENCY = 8

# Web/TLS checks make up to three connections per host, so they're capped
# tighter than the IP lookups. Ordered by ownership confidence first, so a
# cap never drops a confirmed asset in favour of an unverified one.
_MAX_HOSTS_TO_WEB_CHECK = 25
_WEB_CHECK_CONCURRENCY = 6

_CONFIDENCE_RANK = {
    "confirmed": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "informational": 0,
    "unverified": 0,
}


def _confidence_rank(confidence) -> int:
    value = getattr(confidence, "value", confidence)
    return _CONFIDENCE_RANK.get(str(value).lower(), 0)


def _to_ownership_confidence(confidence) -> OwnershipConfidence:
    value = getattr(confidence, "value", confidence)
    try:
        return OwnershipConfidence(value)
    except ValueError:
        return OwnershipConfidence.UNVERIFIED


def _to_finding_confidence(confidence) -> FindingConfidence:
    # Confidence (providers/base.py) and FindingConfidence (models/enums.py)
    # intentionally share an identical value set, so this always succeeds.
    return FindingConfidence(getattr(confidence, "value", confidence))


@dataclass
class GatheredIntelligence:
    assets: list[DiscoveredAsset] = field(default_factory=list)
    findings: list[RawFinding] = field(default_factory=list)
    rdap: dict | None = None
    provider_errors: list[dict] = field(default_factory=list)
    # Hosts the web/TLS checks actually reached this run. Only findings
    # belonging to these hosts are eligible for auto-remediation — see
    # upsert_findings.
    web_checked_hostnames: set[str] = field(default_factory=set)


async def gather_intelligence(domain: str, *, include_typosquat: bool) -> GatheredIntelligence:
    """include_typosquat is True only for is_internal_brand vendors (managed
    through /organization) — typosquat/lookalike-domain monitoring is brand
    protection for your own domain, not something run against third-party
    vendors. See app/workers/tasks.py for where this flag comes from.
    """
    result = GatheredIntelligence()

    dns_provider = DNSProvider()
    crtsh_provider = CrtShProvider()
    subfinder_provider = SubfinderProvider()
    rdap_provider = RDAPProvider()

    async def _safe(label, coro):
        try:
            return await coro
        except Exception as exc:  # one provider failing must not sink the whole scan
            logger.exception("provider %s failed for %s", label, domain)
            result.provider_errors.append({"provider": label, "error": str(exc)})
            return None

    tasks = {
        "dns.evaluate": _safe("dns.evaluate", dns_provider.evaluate(domain)),
        "dns.collect_assets": _safe("dns.collect_assets", dns_provider.collect_assets(domain)),
        "crtsh": _safe("crtsh", crtsh_provider.discover(domain)),
        "subfinder": _safe("subfinder", subfinder_provider.discover(domain)),
        "rdap": _safe("rdap", rdap_provider.lookup(domain)),
    }
    if include_typosquat:
        tasks["typosquat"] = _safe("typosquat", TyposquatProvider().generate_and_evaluate(domain))

    gathered = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values())))

    dns_findings = gathered["dns.evaluate"]
    dns_assets = gathered["dns.collect_assets"]
    crtsh_assets = gathered["crtsh"]
    subfinder_assets = gathered["subfinder"]
    rdap_info = gathered["rdap"]
    typosquat_candidates = gathered.get("typosquat")

    result.findings = list(dns_findings or [])
    result.rdap = rdap_info

    for candidate in typosquat_candidates or []:
        finding_type = "typosquat_active_mail" if candidate.mail_configured else "typosquat_domain_resolves"
        result.findings.append(
            RawFinding(
                finding_type=finding_type,
                title=f"Possible lookalike domain resolves: {candidate.domain}",
                description=(
                    f"{candidate.domain} was generated via {candidate.generation_technique} "
                    f"variation of {domain} and currently resolves"
                    + (
                        ", with mail (MX) configured — actively-usable phishing "
                        "infrastructure, not just a defensively parked domain."
                        if candidate.mail_configured
                        else "."
                    )
                ),
                severity="high" if candidate.mail_configured else "low",
                confidence=Confidence.MEDIUM,
                evidence={
                    # instance_key lets upsert_findings tell apart multiple
                    # candidates that share the same finding_type — see there.
                    "instance_key": candidate.domain,
                    "candidate_domain": candidate.domain,
                    "technique": candidate.generation_technique,
                    "mail_configured": candidate.mail_configured,
                    "registrar": candidate.registrar,
                    "rdap": candidate.evidence.get("rdap"),
                },
                remediation=(
                    "Consider requesting takedown/registration of this domain, or "
                    "monitor it for phishing/brand-abuse activity."
                ),
            )
        )

    merged: dict[str, DiscoveredAsset] = {}
    for asset_list in (dns_assets, crtsh_assets, subfinder_assets):
        for discovered in asset_list or []:
            if not discovered.hostname:
                continue
            key = discovered.hostname.lower()
            existing = merged.get(key)
            if existing is None or _confidence_rank(discovered.ownership_confidence) > _confidence_rank(
                existing.ownership_confidence
            ):
                merged[key] = discovered

    # The vendor's own domain is an asset in its own right, and it's the one
    # we're most confident actually belongs to them — everything else was
    # inferred from CT logs or passive enumeration.
    if domain not in merged:
        merged[domain] = DiscoveredAsset(
            hostname=domain,
            ip_address=None,
            asset_type="subdomain",
            source="vendor_record",
            ownership_confidence=Confidence.CONFIRMED,
            metadata={"note": "vendor's registered primary domain"},
        )

    result.assets = list(merged.values())

    vuln_findings = await _safe("vulnerability_intelligence", _gather_vulnerability_intelligence(result.assets))
    result.findings.extend(vuln_findings or [])

    web_outcome = await _safe("web_security", _gather_web_intelligence(result.assets))
    if web_outcome is not None:
        web_findings, checked_hostnames = web_outcome
        result.findings.extend(web_findings)
        result.web_checked_hostnames = checked_hostnames

    return result


async def _gather_web_intelligence(
    assets: list[DiscoveredAsset],
) -> tuple[list[RawFinding], set[str]]:
    """Runs HTTPS/TLS/security-header checks against web-serving assets.

    Returns the findings plus the set of hostnames actually attempted, so the
    ingestion layer knows which hosts' previous findings are safe to
    auto-remediate (a host skipped by the cap must not have its findings
    silently closed).
    """
    candidates = [
        a
        for a in assets
        if a.hostname
        and not a.hostname.startswith("*.")
        and a.asset_type in WEB_CHECKABLE_ASSET_TYPES
    ]
    # Highest ownership confidence first — if the cap bites, we'd rather check
    # the vendor's confirmed primary domain than an unverified CT-log entry.
    candidates.sort(key=lambda a: _confidence_rank(a.ownership_confidence), reverse=True)

    to_check = candidates[:_MAX_HOSTS_TO_WEB_CHECK]
    if len(candidates) > _MAX_HOSTS_TO_WEB_CHECK:
        logger.info(
            "web checks: evaluating %s of %s web-capable hosts (per-scan cap)",
            _MAX_HOSTS_TO_WEB_CHECK,
            len(candidates),
        )

    provider = WebSecurityProvider()
    semaphore = asyncio.Semaphore(_WEB_CHECK_CONCURRENCY)

    async def _check_one(hostname: str):
        async with semaphore:
            try:
                return hostname, await provider.evaluate(hostname)
            except Exception:
                logger.exception("web check failed for %s", hostname)
                return hostname, None

    results = await asyncio.gather(*(_check_one(a.hostname) for a in to_check))

    findings: list[RawFinding] = []
    checked: set[str] = set()
    for hostname, host_findings in results:
        if host_findings is None:
            # The check itself errored — we learned nothing about this host,
            # so it must not count as "checked and clean."
            continue
        checked.add(hostname)
        findings.extend(host_findings)

    logger.info("web checks: %s hosts evaluated, %s findings", len(checked), len(findings))
    return findings, checked


async def _gather_vulnerability_intelligence(assets: list[DiscoveredAsset]) -> list[RawFinding]:
    """Resolves each discovered hostname to IPs, looks each unique IP up in
    Shodan's passive index, and cross-references any CVEs it reports against
    the CISA KEV catalog.

    Mutates `assets` in place to attach resolved IPs — assets previously only
    ever carried a hostname.
    """
    findings: list[RawFinding] = []
    semaphore = asyncio.Semaphore(_ENRICHMENT_CONCURRENCY)

    # crt.sh legitimately returns wildcard names (*.acme.com) and we keep them
    # as Asset rows, but a wildcard has no A record of its own — resolving it
    # is a guaranteed-useless lookup, so it's excluded here rather than
    # burning one of the per-scan resolution slots.
    resolvable = [a for a in assets if a.hostname and not a.hostname.startswith("*.")]

    to_resolve = resolvable[:_MAX_HOSTS_TO_RESOLVE]
    if len(resolvable) > _MAX_HOSTS_TO_RESOLVE:
        logger.info(
            "vulnerability intel: resolving %s of %s resolvable hosts (per-scan cap)",
            _MAX_HOSTS_TO_RESOLVE,
            len(resolvable),
        )

    async def _resolve_one(asset: DiscoveredAsset) -> None:
        async with semaphore:
            ips = await resolve_ips(asset.hostname)
        if ips:
            asset.ip_address = ips[0]
            asset.metadata = {**asset.metadata, "resolved_ips": ips}

    await asyncio.gather(*(_resolve_one(a) for a in to_resolve))

    # One IP often backs many hostnames (shared hosting, CDN, load balancer),
    # so enrich per unique IP and map results back to every hostname on it.
    ip_to_hostnames: dict[str, list[str]] = {}
    for asset in to_resolve:
        for ip in asset.metadata.get("resolved_ips", []):
            ip_to_hostnames.setdefault(ip, []).append(asset.hostname)

    unique_ips = list(ip_to_hostnames)[:_MAX_IPS_TO_ENRICH]
    if len(ip_to_hostnames) > _MAX_IPS_TO_ENRICH:
        logger.info(
            "vulnerability intel: enriching %s of %s unique IPs (per-scan cap)",
            _MAX_IPS_TO_ENRICH,
            len(ip_to_hostnames),
        )

    if not unique_ips:
        # Nothing resolved, so there's nothing to look up — skip the KEV
        # catalog fetch entirely rather than pulling ~1MB to check zero CVEs.
        logger.info("vulnerability intel: no hosts resolved to IPs, skipping enrichment")
        return findings

    shodan = ShodanInternetDBProvider()

    async def _enrich_one(ip: str):
        async with semaphore:
            return await shodan.lookup(ip)

    kev_catalog, shodan_results = await asyncio.gather(
        get_kev_catalog(),
        asyncio.gather(*(_enrich_one(ip) for ip in unique_ips)),
    )

    for ip, shodan_result in zip(unique_ips, shodan_results):
        if shodan_result is None:
            continue
        hostnames = ip_to_hostnames.get(ip, [])
        primary_hostname = hostnames[0] if hostnames else None

        for cve_id in shodan_result.cves:
            kev_entry = kev_catalog.get(cve_id)
            findings.append(_build_cve_finding(ip, primary_hostname, hostnames, cve_id, kev_entry, shodan_result))

        for port in shodan_result.ports:
            label = notable_port_label(port)
            if label:
                findings.append(_build_exposed_port_finding(ip, primary_hostname, hostnames, port, label))

    return findings


def _build_cve_finding(ip, primary_hostname, hostnames, cve_id, kev_entry, shodan_result) -> RawFinding:
    is_kev = kev_entry is not None
    evidence = {
        "instance_key": f"{ip}:{cve_id}",
        "cve_id": cve_id,
        "ip_address": ip,
        "hostnames_on_ip": hostnames,
        "source": "shodan_internetdb",
        "shodan_reported_cves": shodan_result.cves,
        "in_cisa_kev": is_kev,
    }
    if is_kev:
        evidence["kev_vendor_project"] = kev_entry.get("vendorProject")
        evidence["kev_product"] = kev_entry.get("product")
        evidence["kev_date_added"] = kev_entry.get("dateAdded")
        evidence["kev_known_ransomware"] = kev_entry.get("knownRansomwareCampaignUse")

    if is_kev:
        return RawFinding(
            finding_type="kev_exposure_confirmed",
            title=f"{cve_id} (actively exploited) associated with {primary_hostname or ip}",
            description=(
                f"Shodan's passive index associates {cve_id} with {ip}"
                + (f" ({primary_hostname})" if primary_hostname else "")
                + f". This CVE is on CISA's Known Exploited Vulnerabilities catalog — "
                f"{kev_entry.get('vulnerabilityName', 'it')} is being actively exploited in "
                "the wild. Note that Shodan's association is based on observed service "
                "banners/versions, not on confirming the vulnerability is exploitable here."
            ),
            severity="critical",
            # HIGH, not CONFIRMED: KEV confirms the CVE is being exploited
            # somewhere, and Shodan associates it with this host — but neither
            # confirms this specific host is actually vulnerable.
            confidence=Confidence.HIGH,
            evidence=evidence,
            remediation=(
                f"Confirm with the vendor whether {cve_id} has been patched on internet-facing "
                "infrastructure. CISA-KEV vulnerabilities should be treated as urgent."
            ),
            asset_hostname=primary_hostname,
        )

    return RawFinding(
        finding_type="shodan_known_vulnerability",
        title=f"{cve_id} associated with {primary_hostname or ip}",
        description=(
            f"Shodan's passive index associates {cve_id} with {ip}"
            + (f" ({primary_hostname})" if primary_hostname else "")
            + ". This is based on observed service banners/version strings, not on "
            "confirming the vulnerability is present or exploitable — treat as a lead to "
            "verify with the vendor, not a confirmed exposure."
        ),
        severity="medium",
        confidence=Confidence.LOW,
        evidence=evidence,
        remediation=f"Ask the vendor to confirm patch status for {cve_id}.",
        asset_hostname=primary_hostname,
    )


def _build_exposed_port_finding(ip, primary_hostname, hostnames, port, label) -> RawFinding:
    return RawFinding(
        finding_type="exposed_service_passive",
        title=f"{label} (port {port}) reachable on {primary_hostname or ip}",
        description=(
            f"Shodan's passive index shows port {port} ({label}) open on {ip}"
            + (f" ({primary_hostname})" if primary_hostname else "")
            + ". Remote-access and database services exposed directly to the internet are "
            "a common initial-access vector and usually warrant review. Shodan data "
            "reflects its last scan of this host and may be out of date."
        ),
        severity="high" if port in {23, 3389, 445} else "medium",
        confidence=Confidence.MEDIUM,
        evidence={
            "instance_key": f"{ip}:{port}",
            "ip_address": ip,
            "port": port,
            "service": label,
            "hostnames_on_ip": hostnames,
            "source": "shodan_internetdb",
        },
        remediation=(
            f"Confirm with the vendor whether {label} needs to be internet-facing, or whether "
            "it can be restricted to a VPN/allowlist."
        ),
        asset_hostname=primary_hostname,
    )


def upsert_assets(db: Session, vendor_id: uuid.UUID, assets: list[DiscoveredAsset]) -> None:
    now = datetime.now(timezone.utc)
    for discovered in assets:
        existing = db.scalar(
            select(Asset).where(Asset.vendor_id == vendor_id, Asset.hostname == discovered.hostname)
        )
        ownership_confidence = _to_ownership_confidence(discovered.ownership_confidence)
        if existing is not None:
            existing.last_seen = now
            existing.active = True
            existing.asset_metadata = {**existing.asset_metadata, **discovered.metadata}
            # Assets discovered before IP resolution existed have no IP, and an
            # IP can legitimately change between scans — keep it current.
            if discovered.ip_address:
                existing.ip_address = discovered.ip_address
            if _confidence_rank(ownership_confidence) > _confidence_rank(existing.ownership_confidence):
                existing.ownership_confidence = ownership_confidence
        else:
            db.add(
                Asset(
                    vendor_id=vendor_id,
                    hostname=discovered.hostname,
                    ip_address=discovered.ip_address,
                    asset_type=discovered.asset_type,
                    source=discovered.source,
                    ownership_confidence=ownership_confidence,
                    asset_metadata=discovered.metadata,
                )
            )
    db.commit()


def upsert_findings(
    db: Session,
    vendor_id: uuid.UUID,
    raw_findings: list[RawFinding],
    web_checked_hostnames: set[str] | None = None,
) -> None:
    """Upserts findings and auto-remediates any still-OPEN DNS/email finding
    whose condition is no longer detected on this scan.

    Findings carrying an `asset_hostname` (the vulnerability/exposed-port ones)
    are linked to that Asset row; the DNS/email checks evaluate the domain as a
    whole and stay vendor-level with asset_id=None. The linkage matters beyond
    display: the scoring engine discounts findings attached to an asset whose
    ownership_confidence is low/unverified.

    A finding an analyst already triaged (accepted / false_positive /
    investigating) is never silently reopened or auto-closed here — only
    OPEN findings are touched, both on the way in and the way out.
    """
    now = datetime.now(timezone.utc)
    detected_types: set[str] = set()
    detected_web_pairs: set[tuple[str, str]] = set()

    asset_ids_by_hostname = {
        hostname: asset_id
        for asset_id, hostname in db.execute(
            select(Asset.id, Asset.hostname).where(Asset.vendor_id == vendor_id)
        )
    }

    for raw in raw_findings:
        detected_types.add(raw.finding_type)
        if raw.finding_type in WEB_CHECK_FINDING_TYPES and raw.asset_hostname:
            detected_web_pairs.add((raw.finding_type, raw.asset_hostname))
        asset_id = asset_ids_by_hostname.get(raw.asset_hostname) if raw.asset_hostname else None

        conditions = [
            Finding.vendor_id == vendor_id,
            Finding.finding_type == raw.finding_type,
            Finding.asset_id == asset_id if asset_id is not None else Finding.asset_id.is_(None),
        ]
        # Findings from a per-instance source (one per typosquat candidate,
        # one per CVE/port on an IP) all share the same finding_type but
        # represent different things — instance_key in evidence disambiguates
        # them so they don't collapse into a single row. Findings without one
        # (the DNS/email checks, which only ever produce at most one open row
        # per vendor per finding_type) keep the original, simpler lookup.
        instance_key = raw.evidence.get("instance_key")
        if instance_key:
            conditions.append(Finding.evidence["instance_key"].astext == instance_key)
        existing = db.scalar(select(Finding).where(*conditions))
        if existing is not None:
            if existing.status == FindingStatus.OPEN:
                existing.last_seen = now
                existing.evidence = raw.evidence
                existing.description = raw.description
                existing.severity = FindingSeverity(raw.severity)
                existing.confidence = _to_finding_confidence(raw.confidence)
            # else: analyst already triaged this finding — leave status/fields
            # alone even though the condition is still present.
        else:
            db.add(
                Finding(
                    vendor_id=vendor_id,
                    asset_id=asset_id,
                    finding_type=raw.finding_type,
                    title=raw.title,
                    description=raw.description,
                    severity=FindingSeverity(raw.severity),
                    confidence=_to_finding_confidence(raw.confidence),
                    evidence=raw.evidence,
                    remediation=raw.remediation,
                    status=FindingStatus.OPEN,
                )
            )

    # Auto-remediation is deliberately limited to the DNS/email checks. For
    # those, we actively queried and got a definitive answer, so "no longer
    # detected" genuinely means the condition is gone. Vulnerability and
    # exposed-port findings come from Shodan's index, where a missing result
    # can equally mean Shodan hasn't rescanned, the IP rotated, or a per-scan
    # cap skipped it — closing those automatically would be treating absence
    # of evidence as proof of remediation. They stay open until an analyst
    # triages them.
    resolved_types = DNS_CHECK_FINDING_TYPES - detected_types
    if resolved_types:
        stale = db.scalars(
            select(Finding).where(
                Finding.vendor_id == vendor_id,
                Finding.status == FindingStatus.OPEN,
                Finding.finding_type.in_(resolved_types),
            )
        )
        for finding in stale:
            finding.status = FindingStatus.REMEDIATED
            finding.last_seen = now

    # Web findings are per-host, so they can't be remediated by finding_type
    # alone: host A still failing a check must not keep host B's fixed finding
    # open, and vice versa. Only hosts actually reached this run are eligible —
    # a host skipped by the per-scan cap or unreachable due to a transient
    # error keeps its findings untouched rather than being assumed fixed.
    if web_checked_hostnames:
        open_web_findings = db.scalars(
            select(Finding).where(
                Finding.vendor_id == vendor_id,
                Finding.status == FindingStatus.OPEN,
                Finding.finding_type.in_(WEB_CHECK_FINDING_TYPES),
            )
        )
        for finding in open_web_findings:
            hostname = (finding.evidence or {}).get("hostname")
            if hostname not in web_checked_hostnames:
                continue
            if (finding.finding_type, hostname) not in detected_web_pairs:
                finding.status = FindingStatus.REMEDIATED
                finding.last_seen = now

    db.commit()
