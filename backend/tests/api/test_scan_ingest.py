"""Integration tests for the upsert/auto-remediate logic in
app.services.scan_ingest — needs a real Postgres (JSONB/UUID columns), so this
skips cleanly if none is reachable; see tests/conftest.py.
"""

import uuid

from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.models.vendor import Vendor
from app.providers.base import Confidence, DiscoveredAsset, RawFinding
from app.services.scan_ingest import upsert_assets, upsert_findings
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _make_vendor(db_session) -> Vendor:
    vendor = Vendor(name="Acme Corp", primary_domain=f"{uuid.uuid4().hex}.example.com")
    db_session.add(vendor)
    db_session.commit()
    db_session.refresh(vendor)
    return vendor


def test_upsert_assets_creates_then_updates_without_duplicating(db_session) -> None:
    vendor = _make_vendor(db_session)
    discovered = DiscoveredAsset(
        hostname="www.acme.com",
        ip_address=None,
        asset_type="subdomain",
        source="crtsh",
        ownership_confidence=Confidence.MEDIUM,
        metadata={"wildcard": False},
    )

    upsert_assets(db_session, vendor.id, [discovered])
    upsert_assets(db_session, vendor.id, [discovered])

    db_session.refresh(vendor)
    assert len(vendor.assets) == 1
    assert vendor.assets[0].hostname == "www.acme.com"


def test_upsert_assets_upgrades_confidence_but_never_downgrades(db_session) -> None:
    vendor = _make_vendor(db_session)
    low_confidence = DiscoveredAsset(
        hostname="api.acme.com",
        ip_address=None,
        asset_type="subdomain",
        source="crtsh",
        ownership_confidence=Confidence.MEDIUM,
        metadata={},
    )
    high_confidence = DiscoveredAsset(
        hostname="api.acme.com",
        ip_address=None,
        asset_type="subdomain",
        source="dns",
        ownership_confidence=Confidence.HIGH,
        metadata={},
    )

    upsert_assets(db_session, vendor.id, [high_confidence])
    upsert_assets(db_session, vendor.id, [low_confidence])

    db_session.refresh(vendor)
    assert vendor.assets[0].ownership_confidence.value == "high"


def test_upsert_findings_creates_open_finding(db_session) -> None:
    vendor = _make_vendor(db_session)
    raw = RawFinding(
        finding_type="spf_missing",
        title="SPF record not configured",
        description="No SPF TXT record found.",
        severity="medium",
        confidence=Confidence.CONFIRMED,
        evidence={"query": "acme.com TXT"},
        remediation="Publish an SPF record.",
    )

    upsert_findings(db_session, vendor.id, [raw])

    findings = db_session.query(Finding).filter(Finding.vendor_id == vendor.id).all()
    assert len(findings) == 1
    assert findings[0].status == FindingStatus.OPEN
    assert findings[0].finding_type == "spf_missing"


def test_upsert_findings_auto_remediates_when_condition_clears(db_session) -> None:
    vendor = _make_vendor(db_session)
    raw = RawFinding(
        finding_type="spf_missing",
        title="SPF record not configured",
        description="No SPF TXT record found.",
        severity="medium",
        confidence=Confidence.CONFIRMED,
        evidence={},
        remediation=None,
    )
    upsert_findings(db_session, vendor.id, [raw])

    # Next scan no longer detects spf_missing — the vendor fixed it.
    upsert_findings(db_session, vendor.id, [])

    finding = db_session.query(Finding).filter(Finding.vendor_id == vendor.id).one()
    assert finding.status == FindingStatus.REMEDIATED


def test_upsert_findings_does_not_reopen_accepted_risk(db_session) -> None:
    vendor = _make_vendor(db_session)
    raw = RawFinding(
        finding_type="dmarc_missing",
        title="DMARC record not configured",
        description="No DMARC TXT record found.",
        severity="high",
        confidence=Confidence.CONFIRMED,
        evidence={},
        remediation=None,
    )
    upsert_findings(db_session, vendor.id, [raw])

    finding = db_session.query(Finding).filter(Finding.vendor_id == vendor.id).one()
    finding.status = FindingStatus.ACCEPTED
    db_session.commit()

    # Same condition detected again — must NOT flip back to OPEN.
    upsert_findings(db_session, vendor.id, [raw])

    db_session.refresh(finding)
    assert finding.status == FindingStatus.ACCEPTED
