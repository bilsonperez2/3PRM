"""Pure-logic tests for the scoring exclusion rules — no database. Finding and
Asset are SQLAlchemy models but nothing here ever flushes/commits them, so
constructing them in memory and passing straight into _counts_toward_score is
safe and needs no infrastructure.
"""

import uuid
from datetime import datetime, timedelta, timezone

from app.models.asset import Asset
from app.models.enums import FindingConfidence, FindingSeverity, FindingStatus, OwnershipConfidence
from app.models.finding import Finding
from app.services.risk_engine.scorer import _counts_toward_score


def _finding(**overrides) -> Finding:
    defaults = dict(
        vendor_id=uuid.uuid4(),
        asset_id=None,
        finding_type="spf_missing",
        title="SPF record not configured",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CONFIRMED,
        evidence={},
        status=FindingStatus.OPEN,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def test_open_confirmed_finding_counts() -> None:
    assert _counts_toward_score(_finding(), {}) is True


def test_false_positive_does_not_count() -> None:
    assert _counts_toward_score(_finding(status=FindingStatus.FALSE_POSITIVE), {}) is False


def test_remediated_does_not_count() -> None:
    assert _counts_toward_score(_finding(status=FindingStatus.REMEDIATED), {}) is False


def test_accepted_risk_still_counts() -> None:
    # Accepting a risk is an internal decision about how to respond, not a
    # change in what an outside attacker would see — must not zero the score.
    assert _counts_toward_score(_finding(status=FindingStatus.ACCEPTED), {}) is True


def test_investigating_still_counts() -> None:
    assert _counts_toward_score(_finding(status=FindingStatus.INVESTIGATING), {}) is True


def test_low_confidence_does_not_count() -> None:
    assert _counts_toward_score(_finding(confidence=FindingConfidence.LOW), {}) is False


def test_informational_confidence_does_not_count() -> None:
    assert _counts_toward_score(_finding(confidence=FindingConfidence.INFORMATIONAL), {}) is False


def test_confirmed_confidence_counts() -> None:
    assert _counts_toward_score(_finding(confidence=FindingConfidence.CONFIRMED), {}) is True


def test_active_suppression_does_not_count() -> None:
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert _counts_toward_score(_finding(suppressed_until=future), {}) is False


def test_expired_suppression_counts_again() -> None:
    past = datetime.now(timezone.utc) - timedelta(days=1)
    assert _counts_toward_score(_finding(suppressed_until=past), {}) is True


def test_low_ownership_confidence_asset_does_not_count() -> None:
    asset_id = uuid.uuid4()
    asset = Asset(
        id=asset_id,
        vendor_id=uuid.uuid4(),
        hostname="test.example.com",
        asset_type="subdomain",
        source="crtsh",
        ownership_confidence=OwnershipConfidence.LOW,
    )
    finding = _finding(asset_id=asset_id)
    assert _counts_toward_score(finding, {asset_id: asset}) is False


def test_unverified_ownership_confidence_asset_does_not_count() -> None:
    asset_id = uuid.uuid4()
    asset = Asset(
        id=asset_id,
        vendor_id=uuid.uuid4(),
        hostname="test.example.com",
        asset_type="subdomain",
        source="crtsh",
        ownership_confidence=OwnershipConfidence.UNVERIFIED,
    )
    finding = _finding(asset_id=asset_id)
    assert _counts_toward_score(finding, {asset_id: asset}) is False


def test_confirmed_ownership_confidence_asset_counts() -> None:
    asset_id = uuid.uuid4()
    asset = Asset(
        id=asset_id,
        vendor_id=uuid.uuid4(),
        hostname="test.example.com",
        asset_type="subdomain",
        source="crtsh",
        ownership_confidence=OwnershipConfidence.CONFIRMED,
    )
    finding = _finding(asset_id=asset_id)
    assert _counts_toward_score(finding, {asset_id: asset}) is True


def test_vendor_level_finding_with_no_asset_counts() -> None:
    # asset_id is None for Phase 2's DNS/email findings — no asset lookup
    # should be attempted, and it must still count.
    assert _counts_toward_score(_finding(asset_id=None), {}) is True
