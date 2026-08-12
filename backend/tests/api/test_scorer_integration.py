"""Integration test for the full risk scoring pipeline — needs Postgres for
JSONB/UUID columns; see tests/conftest.py. Seeds its own RiskScoringConfig row
per test rather than relying on the Alembic seed migration, since these
fixtures build the schema via Base.metadata.create_all (no migration data).
"""

import uuid

from app.models.enums import FindingConfidence, FindingSeverity, FindingStatus
from app.models.finding import Finding
from app.models.risk_score import RiskScore, RiskScoringConfig
from app.models.vendor import Vendor
from app.services.risk_engine.scorer import score_vendor
from tests.conftest import requires_postgres

pytestmark = requires_postgres


def _seed_config(db_session) -> None:
    db_session.add(
        RiskScoringConfig(
            version="test-1",
            weights={"email_security": 1.0},
            deductions={
                "spf_missing": {"points": 20, "category": "email_security"},
                "dmarc_missing": {"points": 10, "category": "email_security"},
            },
            active=True,
        )
    )
    db_session.commit()


def _make_vendor(db_session) -> Vendor:
    vendor = Vendor(name="Acme Corp", primary_domain=f"{uuid.uuid4().hex}.example.com")
    db_session.add(vendor)
    db_session.commit()
    db_session.refresh(vendor)
    return vendor


def test_score_reflects_open_findings_deductions(db_session) -> None:
    _seed_config(db_session)
    vendor = _make_vendor(db_session)
    db_session.add_all(
        [
            Finding(
                vendor_id=vendor.id,
                finding_type="spf_missing",
                title="SPF record not configured",
                severity=FindingSeverity.MEDIUM,
                confidence=FindingConfidence.CONFIRMED,
                evidence={},
                status=FindingStatus.OPEN,
            ),
            Finding(
                vendor_id=vendor.id,
                finding_type="dmarc_missing",
                title="DMARC record not configured",
                severity=FindingSeverity.HIGH,
                confidence=FindingConfidence.CONFIRMED,
                evidence={},
                status=FindingStatus.OPEN,
            ),
        ]
    )
    db_session.commit()

    result = score_vendor(db_session, vendor.id)

    assert result.score == 70
    assert result.grade == "C"
    email_category = result.category_scores["email_security"]
    assert email_category["score"] == 70
    reasons = {d["finding_type"] for d in email_category["deductions"]}
    assert reasons == {"spf_missing", "dmarc_missing"}


def test_false_positive_finding_excluded_from_score(db_session) -> None:
    _seed_config(db_session)
    vendor = _make_vendor(db_session)
    db_session.add(
        Finding(
            vendor_id=vendor.id,
            finding_type="spf_missing",
            title="SPF record not configured",
            severity=FindingSeverity.MEDIUM,
            confidence=FindingConfidence.CONFIRMED,
            evidence={},
            status=FindingStatus.FALSE_POSITIVE,
        )
    )
    db_session.commit()

    result = score_vendor(db_session, vendor.id)

    assert result.score == 100
    assert result.category_scores["email_security"]["deductions"] == []


def test_score_history_is_append_only(db_session) -> None:
    _seed_config(db_session)
    vendor = _make_vendor(db_session)

    first = score_vendor(db_session, vendor.id)
    second = score_vendor(db_session, vendor.id)

    assert first.id != second.id
    rows = db_session.query(RiskScore).filter(RiskScore.vendor_id == vendor.id).all()
    assert len(rows) == 2
    assert {row.id for row in rows} == {first.id, second.id}
