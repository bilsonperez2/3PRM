"""Pure-logic tests for SPF/DMARC parsing — no network, no database. These feed
already-resolved TXT records directly into the parsing functions, which are
split out from DNSProvider.evaluate() specifically so they're testable this
way (see app/providers/dns_provider.py).
"""

from app.providers.base import Confidence
from app.providers.dns_provider import evaluate_dmarc, evaluate_spf


def test_spf_missing_when_no_records() -> None:
    findings = evaluate_spf("acme.com", [])
    assert len(findings) == 1
    assert findings[0].finding_type == "spf_missing"
    assert findings[0].confidence == Confidence.CONFIRMED


def test_spf_present_and_strict_produces_no_finding() -> None:
    findings = evaluate_spf("acme.com", ["v=spf1 include:_spf.google.com -all"])
    assert findings == []


def test_spf_permissive_all_is_flagged() -> None:
    findings = evaluate_spf("acme.com", ["v=spf1 include:_spf.google.com +all"])
    assert len(findings) == 1
    assert findings[0].finding_type == "spf_permissive"
    assert findings[0].severity == "high"


def test_dmarc_missing_when_no_records() -> None:
    findings = evaluate_dmarc("acme.com", [])
    assert len(findings) == 1
    assert findings[0].finding_type == "dmarc_missing"


def test_dmarc_policy_none_is_flagged() -> None:
    findings = evaluate_dmarc("acme.com", ["v=DMARC1; p=none; rua=mailto:dmarc@acme.com"])
    assert len(findings) == 1
    assert findings[0].finding_type == "dmarc_policy_none"
    assert findings[0].evidence["policy"] == "none"


def test_dmarc_policy_reject_produces_no_finding() -> None:
    findings = evaluate_dmarc("acme.com", ["v=DMARC1; p=reject; rua=mailto:dmarc@acme.com"])
    assert findings == []


def test_dmarc_policy_quarantine_produces_no_finding() -> None:
    findings = evaluate_dmarc("acme.com", ["v=DMARC1; p=quarantine"])
    assert findings == []
