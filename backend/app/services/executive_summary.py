"""Builds a plain-language executive summary for a vendor.

Pure presentation logic over data already computed elsewhere (RiskScore,
Finding) — no new external calls, no new stored state. Exists so "hand this to
a stakeholder" doesn't mean reading raw JSON off the Findings tab. Mirrors the
format from the platform spec:

    Vendor: Example Corp
    Overall Risk: Moderate
    External Security: 82/100
    Business Criticality: High
    Key Concerns: ...
    Positive Indicators: ...
    Recommended Action: ...
"""

from datetime import datetime, timezone

from app.models.enums import FindingStatus
from app.models.finding import Finding
from app.models.risk_score import RiskScore
from app.models.vendor import Vendor
from app.schemas.executive_summary import ExecutiveSummary

_GRADE_TO_RISK_LABEL = {
    "A": "Low",
    "B": "Low",
    "C": "Moderate",
    "D": "High",
    "F": "Critical",
}

_RECOMMENDED_ACTION_BY_LABEL = {
    "Low": "No immediate action required; continue routine monitoring.",
    "Moderate": "Monitor for changes and re-evaluate at the next scheduled review.",
    "High": (
        "Request vendor remediation for the findings below and re-evaluate within 30 days."
    ),
    "Critical": (
        "Escalate to the vendor immediately, request remediation, and re-evaluate within "
        "2 weeks. Consider whether current data/system access levels remain appropriate "
        "until resolved."
    ),
    "Unknown": "Run an initial scan to establish a baseline before assessing risk.",
}

# Only findings still representing a live, un-dismissed condition feed the
# summary — false_positive (not real) and remediated (already fixed) don't
# belong in a "here's what's currently wrong" readout.
_ACTIVE_STATUSES = {FindingStatus.OPEN, FindingStatus.INVESTIGATING, FindingStatus.ACCEPTED}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def build_executive_summary(
    vendor: Vendor, latest_score: RiskScore | None, findings: list[Finding]
) -> ExecutiveSummary:
    active_findings = [f for f in findings if f.status in _ACTIVE_STATUSES]

    risk_label = _GRADE_TO_RISK_LABEL.get(latest_score.grade, "Unknown") if latest_score else "Unknown"

    key_concerns = [
        f.title
        for f in sorted(
            active_findings,
            key=lambda f: _SEVERITY_ORDER.get(f.severity.value, 0),
            reverse=True,
        )[:5]
    ]

    return ExecutiveSummary(
        vendor_id=vendor.id,
        vendor_name=vendor.name,
        overall_risk_label=risk_label,
        external_security_score=latest_score.score if latest_score else None,
        external_security_grade=latest_score.grade if latest_score else None,
        business_criticality=vendor.criticality.value.capitalize(),
        key_concerns=key_concerns,
        positive_indicators=_build_positive_indicators(active_findings),
        recommended_action=_RECOMMENDED_ACTION_BY_LABEL.get(
            risk_label, "Review findings and determine next steps with the vendor."
        ),
        generated_at=datetime.now(timezone.utc),
    )


def _build_positive_indicators(active_findings: list[Finding]) -> list[str]:
    active_types = {f.finding_type for f in active_findings}
    indicators = []

    if not any("kev" in t for t in active_types):
        indicators.append("No known CISA KEV (actively exploited vulnerability) exposure identified.")
    if "spf_missing" not in active_types and "spf_permissive" not in active_types:
        indicators.append("SPF is configured correctly.")
    if "dmarc_missing" not in active_types and "dmarc_policy_none" not in active_types:
        indicators.append("DMARC is configured and enforced.")
    if "typosquat_active_mail" not in active_types:
        indicators.append("No lookalike domains detected with active mail configured.")
    if not any(t.startswith("tls_cert") or t == "hsts_missing" for t in active_types):
        indicators.append("No TLS/certificate issues currently detected.")

    if not indicators:
        indicators.append("No specific positive indicators identified from current findings.")

    return indicators
