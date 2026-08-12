"""Risk scoring engine.

Computes a transparent, config-driven external risk score:

  1. Findings are grouped by category (via the active ScoringConfig's
     deduction rules), excluding anything that shouldn't count toward the
     score per the rules below.
  2. Each category starts at 100 and is reduced by its findings' deduction
     points, floored at 0.
  3. The overall score is the weighted sum of category scores (weights sum to
     1.0), rounded to the nearest point.
  4. A RiskScore row is appended — never updated in place — with a full
     category/finding breakdown, so "why did this vendor lose N points" is
     always answerable directly from that row without touching application
     code.

What does NOT count toward the score (each traces to a specific requirement,
not an arbitrary choice):
  - `false_positive` / `remediated` findings — the condition isn't real, or
    isn't true anymore.
  - Currently-suppressed findings.
  - Findings with confidence LOW or INFORMATIONAL — "do not penalize vendors
    based on unverified low-confidence findings."
  - Findings tied to an asset whose ownership_confidence is LOW or
    UNVERIFIED — "only sufficiently attributed assets should significantly
    impact risk scores."

Deliberately still counts: `open`, `investigating`, and `accepted` findings.
Accepting a risk is an internal business decision about how to *respond* to a
gap; it doesn't change what an outside attacker would actually see, so it
must not zero out the external score the way false_positive/remediated do.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.enums import FindingConfidence, FindingStatus, OwnershipConfidence
from app.models.finding import Finding
from app.models.risk_score import RiskScore
from app.models.vendor import Vendor
from app.services.risk_engine.config import get_active_config

_LOW_WEIGHT_CONFIDENCE = {FindingConfidence.LOW, FindingConfidence.INFORMATIONAL}
_LOW_WEIGHT_OWNERSHIP = {OwnershipConfidence.LOW, OwnershipConfidence.UNVERIFIED}
_EXCLUDED_STATUSES = {FindingStatus.FALSE_POSITIVE, FindingStatus.REMEDIATED}


def _grade_for(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _counts_toward_score(finding: Finding, asset_by_id: dict) -> bool:
    if finding.status in _EXCLUDED_STATUSES:
        return False
    if finding.suppressed_until and finding.suppressed_until > datetime.now(timezone.utc):
        return False
    if finding.confidence in _LOW_WEIGHT_CONFIDENCE:
        return False
    if finding.asset_id is not None:
        asset = asset_by_id.get(finding.asset_id)
        if asset is not None and asset.ownership_confidence in _LOW_WEIGHT_OWNERSHIP:
            return False
    return True


def score_vendor(db: Session, vendor_id: uuid.UUID) -> RiskScore:
    vendor = db.get(Vendor, vendor_id)
    if vendor is None:
        raise ValueError(f"Vendor {vendor_id} not found")

    config = get_active_config(db)

    findings = list(db.scalars(select(Finding).where(Finding.vendor_id == vendor_id)))
    assets = list(db.scalars(select(Asset).where(Asset.vendor_id == vendor_id)))
    asset_by_id = {a.id: a for a in assets}

    by_type: dict[str, list[tuple]] = {}
    for finding in findings:
        rule = config.deduction_for(finding.finding_type)
        if rule is None or not _counts_toward_score(finding, asset_by_id):
            continue
        by_type.setdefault(finding.finding_type, []).append((finding, rule))

    category_deductions: dict[str, list[dict]] = {}
    for entries in by_type.values():
        rule = entries[0][1]
        # A non-per_finding rule only ever deducts once for that finding_type,
        # even if (defensively) more than one open row of it somehow exists —
        # per_finding rules (e.g. one deduction per typosquat candidate) sum.
        applied = entries if rule.per_finding else entries[:1]
        for finding, r in applied:
            category_deductions.setdefault(r.category, []).append(
                {
                    "finding_id": str(finding.id),
                    "finding_type": finding.finding_type,
                    "title": finding.title,
                    "points": r.points,
                }
            )

    category_scores: dict[str, dict] = {}
    overall = 0.0
    for category, weight in config.weights.items():
        deductions = category_deductions.get(category, [])
        points_lost = sum(d["points"] for d in deductions)
        category_score = max(0, 100 - points_lost)
        category_scores[category] = {
            "score": category_score,
            "weight": weight,
            "deductions": deductions,
        }
        overall += weight * category_score

    score = max(0, min(100, round(overall)))
    grade = _grade_for(score)

    risk_score = RiskScore(
        vendor_id=vendor_id,
        score=score,
        grade=grade,
        category_scores=category_scores,
        scoring_version=config.version,
    )
    db.add(risk_score)
    db.commit()
    db.refresh(risk_score)
    return risk_score
