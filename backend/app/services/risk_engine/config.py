"""Risk scoring configuration loader.

Weights and per-finding-type deduction rules live in the `risk_scoring_config`
table (see app.models.risk_score.RiskScoringConfig), not hardcoded in
application code, so they can be tuned without a deploy. Exactly one row is
expected to have active=True at a time; scorer.py reads that row through
get_active_config().
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.risk_score import RiskScoringConfig


@dataclass
class DeductionRule:
    points: int
    category: str
    per_finding: bool = False


@dataclass
class ScoringConfig:
    version: str
    weights: dict[str, float]
    deductions: dict[str, DeductionRule]

    def deduction_for(self, finding_type: str) -> DeductionRule | None:
        return self.deductions.get(finding_type)


class NoActiveScoringConfigError(Exception):
    """Raised when no risk_scoring_config row has active=True. Seed one via
    migration (see alembic/versions/0002_seed_risk_scoring_config.py) or
    activate an existing row before scoring vendors."""


def get_active_config(db: Session) -> ScoringConfig:
    row = db.scalar(select(RiskScoringConfig).where(RiskScoringConfig.active.is_(True)))
    if row is None:
        raise NoActiveScoringConfigError(
            "No active risk_scoring_config row found. Seed one via migration or "
            "activate an existing RiskScoringConfig row."
        )
    deductions = {
        finding_type: DeductionRule(
            points=rule["points"],
            category=rule["category"],
            per_finding=rule.get("per_finding", False),
        )
        for finding_type, rule in row.deductions.items()
    }
    return ScoringConfig(version=row.version, weights=row.weights, deductions=deductions)
