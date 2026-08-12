import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base


class RiskScore(Base):
    """Append-only external risk score snapshot.

    Never updated in place — a new row is written every time the vendor is
    re-scored, so trend charts and "what changed since last scan" are a plain
    query over history rather than a diff against mutated state.
    """

    __tablename__ = "risk_scores"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )

    score: Mapped[int] = mapped_column(Integer, nullable=False)
    grade: Mapped[str] = mapped_column(String(2), nullable=False)

    # Per-category breakdown and the ordered list of (finding_id, reason, points)
    # deductions that produced `score` — this is what answers "why did this vendor
    # lose N points."
    category_scores: Mapped[dict] = mapped_column(JSONB, default=dict)

    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    scoring_version: Mapped[str] = mapped_column(String(32), nullable=False)

    vendor: Mapped["Vendor"] = relationship(back_populates="risk_scores")


class RiskScoringConfig(Base):
    """Versioned scoring configuration — category weights and per-finding-type
    deduction rules. Lives in the database (not hardcoded in application code) so
    weights can be tuned without a deploy. Only one row should have active=True at
    a time; the risk engine reads that row.
    """

    __tablename__ = "risk_scoring_config"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    version: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    weights: Mapped[dict] = mapped_column(JSONB, nullable=False)
    deductions: Mapped[dict] = mapped_column(JSONB, nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
