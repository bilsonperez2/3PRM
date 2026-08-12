import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base
from app.models.enums import FindingConfidence, FindingSeverity, FindingStatus, pg_enum


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # e.g. "dmarc_policy_none", "tls_cert_expiring_soon", "kev_exposure_confirmed" —
    # keys into risk_scoring_config.deductions.
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    severity: Mapped[FindingSeverity] = mapped_column(
        pg_enum(FindingSeverity, "finding_severity"), default=FindingSeverity.INFO
    )
    confidence: Mapped[FindingConfidence] = mapped_column(
        pg_enum(FindingConfidence, "finding_confidence"), default=FindingConfidence.MEDIUM
    )

    # Structured, auditable evidence backing this finding (raw DNS record, cert
    # fields, tool/source name, API response metadata, timestamp). Never store
    # secrets or credentials here — see core validation at ingestion time.
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict)

    remediation: Mapped[str | None] = mapped_column(Text)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    status: Mapped[FindingStatus] = mapped_column(
        pg_enum(FindingStatus, "finding_status"), default=FindingStatus.OPEN, nullable=False
    )
    suppressed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    analyst_notes: Mapped[str | None] = mapped_column(Text)

    # Points this finding currently deducts from the vendor's external score, per
    # risk_scoring_config at the time it was last scored. 0 while status is
    # false_positive or while suppressed.
    risk_points: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    vendor: Mapped["Vendor"] = relationship(back_populates="findings")
    asset: Mapped["Asset | None"] = relationship(back_populates="findings")
