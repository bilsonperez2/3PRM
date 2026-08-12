import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base
from app.models.enums import TriState, pg_enum


class GovernanceProfile(Base):
    """Vendor governance / TPRM attestation data.

    Deliberately kept separate from RiskScore (external technical risk). This is
    manually attested, not derived from scanning, and must never be blended
    automatically into the external score — it feeds a distinct governance score
    that later combines with business criticality and external risk into an
    overall vendor risk view.
    """

    __tablename__ = "governance_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("vendors.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    soc2_reviewed: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_soc2"), default=TriState.UNKNOWN
    )
    iso27001_certified: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_iso27001"), default=TriState.UNKNOWN
    )
    security_questionnaire_status: Mapped[str | None] = mapped_column(String(64))
    dpa_on_file: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_dpa"), default=TriState.UNKNOWN
    )
    incident_notification_required: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_incident_notification"), default=TriState.UNKNOWN
    )
    cyber_insurance: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_cyber_insurance"), default=TriState.UNKNOWN
    )
    mfa_enforced: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_mfa"), default=TriState.UNKNOWN
    )
    encryption_at_rest: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_encryption_at_rest"), default=TriState.UNKNOWN
    )
    encryption_in_transit: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_encryption_in_transit"), default=TriState.UNKNOWN
    )
    bcdr_in_place: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_bcdr"), default=TriState.UNKNOWN
    )
    pentest_performed: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_pentest"), default=TriState.UNKNOWN
    )
    security_awareness_program: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_security_awareness"), default=TriState.UNKNOWN
    )
    vulnerability_mgmt_program: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_vuln_mgmt"), default=TriState.UNKNOWN
    )
    patch_mgmt_program: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_patch_mgmt"), default=TriState.UNKNOWN
    )
    subprocessor_mgmt: Mapped[TriState] = mapped_column(
        pg_enum(TriState, "tri_state_subprocessor_mgmt"), default=TriState.UNKNOWN
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    vendor: Mapped["Vendor"] = relationship(back_populates="governance_profile")
