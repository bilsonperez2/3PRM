import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base
from app.models.enums import AccessLevel, Criticality, RiskTier, VendorCategory, pg_enum


class Vendor(Base):
    __tablename__ = "vendors"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    primary_domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    business_owner: Mapped[str | None] = mapped_column(String(255))
    vendor_category: Mapped[VendorCategory] = mapped_column(
        pg_enum(VendorCategory, "vendor_category"), default=VendorCategory.OTHER
    )
    criticality: Mapped[Criticality] = mapped_column(
        pg_enum(Criticality, "criticality"), default=Criticality.MEDIUM
    )
    data_access_level: Mapped[AccessLevel] = mapped_column(
        pg_enum(AccessLevel, "data_access_level"), default=AccessLevel.NONE
    )
    system_access_level: Mapped[AccessLevel] = mapped_column(
        pg_enum(AccessLevel, "system_access_level"), default=AccessLevel.NONE
    )
    risk_tier: Mapped[RiskTier] = mapped_column(
        pg_enum(RiskTier, "risk_tier"), default=RiskTier.MEDIUM
    )

    # Explicit, vendor-level authorization gate for active scanning. Defaults to
    # False; scan_orchestrator.start_scan() must reject any authorized_active scan
    # request while this is not True, regardless of what the caller/UI sends.
    active_scan_authorized: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # True for rows that represent 4Wall's own brand/domain (added for brand-
    # protection / typosquat monitoring of the organization itself), not a
    # third-party vendor. Reuses the same Scan/Asset/Finding/RiskScore
    # machinery — the DNS/typosquat checks don't care whether the target is
    # "ours" or a vendor's — but is excluded from /vendors and dashboard
    # vendor counts, and managed through /organization instead, so it never
    # gets counted as a third party.
    is_internal_brand: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Manually maintained links to the vendor's published security/compliance
    # material. Deliberately not auto-discovered: there's no standard location
    # for a trust center, and a marketing page claiming "SOC 2 compliant" is
    # not evidence — an analyst records where the real material lives.
    trust_center_url: Mapped[str | None] = mapped_column(String(512))
    security_page_url: Mapped[str | None] = mapped_column(String(512))
    # The vendor's *own* published status page (e.g. status.vendor.com). This
    # is what the vendor reports about themselves — distinct from, and more
    # authoritative than, the uptime_checks this platform records by probing
    # them from one location.
    status_page_url: Mapped[str | None] = mapped_column(String(512))
    compliance_notes: Mapped[str | None] = mapped_column(Text)

    renewal_date: Mapped[date | None] = mapped_column(Date)
    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    assets: Mapped[list["Asset"]] = relationship(back_populates="vendor", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="vendor", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="vendor", cascade="all, delete-orphan")
    risk_scores: Mapped[list["RiskScore"]] = relationship(
        back_populates="vendor", cascade="all, delete-orphan"
    )
    governance_profile: Mapped["GovernanceProfile | None"] = relationship(
        back_populates="vendor", cascade="all, delete-orphan", uselist=False
    )
    uptime_checks: Mapped[list["UptimeCheck"]] = relationship(
        back_populates="vendor", cascade="all, delete-orphan"
    )
