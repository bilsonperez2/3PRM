import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base
from app.models.enums import AssetType, OwnershipConfidence, pg_enum


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )

    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), index=True)
    asset_type: Mapped[AssetType] = mapped_column(pg_enum(AssetType, "asset_type"), nullable=False)

    # Which provider/adapter discovered this asset (e.g. "crtsh", "dns", "subfinder").
    source: Mapped[str] = mapped_column(String(64), nullable=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Never assume a discovered hostname/IP belongs to the vendor. Only
    # confirmed/high-confidence assets should meaningfully affect risk scoring.
    ownership_confidence: Mapped[OwnershipConfidence] = mapped_column(
        pg_enum(OwnershipConfidence, "ownership_confidence"),
        default=OwnershipConfidence.UNVERIFIED,
    )

    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Free-form provider metadata: hosting provider, ASN, raw discovery evidence, etc.
    # Column is named "metadata" per spec; attribute is asset_metadata since
    # `metadata` is reserved on SQLAlchemy declarative base classes.
    asset_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)

    vendor: Mapped["Vendor"] = relationship(back_populates="assets")
    findings: Mapped[list["Finding"]] = relationship(back_populates="asset")
