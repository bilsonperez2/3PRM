import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from app.db.base import Base


class UptimeCheck(Base):
    """One reachability probe of a vendor's primary domain.

    Deliberately a narrow, append-only table: this accumulates far faster than
    anything else in the schema (one row per vendor per poll interval), so it
    stays cheap to write and is pruned on a retention window rather than kept
    forever. Uptime percentages and incident lists are derived from these rows
    at query time — no denormalised rollup to drift out of sync.
    """

    __tablename__ = "uptime_checks"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False
    )

    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    reachable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    response_time_ms: Mapped[int | None] = mapped_column(Integer)
    # Populated only when reachable is False — the transport/HTTP reason, so an
    # outage can be explained rather than just counted.
    error: Mapped[str | None] = mapped_column(String(255))

    vendor: Mapped["Vendor"] = relationship(back_populates="uptime_checks")

    __table_args__ = (
        # Every read path is "this vendor, this time window, newest first".
        Index("ix_uptime_checks_vendor_checked_at", "vendor_id", "checked_at"),
    )
