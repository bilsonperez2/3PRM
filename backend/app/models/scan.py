import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.models.enums import ScanMode, ScanStatus, pg_enum


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    vendor_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("vendors.id", ondelete="CASCADE"), nullable=False, index=True
    )

    scan_type: Mapped[str] = mapped_column(String(64), nullable=False)
    mode: Mapped[ScanMode] = mapped_column(pg_enum(ScanMode, "scan_mode"), nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"), default=ScanStatus.QUEUED, nullable=False
    )
    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    scan_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)

    vendor: Mapped["Vendor"] = relationship(back_populates="scans")
