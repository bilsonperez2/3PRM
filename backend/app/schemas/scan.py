import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import ScanMode, ScanStatus


class ScanCreateRequest(BaseModel):
    scan_type: str = "full_passive"
    mode: ScanMode = ScanMode.PASSIVE


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vendor_id: uuid.UUID
    scan_type: str
    mode: ScanMode
    started_at: datetime | None
    completed_at: datetime | None
    status: ScanStatus
    findings_count: int
    scan_metadata: dict
