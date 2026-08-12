import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import FindingConfidence, FindingSeverity, FindingStatus


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vendor_id: uuid.UUID
    asset_id: uuid.UUID | None
    finding_type: str
    title: str
    description: str | None
    severity: FindingSeverity
    confidence: FindingConfidence
    evidence: dict
    remediation: str | None
    detected_at: datetime
    last_seen: datetime
    status: FindingStatus
    suppressed_until: datetime | None
    analyst_notes: str | None
    risk_points: int


class FindingFalsePositiveRequest(BaseModel):
    analyst_notes: str | None = None


class FindingAcceptRiskRequest(BaseModel):
    analyst_notes: str | None = None


class FindingSuppressRequest(BaseModel):
    suppressed_until: datetime
    analyst_notes: str | None = None


class FindingReopenRequest(BaseModel):
    analyst_notes: str | None = None
