import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import AssetType, OwnershipConfidence


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vendor_id: uuid.UUID
    hostname: str | None
    ip_address: str | None
    asset_type: AssetType
    source: str
    first_seen: datetime
    last_seen: datetime
    ownership_confidence: OwnershipConfidence
    active: bool
    asset_metadata: dict
