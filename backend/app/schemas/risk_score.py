import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class RiskScoreRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vendor_id: uuid.UUID
    score: int
    grade: str
    category_scores: dict
    calculated_at: datetime
    scoring_version: str
