import uuid
from datetime import datetime

from pydantic import BaseModel


class ExecutiveSummary(BaseModel):
    vendor_id: uuid.UUID
    vendor_name: str
    overall_risk_label: str
    external_security_score: int | None
    external_security_grade: str | None
    business_criticality: str
    key_concerns: list[str]
    positive_indicators: list[str]
    recommended_action: str
    generated_at: datetime
