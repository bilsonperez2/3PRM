import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import TriState


class GovernanceProfileBase(BaseModel):
    soc2_reviewed: TriState = TriState.UNKNOWN
    iso27001_certified: TriState = TriState.UNKNOWN
    security_questionnaire_status: str | None = None
    dpa_on_file: TriState = TriState.UNKNOWN
    incident_notification_required: TriState = TriState.UNKNOWN
    cyber_insurance: TriState = TriState.UNKNOWN
    mfa_enforced: TriState = TriState.UNKNOWN
    encryption_at_rest: TriState = TriState.UNKNOWN
    encryption_in_transit: TriState = TriState.UNKNOWN
    bcdr_in_place: TriState = TriState.UNKNOWN
    pentest_performed: TriState = TriState.UNKNOWN
    security_awareness_program: TriState = TriState.UNKNOWN
    vulnerability_mgmt_program: TriState = TriState.UNKNOWN
    patch_mgmt_program: TriState = TriState.UNKNOWN
    subprocessor_mgmt: TriState = TriState.UNKNOWN


class GovernanceProfileUpdate(GovernanceProfileBase):
    pass


class GovernanceProfileRead(GovernanceProfileBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vendor_id: uuid.UUID
    updated_at: datetime
