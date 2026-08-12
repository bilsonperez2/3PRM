import re
import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, field_validator

from app.models.enums import AccessLevel, Criticality, RiskTier, VendorCategory

# Conservative hostname validation: labels of letters/digits/hyphens, no leading/
# trailing hyphen per label, 2+ char TLD. Applied to primary_domain so a vendor
# record can never carry a value that would misbehave if later passed to a
# provider/subprocess call.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


def validate_optional_url(value: str | None) -> str | None:
    """Analyst-entered links are rendered as clickable anchors in the UI, so
    only http(s) is accepted — this rejects javascript:/data: URLs rather
    than trusting the frontend to sanitise them."""
    if value is None:
        return None
    value = value.strip()
    if not value:
        return None
    if not value.lower().startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    return value


def validate_domain(value: str) -> str:
    value = value.strip().lower()
    value = value.removeprefix("http://").removeprefix("https://").split("/")[0]
    try:
        candidate = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Not a valid domain name: {value!r}") from exc
    if not _HOSTNAME_RE.match(candidate):
        raise ValueError(f"Not a valid domain name: {value!r}")
    return candidate


class VendorBase(BaseModel):
    name: str
    primary_domain: str
    business_owner: str | None = None
    vendor_category: VendorCategory = VendorCategory.OTHER
    criticality: Criticality = Criticality.MEDIUM
    data_access_level: AccessLevel = AccessLevel.NONE
    system_access_level: AccessLevel = AccessLevel.NONE
    risk_tier: RiskTier = RiskTier.MEDIUM
    active_scan_authorized: bool = False
    is_internal_brand: bool = False
    trust_center_url: str | None = None
    security_page_url: str | None = None
    status_page_url: str | None = None
    compliance_notes: str | None = None
    renewal_date: date | None = None
    notes: str | None = None

    @field_validator("primary_domain")
    @classmethod
    def _validate_primary_domain(cls, value: str) -> str:
        return validate_domain(value)

    @field_validator("trust_center_url", "security_page_url", "status_page_url")
    @classmethod
    def _validate_url(cls, value: str | None) -> str | None:
        return validate_optional_url(value)


class VendorCreate(VendorBase):
    pass


class VendorUpdate(BaseModel):
    name: str | None = None
    primary_domain: str | None = None
    business_owner: str | None = None
    vendor_category: VendorCategory | None = None
    criticality: Criticality | None = None
    data_access_level: AccessLevel | None = None
    system_access_level: AccessLevel | None = None
    risk_tier: RiskTier | None = None
    active_scan_authorized: bool | None = None
    is_internal_brand: bool | None = None
    trust_center_url: str | None = None
    security_page_url: str | None = None
    status_page_url: str | None = None
    compliance_notes: str | None = None
    renewal_date: date | None = None
    notes: str | None = None

    @field_validator("primary_domain")
    @classmethod
    def _validate_primary_domain(cls, value: str | None) -> str | None:
        return validate_domain(value) if value is not None else value

    @field_validator("trust_center_url", "security_page_url", "status_page_url")
    @classmethod
    def _validate_url(cls, value: str | None) -> str | None:
        return validate_optional_url(value)


class VendorRead(VendorBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    created_at: datetime
    updated_at: datetime


class VendorListItem(VendorRead):
    """Vendor plus the timestamp of its most recent completed scan.

    Kept separate from VendorRead because it isn't a column on the vendor —
    it's derived from the scans table, and only the list view needs it. The
    endpoint computes it in one grouped query rather than per row.
    """

    last_scanned_at: datetime | None = None


class OrganizationDomainCreate(BaseModel):
    """Simplified creation payload for /organization — just a name and a
    domain to monitor. Vendor-specific concepts (business_owner, criticality,
    data/system access level, renewal_date) don't apply to your own
    organization, so they're not exposed here; the API fills in sensible
    defaults and forces is_internal_brand=True server-side.
    """

    name: str
    primary_domain: str

    @field_validator("primary_domain")
    @classmethod
    def _validate_primary_domain(cls, value: str) -> str:
        return validate_domain(value)
