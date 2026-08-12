import enum

from sqlalchemy import Enum as _SAEnum


def pg_enum(enum_cls: type[enum.Enum], name: str) -> _SAEnum:
    """SQLAlchemy's Enum() sends a Python enum member's *name* (e.g. "OTHER") to
    the database by default, not its *value* (e.g. "other") — even for str-mixin
    enums like the ones in this module. Our Postgres enum types (created in the
    Alembic migration) and our API/JSON layer both use the lowercase `.value`,
    so every enum column must be declared through this helper rather than
    `Enum(...)` directly, or inserts fail with
    `invalid input value for enum ...: "OTHER"`.
    """
    return _SAEnum(enum_cls, name=name, values_callable=lambda obj: [e.value for e in obj])


class Criticality(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccessLevel(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class RiskTier(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class VendorCategory(str, enum.Enum):
    SOFTWARE = "software"
    CLOUD_HOSTING = "cloud_hosting"
    PROFESSIONAL_SERVICES = "professional_services"
    PAYMENT_PROCESSING = "payment_processing"
    LOGISTICS = "logistics"
    STAFFING = "staffing"
    MARKETING = "marketing"
    EQUIPMENT_SUPPLIER = "equipment_supplier"
    OTHER = "other"


class OwnershipConfidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNVERIFIED = "unverified"


class AssetType(str, enum.Enum):
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    MAIL_SERVER = "mail_server"
    NAMESERVER = "nameserver"
    CERTIFICATE = "certificate"
    WEB_ASSET = "web_asset"
    OTHER = "other"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ACCEPTED = "accepted"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class ScanMode(str, enum.Enum):
    PASSIVE = "passive"
    AUTHORIZED_ACTIVE = "authorized_active"


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TriState(str, enum.Enum):
    UNKNOWN = "unknown"
    YES = "yes"
    NO = "no"
