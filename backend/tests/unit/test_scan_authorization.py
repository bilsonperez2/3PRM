"""The most safety-critical test in this codebase: an authorized_active scan
must never be allowed to start for a vendor that hasn't explicitly opted in.
This check happens before any database access, so it's verified here with no
database at all.
"""

import uuid

import pytest

from app.models.enums import ScanMode
from app.models.vendor import Vendor
from app.schemas.scan import ScanCreateRequest
from app.schemas.vendor import VendorCreate
from app.services.scan_orchestrator import ScanAuthorizationError, start_scan


def _unauthorized_vendor() -> Vendor:
    vendor = Vendor(name="Acme Corp", primary_domain="acme.com")
    vendor.id = uuid.uuid4()
    vendor.active_scan_authorized = False
    return vendor


def test_authorized_active_scan_rejected_when_not_authorized() -> None:
    vendor = _unauthorized_vendor()
    request = ScanCreateRequest(mode=ScanMode.AUTHORIZED_ACTIVE)

    with pytest.raises(ScanAuthorizationError):
        # db is never touched on this path — the authorization check runs first.
        start_scan(db=None, vendor=vendor, request=request)  # type: ignore[arg-type]


def test_vendor_create_schema_defaults_active_scan_authorized_to_false() -> None:
    # The API layer's VendorCreate schema is what actually governs the value a
    # new Vendor row is created with (see api/v1/vendors.py create_vendor); a
    # caller who omits the field must get the safe default, not an opt-in.
    payload = VendorCreate(name="Acme Corp", primary_domain="acme.com")
    assert payload.active_scan_authorized is False

    vendor = Vendor(**payload.model_dump())
    vendor.id = uuid.uuid4()

    request = ScanCreateRequest(mode=ScanMode.AUTHORIZED_ACTIVE)
    with pytest.raises(ScanAuthorizationError):
        start_scan(db=None, vendor=vendor, request=request)  # type: ignore[arg-type]
