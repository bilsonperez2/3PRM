"""Integration tests for the scan endpoint's authorization gate and rate limit.

The rejection path (test_authorized_active_scan_rejected_via_api) only needs
Postgres — the ScanAuthorizationError is raised before anything is enqueued.
The success path additionally needs the Celery broker (Redis), since
start_scan() always enqueues a task on success; it's marked accordingly and
skips if Redis isn't reachable.

Creating a vendor automatically starts an initial passive scan (see
app/api/v1/vendors.py::start_initial_scan), which counts toward the rate
limit. Tests that need a manual scan to be accepted backdate that initial
scan past the minimum interval first.
"""

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from app.core.config import get_settings
from app.models.scan import Scan
from tests.conftest import requires_celery_broker, requires_postgres

pytestmark = requires_postgres


def _create_vendor(client, **overrides):
    payload = {"name": "Acme Corp", "primary_domain": "acme.com", **overrides}
    return client.post("/api/v1/vendors", json=payload).json()


def _backdate_existing_scans(db_session, vendor_id: str) -> None:
    """Move a vendor's existing scans (i.e. the automatic initial scan) outside
    the rate-limit window, so the next manual scan is treated as the first."""
    interval = timedelta(minutes=get_settings().scan_min_interval_minutes)
    db_session.execute(
        update(Scan)
        .where(Scan.vendor_id == uuid.UUID(vendor_id))
        .values(started_at=datetime.now(timezone.utc) - interval - timedelta(minutes=1))
    )
    db_session.commit()


def test_authorized_active_scan_rejected_via_api(client) -> None:
    vendor = _create_vendor(client, active_scan_authorized=False)

    response = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full", "mode": "authorized_active"},
    )
    assert response.status_code == 403


@requires_celery_broker
def test_vendor_creation_starts_initial_passive_scan(client) -> None:
    vendor = _create_vendor(client, primary_domain="initial-example.com")

    scans = client.get(f"/api/v1/vendors/{vendor['id']}/scans").json()
    assert len(scans) == 1
    assert scans[0]["scan_type"] == "initial_passive"
    assert scans[0]["mode"] == "passive"


@requires_celery_broker
def test_passive_scan_accepted_via_api(client, db_session) -> None:
    vendor = _create_vendor(client, primary_domain="passive-example.com")
    _backdate_existing_scans(db_session, vendor["id"])

    response = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full_passive", "mode": "passive"},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["mode"] == "passive"
    assert body["status"] in {"queued", "running", "completed"}


@requires_celery_broker
def test_manual_scan_right_after_creation_is_rate_limited(client) -> None:
    vendor = _create_vendor(client, primary_domain="initial-ratelimit-example.com")

    response = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full_passive", "mode": "passive"},
    )
    assert response.status_code == 429


@requires_celery_broker
def test_second_immediate_scan_is_rate_limited(client, db_session) -> None:
    vendor = _create_vendor(client, primary_domain="ratelimit-example.com")
    _backdate_existing_scans(db_session, vendor["id"])

    first = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full_passive", "mode": "passive"},
    )
    assert first.status_code == 202

    second = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full_passive", "mode": "passive"},
    )
    assert second.status_code == 429
