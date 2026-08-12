"""Integration tests for the scan endpoint's authorization gate and rate limit.

The rejection path (test_authorized_active_scan_rejected_via_api) only needs
Postgres — the ScanAuthorizationError is raised before anything is enqueued.
The success path additionally needs the Celery broker (Redis), since
start_scan() always enqueues a task on success; it's marked accordingly and
skips if Redis isn't reachable.
"""

from tests.conftest import requires_celery_broker, requires_postgres

pytestmark = requires_postgres


def _create_vendor(client, **overrides):
    payload = {"name": "Acme Corp", "primary_domain": "acme.com", **overrides}
    return client.post("/api/v1/vendors", json=payload).json()


def test_authorized_active_scan_rejected_via_api(client) -> None:
    vendor = _create_vendor(client, active_scan_authorized=False)

    response = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full", "mode": "authorized_active"},
    )
    assert response.status_code == 403


@requires_celery_broker
def test_passive_scan_accepted_via_api(client) -> None:
    vendor = _create_vendor(client, primary_domain="passive-example.com")

    response = client.post(
        f"/api/v1/vendors/{vendor['id']}/scan",
        json={"scan_type": "full_passive", "mode": "passive"},
    )
    assert response.status_code == 202
    body = response.json()
    assert body["mode"] == "passive"
    assert body["status"] in {"queued", "running", "completed"}


@requires_celery_broker
def test_second_immediate_scan_is_rate_limited(client) -> None:
    vendor = _create_vendor(client, primary_domain="ratelimit-example.com")

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
