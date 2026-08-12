"""Integration tests against a real Postgres. Require TEST_DATABASE_URL (or the
default localhost:5432/tprm_test) to be reachable; skipped otherwise — see
tests/conftest.py.
"""

from tests.conftest import requires_postgres

pytestmark = requires_postgres


def test_create_and_list_vendor(client) -> None:
    response = client.post(
        "/api/v1/vendors",
        json={"name": "Acme Corp", "primary_domain": "acme.com"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "Acme Corp"
    assert body["primary_domain"] == "acme.com"
    assert body["active_scan_authorized"] is False

    listed = client.get("/api/v1/vendors")
    assert listed.status_code == 200
    assert any(v["id"] == body["id"] for v in listed.json())


def test_get_missing_vendor_returns_404(client) -> None:
    response = client.get("/api/v1/vendors/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


def test_update_vendor(client) -> None:
    created = client.post(
        "/api/v1/vendors",
        json={"name": "Beta LLC", "primary_domain": "beta.com"},
    ).json()

    response = client.put(
        f"/api/v1/vendors/{created['id']}",
        json={"risk_tier": "high", "business_owner": "Jane Doe"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["risk_tier"] == "high"
    assert body["business_owner"] == "Jane Doe"


def test_create_vendor_rejects_invalid_domain(client) -> None:
    response = client.post(
        "/api/v1/vendors",
        json={"name": "Bad Co", "primary_domain": "not a domain"},
    )
    assert response.status_code == 422
