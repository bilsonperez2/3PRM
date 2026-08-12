"""Pure-logic tests for vendor status page parsing — no network. Exercises the
Statuspage/Instatus payload shapes and the endpoint-candidate derivation.
"""

from app.providers.vendor_status_provider import (
    INDICATOR_DEGRADED,
    INDICATOR_MAJOR_OUTAGE,
    INDICATOR_OPERATIONAL,
    INDICATOR_PARTIAL_OUTAGE,
    _candidate_endpoints,
    _parse_instatus,
    _parse_statuspage,
)


def test_statuspage_all_operational() -> None:
    payload = {
        "status": {"indicator": "none", "description": "All Systems Operational"},
        "components": [
            {"name": "API", "status": "operational"},
            {"name": "Dashboard", "status": "operational"},
        ],
        "incidents": [],
    }
    result = _parse_statuspage(payload)
    assert result is not None
    assert result.indicator == INDICATOR_OPERATIONAL
    assert result.description == "All Systems Operational"
    assert len(result.components) == 2
    assert result.active_incidents == []


def test_statuspage_maps_severity_levels() -> None:
    for raw, expected in [
        ("minor", INDICATOR_DEGRADED),
        ("major", INDICATOR_PARTIAL_OUTAGE),
        ("critical", INDICATOR_MAJOR_OUTAGE),
    ]:
        result = _parse_statuspage({"status": {"indicator": raw, "description": "x"}})
        assert result is not None and result.indicator == expected


def test_statuspage_skips_group_containers() -> None:
    # Statuspage repeats child names inside group entries; counting groups
    # would double-report components.
    payload = {
        "status": {"indicator": "none", "description": "ok"},
        "components": [
            {"name": "Core", "status": "operational", "group": True},
            {"name": "API", "status": "degraded_performance"},
        ],
    }
    result = _parse_statuspage(payload)
    assert [c.name for c in result.components] == ["API"]
    assert result.components[0].indicator == INDICATOR_DEGRADED


def test_statuspage_extracts_active_incidents() -> None:
    payload = {
        "status": {"indicator": "major", "description": "Partial outage"},
        "incidents": [
            {
                "name": "Elevated API errors",
                "impact": "major",
                "status": "investigating",
                "created_at": "2026-08-11T10:00:00Z",
                "shortlink": "https://stspg.io/abc",
            }
        ],
    }
    result = _parse_statuspage(payload)
    assert len(result.active_incidents) == 1
    assert result.active_incidents[0].name == "Elevated API errors"
    assert result.active_incidents[0].url == "https://stspg.io/abc"


def test_non_statuspage_payload_returns_none() -> None:
    # A random JSON endpoint must not be mistaken for a status page.
    assert _parse_statuspage({"hello": "world"}) is None
    assert _parse_statuspage({"status": "up"}) is None


def test_instatus_payload() -> None:
    payload = {"page": {"name": "Acme", "status": "HASISSUES"}, "activeIncidents": [{"name": "Latency"}]}
    result = _parse_instatus(payload)
    assert result is not None
    assert result.indicator == INDICATOR_DEGRADED
    assert result.platform == "instatus"
    assert result.active_incidents[0].name == "Latency"


def test_instatus_unknown_status_returns_none() -> None:
    assert _parse_instatus({"page": {"status": "SOMETHING_ELSE"}}) is None


def test_candidate_endpoints_tries_path_and_host_root() -> None:
    # A recorded URL with a path (trustpage.vendor.com/status/) may have its
    # API at either that path or the host root, so both are attempted.
    candidates = _candidate_endpoints("https://trustpage.ninjaone.com/status/")
    urls = [url for _, url in candidates]
    assert "https://trustpage.ninjaone.com/status/api/v2/summary.json" in urls
    assert "https://trustpage.ninjaone.com/api/v2/summary.json" in urls


def test_candidate_endpoints_bare_host_not_duplicated() -> None:
    candidates = _candidate_endpoints("https://status.acme.com")
    statuspage_urls = [url for platform, url in candidates if platform == "statuspage"]
    assert statuspage_urls == ["https://status.acme.com/api/v2/summary.json"]
