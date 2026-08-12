"""Pure-logic tests for HTTP security-header evaluation — no network. The
header logic is split out of WebSecurityProvider specifically so it can be
exercised with fabricated header dicts.
"""

from app.providers.web_provider import evaluate_security_headers

_FULLY_HARDENED = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=()",
}


def _types(findings) -> set[str]:
    return {f.finding_type for f in findings}


def test_fully_hardened_site_produces_no_findings() -> None:
    assert evaluate_security_headers("acme.com", _FULLY_HARDENED, []) == []


def test_bare_response_flags_every_header_check() -> None:
    found = _types(evaluate_security_headers("acme.com", {}, []))
    assert found == {
        "hsts_missing",
        "csp_missing",
        "clickjacking_protection_missing",
        "x_content_type_options_missing",
        "referrer_policy_missing",
        "permissions_policy_missing",
    }


def test_header_matching_is_case_insensitive() -> None:
    # Real servers send mixed-case header names.
    headers = {k.title(): v for k, v in _FULLY_HARDENED.items()}
    assert evaluate_security_headers("acme.com", headers, []) == []


def test_unsafe_csp_is_flagged_separately_from_missing_csp() -> None:
    headers = {**_FULLY_HARDENED, "content-security-policy": "default-src 'self' 'unsafe-inline'"}
    found = _types(evaluate_security_headers("acme.com", headers, []))
    assert "csp_unsafe" in found
    assert "csp_missing" not in found


def test_csp_frame_ancestors_satisfies_clickjacking_check() -> None:
    # A CSP frame-ancestors directive is the modern equivalent of
    # X-Frame-Options, so its presence should suppress that finding.
    headers = {**_FULLY_HARDENED, "content-security-policy": "frame-ancestors 'none'"}
    del headers["x-frame-options"]
    assert "clickjacking_protection_missing" not in _types(
        evaluate_security_headers("acme.com", headers, [])
    )


def test_x_frame_options_allowall_is_still_flagged() -> None:
    headers = {**_FULLY_HARDENED, "x-frame-options": "ALLOWALL", "content-security-policy": "default-src 'self'"}
    assert "clickjacking_protection_missing" in _types(
        evaluate_security_headers("acme.com", headers, [])
    )


def test_cookies_without_secure_flag_are_flagged() -> None:
    cookies = ["session=abc123; Path=/; HttpOnly", "tracking=xyz; Path=/"]
    findings = [f for f in evaluate_security_headers("acme.com", _FULLY_HARDENED, cookies)]
    assert _types(findings) == {"insecure_cookies"}
    assert findings[0].evidence["cookie_names"] == ["session", "tracking"]


def test_secure_cookies_are_not_flagged() -> None:
    cookies = ["session=abc123; Path=/; Secure; HttpOnly"]
    assert evaluate_security_headers("acme.com", _FULLY_HARDENED, cookies) == []


def test_findings_are_instance_keyed_by_hostname() -> None:
    a = evaluate_security_headers("a.acme.com", {}, [])[0]
    b = evaluate_security_headers("b.acme.com", {}, [])[0]
    # Same check on two hosts must be two distinct finding rows.
    assert a.evidence["instance_key"] != b.evidence["instance_key"]
    assert a.asset_hostname == "a.acme.com"
